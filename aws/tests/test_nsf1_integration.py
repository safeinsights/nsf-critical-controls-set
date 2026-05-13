"""
Integration test for nsf1 (Phishing-resistant MFA for privileged accounts).

nsf1 is the canonical case for the H1 fix: a per-user `audit_errors` field
must be populated when permission errors block compliance determination, so
that a misconfigured audit role can never silently produce a clean report.

We exercise `audit_account_users` and `audit_root_account` directly with a
stub IAM client. No real AWS calls; no mocked boto3 — just a plain Python
object with the methods the audit invokes.
"""

import json
from pathlib import Path
from unittest import mock

import pytest
from botocore.exceptions import ClientError

from audits import nsf1
from lib import aws_common


# ---------------------------------------------------------------------------
# Stub IAM client
# ---------------------------------------------------------------------------

class _LazyPaginator:
    """
    Paginator whose pages are produced by a callable on each `paginate(**kw)`
    call. The callable receives the kwargs (e.g. `UserName='alice'`) and
    returns either an iterable of pages OR raises (to simulate AccessDenied
    surfaced by the SDK at paginate() time rather than at get_paginator()).
    """

    def __init__(self, page_factory):
        self._page_factory = page_factory

    def paginate(self, **kwargs):
        return iter(self._page_factory(**kwargs))


class FakeIam:
    """
    Stub IAM client. Each method either returns a canned response or raises
    a registered exception. Keeps tests readable — no MagicMock noise.
    """

    def __init__(
        self,
        users=None,
        attached_user_policies=None,
        attached_user_policies_error=None,
        inline_user_policies=None,
        user_policy_documents=None,
        groups_for_user=None,
        attached_group_policies=None,
        mfa_devices=None,
        mfa_devices_error=None,
        account_summary_mfa_enabled=True,
        account_summary_error=None,
    ):
        self._users = users or []
        self._attached_user_policies = attached_user_policies or {}
        self._attached_user_policies_error = attached_user_policies_error
        self._inline_user_policies = inline_user_policies or {}
        self._user_policy_documents = user_policy_documents or {}
        self._groups_for_user = groups_for_user or {}
        self._attached_group_policies = attached_group_policies or {}
        self._mfa_devices = mfa_devices or {}
        self._mfa_devices_error = mfa_devices_error or {}
        self._account_summary_mfa_enabled = account_summary_mfa_enabled
        self._account_summary_error = account_summary_error

    def get_paginator(self, op):
        if op == 'list_users':
            return _LazyPaginator(lambda **_: [{'Users': self._users}])

        if op == 'list_attached_user_policies':
            def _pages(**kw):
                if self._attached_user_policies_error:
                    raise self._attached_user_policies_error
                user = kw['UserName']
                return [{'AttachedPolicies': self._attached_user_policies.get(user, [])}]
            return _LazyPaginator(_pages)

        if op == 'list_user_policies':
            return _LazyPaginator(lambda **kw: [
                {'PolicyNames': self._inline_user_policies.get(kw['UserName'], [])}
            ])

        if op == 'list_attached_group_policies':
            return _LazyPaginator(lambda **kw: [
                {'AttachedPolicies': self._attached_group_policies.get(kw['GroupName'], [])}
            ])

        raise NotImplementedError(op)

    def list_users(self):
        return {'Users': self._users}

    def get_user_policy(self, *, UserName, PolicyName):
        return {'PolicyDocument': self._user_policy_documents.get(
            (UserName, PolicyName), {}
        )}

    def list_groups_for_user(self, *, UserName):
        return {'Groups': [
            {'GroupName': g} for g in self._groups_for_user.get(UserName, [])
        ]}

    def list_mfa_devices(self, *, UserName):
        if UserName in self._mfa_devices_error:
            raise self._mfa_devices_error[UserName]
        return {'MFADevices': self._mfa_devices.get(UserName, [])}

    def get_account_summary(self):
        if self._account_summary_error:
            raise self._account_summary_error
        return {'SummaryMap': {
            'AccountMFAEnabled': 1 if self._account_summary_mfa_enabled else 0,
        }}


def _access_denied(op='ListUsers'):
    return ClientError({'Error': {'Code': 'AccessDenied', 'Message': 'no'}}, op)


# ---------------------------------------------------------------------------
# audit_account_users — the H1 canonical case
# ---------------------------------------------------------------------------

class TestAuditAccountUsers:
    def test_compliant_privileged_user_with_fido2(self):
        # Admin user with a FIDO2 hardware key → compliant.
        iam = FakeIam(
            users=[{'UserName': 'alice', 'Arn': 'arn:aws:iam::123:user/alice'}],
            attached_user_policies={'alice': [
                {'PolicyName': 'AdministratorAccess',
                 'PolicyArn': 'arn:aws:iam::aws:policy/AdministratorAccess'}
            ]},
            mfa_devices={'alice': [
                {'SerialNumber': 'arn:aws:iam::123:u2f/alice'}
            ]},
        )
        results = nsf1.audit_account_users(iam, '123456789012')
        assert len(results) == 1
        r = results[0]
        assert r['is_privileged'] is True
        assert r['mfa_enabled'] is True
        assert r['phishing_resistant'] is True
        assert r['compliant'] is True
        assert r['issues'] == []
        assert r['audit_errors'] == []

    def test_privileged_user_with_virtual_mfa_is_non_compliant(self):
        iam = FakeIam(
            users=[{'UserName': 'bob', 'Arn': 'arn:aws:iam::123:user/bob'}],
            attached_user_policies={'bob': [
                {'PolicyName': 'AdministratorAccess',
                 'PolicyArn': 'arn:aws:iam::aws:policy/AdministratorAccess'}
            ]},
            mfa_devices={'bob': [
                {'SerialNumber': 'arn:aws:iam::123:mfa/bob'}  # virtual
            ]},
        )
        r = nsf1.audit_account_users(iam, '123456789012')[0]
        assert r['is_privileged'] is True
        assert r['phishing_resistant'] is False
        assert r['compliant'] is False
        assert any('non-phishing-resistant' in i for i in r['issues'])
        assert r['audit_errors'] == []

    def test_privileged_user_without_mfa_is_non_compliant(self):
        iam = FakeIam(
            users=[{'UserName': 'carol', 'Arn': 'arn:aws:iam::123:user/carol'}],
            attached_user_policies={'carol': [
                {'PolicyName': 'AdministratorAccess',
                 'PolicyArn': 'arn:aws:iam::aws:policy/AdministratorAccess'}
            ]},
            mfa_devices={'carol': []},
        )
        r = nsf1.audit_account_users(iam, '123456789012')[0]
        assert r['compliant'] is False
        assert any('without MFA' in i for i in r['issues'])

    def test_unprivileged_user_without_mfa_is_compliant(self):
        # Non-privileged users don't need MFA to be compliant for this control.
        iam = FakeIam(
            users=[{'UserName': 'dave', 'Arn': 'arn:aws:iam::123:user/dave'}],
            mfa_devices={'dave': []},
        )
        r = nsf1.audit_account_users(iam, '123456789012')[0]
        assert r['is_privileged'] is False
        assert r['compliant'] is True

    # ---------- THE H1 REGRESSION GUARD ----------

    def test_access_denied_on_privilege_check_marks_audit_error(self, caplog):
        """
        H1 regression: if `list_attached_user_policies` returns AccessDenied,
        the audit MUST NOT silently classify the user as unprivileged.
        Instead, audit_errors records the failure and compliant=False.
        """
        from lib.aws_common import permission_failure_count
        iam = FakeIam(
            users=[{'UserName': 'eve', 'Arn': 'arn:aws:iam::123:user/eve'}],
            attached_user_policies_error=_access_denied('ListAttachedUserPolicies'),
            mfa_devices={'eve': [{'SerialNumber': 'arn:aws:iam::123:u2f/eve'}]},
        )
        r = nsf1.audit_account_users(iam, '123456789012')[0]
        assert r['audit_errors'], "audit_errors was empty — silent failure regressed (H1)"
        assert r['compliant'] is False
        assert any('Could not determine compliance' in i for i in r['issues'])

    def test_access_denied_on_mfa_lookup_flags_audit_error(self):
        iam = FakeIam(
            users=[{'UserName': 'frank', 'Arn': 'arn:aws:iam::123:user/frank'}],
            attached_user_policies={'frank': [
                {'PolicyName': 'AdministratorAccess',
                 'PolicyArn': 'arn:aws:iam::aws:policy/AdministratorAccess'}
            ]},
            mfa_devices_error={'frank': _access_denied('ListMFADevices')},
        )
        r = nsf1.audit_account_users(iam, '123456789012')[0]
        assert any('list_mfa_devices' in e for e in r['audit_errors'])
        assert r['compliant'] is False

    def test_non_permission_error_still_swallowed(self):
        # Non-permission errors (NoSuchEntity etc.) preserve the old
        # tolerate-and-continue behavior — they don't bloat audit_errors.
        iam = FakeIam(
            users=[{'UserName': 'gina', 'Arn': 'arn:aws:iam::123:user/gina'}],
            attached_user_policies_error=ClientError(
                {'Error': {'Code': 'NoSuchEntity', 'Message': 'x'}},
                'ListAttachedUserPolicies',
            ),
            mfa_devices={'gina': []},
        )
        r = nsf1.audit_account_users(iam, '123456789012')[0]
        assert r['audit_errors'] == []
        # User not flagged privileged because the call failed, but that's
        # consistent with "user has no managed policy" rather than a permission
        # boundary issue.
        assert r['is_privileged'] is False


# ---------------------------------------------------------------------------
# audit_root_account
# ---------------------------------------------------------------------------

class TestAuditRootAccount:
    def test_root_mfa_enabled_is_compliant(self):
        iam = FakeIam(account_summary_mfa_enabled=True)
        r = nsf1.audit_root_account(iam, '123456789012')
        assert r['mfa_enabled'] is True
        assert r['compliant'] is True
        assert r['audit_errors'] == []

    def test_root_mfa_disabled_is_non_compliant(self):
        iam = FakeIam(account_summary_mfa_enabled=False)
        r = nsf1.audit_root_account(iam, '123456789012')
        assert r['mfa_enabled'] is False
        assert r['compliant'] is False
        assert any('Root account MFA not enabled' in i for i in r['issues'])

    def test_root_access_denied_records_audit_error(self):
        iam = FakeIam(account_summary_error=_access_denied('GetAccountSummary'))
        r = nsf1.audit_root_account(iam, '123456789012')
        assert r['audit_errors'], 'Root permission error must record audit_errors'
        assert r['compliant'] is False
        assert any('AuditErrors' in i for i in r['issues'])


# ---------------------------------------------------------------------------
# run_audit end-to-end (mocked AuditContext)
# ---------------------------------------------------------------------------

class TestRunAuditEndToEnd:
    def test_writes_csv_with_audit_errors_column(self, tmp_path, monkeypatch):
        """
        End-to-end: simulate a run_audit invocation with a fake IAM client
        that surfaces a permission error. The resulting CSV must include
        an AuditErrors column populated for the affected row.
        """
        # Stub AuditContext so it returns our FakeIam without doing any
        # real STS / role assumption.
        iam = FakeIam(
            users=[{'UserName': 'eve', 'Arn': 'arn:aws:iam::123:user/eve'}],
            attached_user_policies_error=_access_denied(),
            mfa_devices={'eve': []},
            account_summary_mfa_enabled=True,
        )

        class FakeCtx:
            def __init__(self, *a, **kw): pass
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def client(self, service, region_name=None):
                assert service == 'iam'
                return iam

        monkeypatch.setattr(nsf1, 'AuditContext', FakeCtx)

        args = mock.Mock()
        args.accounts = '123456789012'
        args.regions = None
        args.role = None
        args.profile = None
        args.external_id = None
        args.output_dir = str(tmp_path)
        args.format = 'csv,json'

        written, summary = nsf1.run_audit(args)
        assert summary['non_compliant'] >= 1, \
            "permission-denied user must count toward non_compliant"

        # CSV must have an AuditErrors column with the permission error
        # captured for at least one row.
        csv_file = [f for f in written if f.endswith('.csv')][0]
        import csv as csvmod
        with open(csv_file) as f:
            reader = csvmod.DictReader(f)
            rows = list(reader)
        assert 'AuditErrors' in reader.fieldnames, 'AuditErrors column missing'
        # Find eve's row.
        eve_rows = [r for r in rows if r['UserName'] == 'eve']
        assert eve_rows, "eve user row missing from CSV"
        assert eve_rows[0]['AuditErrors'] not in ('', 'None'), (
            "AuditErrors must be populated for the permission-denied user; "
            f"got {eve_rows[0]['AuditErrors']!r}"
        )
        # And eve's compliant flag must be False.
        assert eve_rows[0]['Compliant'] == 'False'

        # JSON sanity-check.
        json_file = [f for f in written if f.endswith('.json')][0]
        payload = json.loads(Path(json_file).read_text())
        eve = next(r for r in payload['records'] if r['UserName'] == 'eve')
        assert eve['AuditErrors']  # truthy list (joined or list-typed)
