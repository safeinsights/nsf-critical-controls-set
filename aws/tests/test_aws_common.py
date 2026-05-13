"""
Tests for aws/lib/aws_common.py.

Covers:
- validate_account_id
- is_permission_error / warn_permission_error / permission_failure_count
- _neutralize_csv_value / _records_to_rows (CSV formula-injection defense)
- save_csv / save_json / save_yaml / save_text / save_results
- resolve_output_dir (symlink rejection, $WORKSPACE handling)
- parse_accounts_arg / parse_regions_arg / parse_formats_arg
- resolve_role
- build_session credential strategy dispatch
- configure_logging / get_logger
"""

import json
import logging
import os
import re
from pathlib import Path
from unittest import mock

import pytest
import yaml

from lib import aws_common
from lib.aws_common import (
    ACCOUNT_ID_RE,
    AuditPermissionError,
    DEFAULT_FORMAT,
    PERMISSION_ERROR_CODES,
    SUPPORTED_FORMATS,
    _CSV_DANGEROUS_PREFIXES,
    _neutralize_csv_value,
    _records_to_rows,
    configure_logging,
    get_logger,
    is_permission_error,
    parse_accounts_arg,
    parse_formats_arg,
    parse_regions_arg,
    permission_failure_count,
    permission_failures,
    reset_permission_failures,
    resolve_output_dir,
    resolve_role,
    save_csv,
    save_json,
    save_results,
    save_text,
    save_yaml,
    validate_account_id,
    warn_permission_error,
)


# ---------------------------------------------------------------------------
# validate_account_id
# ---------------------------------------------------------------------------

class TestValidateAccountId:
    def test_accepts_12_digit_string(self):
        assert validate_account_id('123456789012') == '123456789012'

    def test_returns_input_on_success(self):
        # round-trip
        assert validate_account_id('000000000000') == '000000000000'

    @pytest.mark.parametrize('bad', [
        '12345', '1234567890123', '12345678901a', 'abcdefghijkl',
        '', '   ', '123 456 789 012', '-12345678901',
    ])
    def test_rejects_invalid_strings(self, bad):
        with pytest.raises(ValueError, match='Invalid AWS account ID'):
            validate_account_id(bad)

    def test_rejects_non_strings(self):
        with pytest.raises(ValueError):
            validate_account_id(123456789012)  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            validate_account_id(None)  # type: ignore[arg-type]

    def test_regex_constant_matches_function(self):
        # The exported regex must match exactly what validate_account_id accepts.
        assert ACCOUNT_ID_RE.match('123456789012')
        assert not ACCOUNT_ID_RE.match('1234')


# ---------------------------------------------------------------------------
# Permission-error classifier & counter
# ---------------------------------------------------------------------------

def _client_error(code: str) -> 'object':
    """Build a botocore ClientError with the given Error.Code."""
    from botocore.exceptions import ClientError
    return ClientError({'Error': {'Code': code, 'Message': 'test'}}, 'TestOp')


class TestIsPermissionError:
    @pytest.mark.parametrize('code', sorted(PERMISSION_ERROR_CODES))
    def test_known_permission_codes_are_classified(self, code):
        assert is_permission_error(_client_error(code))

    def test_audit_permission_error_self_class(self):
        assert is_permission_error(AuditPermissionError('denied'))

    @pytest.mark.parametrize('code', ['NoSuchEntity', 'ThrottlingException', 'ValidationError'])
    def test_non_permission_codes_not_classified(self, code):
        assert not is_permission_error(_client_error(code))

    def test_plain_exception_not_classified(self):
        assert not is_permission_error(Exception('bad'))
        assert not is_permission_error(ValueError('bad'))


class TestWarnPermissionError:
    def test_emits_and_counts_on_permission_error(self, caplog):
        reset_permission_failures()
        with caplog.at_level(logging.ERROR, logger=aws_common.LOGGER_NAME):
            emitted = warn_permission_error('ListUsers', _client_error('AccessDenied'))
        assert emitted is True
        assert permission_failure_count() == 1
        assert 'NSF-AUDIT-PERMISSION-ERROR' in caplog.text
        assert 'ListUsers' in caplog.text
        assert 'AccessDenied' in caplog.text

    def test_silent_on_non_permission_error(self, caplog):
        reset_permission_failures()
        emitted = warn_permission_error('GetItem', _client_error('NoSuchEntity'))
        assert emitted is False
        assert permission_failure_count() == 0

    def test_counter_accumulates(self):
        reset_permission_failures()
        for _ in range(3):
            warn_permission_error('ListX', _client_error('AccessDenied'))
        assert permission_failure_count() == 3
        msgs = permission_failures()
        assert len(msgs) == 3
        assert all('ListX' in m for m in msgs)

    def test_reset_clears_counter(self):
        warn_permission_error('Op', _client_error('AccessDenied'))
        assert permission_failure_count() >= 1
        reset_permission_failures()
        assert permission_failure_count() == 0


# ---------------------------------------------------------------------------
# CSV formula-injection defense
# ---------------------------------------------------------------------------

class TestNeutralizeCsvValue:
    @pytest.mark.parametrize('value, expected', [
        ('=cmd|calc', "'=cmd|calc"),
        ('+1+1', "'+1+1"),
        ('-MIN(A1)', "'-MIN(A1)"),
        ('@SUM', "'@SUM"),
        ('\tTAB-LEAD', "'\tTAB-LEAD"),
        ('\rCR-LEAD', "'\rCR-LEAD"),
    ])
    def test_dangerous_prefixes_neutralized(self, value, expected):
        assert _neutralize_csv_value(value) == expected

    @pytest.mark.parametrize('value', [
        'normal', 'has=equals', '0', '', 'arn:aws:iam::123:user/x',
    ])
    def test_safe_strings_unchanged(self, value):
        assert _neutralize_csv_value(value) == value

    @pytest.mark.parametrize('value', [None, 0, 1, True, False, 3.14])
    def test_non_strings_unchanged(self, value):
        assert _neutralize_csv_value(value) == value

    def test_all_dangerous_prefixes_covered(self):
        # Defense in depth: assert the constant matches what we test.
        assert set('=+-@\t\r') == set(_CSV_DANGEROUS_PREFIXES)


# ---------------------------------------------------------------------------
# _records_to_rows (the path that flows into save_csv)
# ---------------------------------------------------------------------------

class TestRecordsToRows:
    def test_orders_by_headers(self):
        records = [{'b': 2, 'a': 1, 'c': 3}]
        assert _records_to_rows(records, ['a', 'b', 'c']) == [[1, 2, 3]]

    def test_missing_field_becomes_empty(self):
        assert _records_to_rows([{'a': 1}], ['a', 'b']) == [[1, '']]

    def test_list_joined_with_semicolons(self):
        assert _records_to_rows([{'a': ['x', 'y']}], ['a']) == [['x; y']]

    def test_empty_list_becomes_none_string(self):
        assert _records_to_rows([{'a': []}], ['a']) == [['None']]

    def test_bool_stringified(self):
        assert _records_to_rows([{'a': True}, {'a': False}], ['a']) == [['True'], ['False']]

    def test_csv_neutralization_applied(self):
        # The whole reason this exists — strings starting with dangerous
        # chars are neutralized even when projected from records.
        rows = _records_to_rows([{'a': '=BAD'}], ['a'])
        assert rows == [["'=BAD"]]


# ---------------------------------------------------------------------------
# Writers
# ---------------------------------------------------------------------------

class TestSaveCsv:
    def test_writes_headers_and_rows(self, tmp_path):
        out = tmp_path / 'a.csv'
        save_csv(str(out), [['v1', 'v2']], headers=['h1', 'h2'])
        assert out.read_text().splitlines() == ['h1,h2', 'v1,v2']

    def test_handles_special_chars_in_value(self, tmp_path):
        out = tmp_path / 'a.csv'
        save_csv(str(out), [['a,b', 'c"d', 'e\nf']], headers=['x', 'y', 'z'])
        # csv.writer handles all quoting; we just need it to round-trip via csv.
        import csv
        with open(out) as f:
            rows = list(csv.reader(f))
        assert rows[1] == ['a,b', 'c"d', 'e\nf']


class TestSaveJson:
    def test_writes_valid_json(self, tmp_path):
        out = tmp_path / 'a.json'
        save_json(str(out), {'k': 'v', 'n': 1})
        assert json.loads(out.read_text()) == {'k': 'v', 'n': 1}

    def test_handles_datetime_via_default_str(self, tmp_path):
        from datetime import datetime
        out = tmp_path / 'a.json'
        save_json(str(out), {'when': datetime(2026, 5, 13, 10, 0, 0)})
        loaded = json.loads(out.read_text())
        assert '2026-05-13' in loaded['when']


class TestSaveYaml:
    def test_writes_safe_yaml_no_python_tags(self, tmp_path):
        out = tmp_path / 'a.yaml'
        # Include a value that PyYAML's unsafe dump would serialize as
        # !!python/tuple — safe_dump rejects unknown types entirely.
        save_yaml(str(out), {'k': 'v', 'list': ['a', 'b']})
        content = out.read_text()
        assert '!!python' not in content
        assert yaml.safe_load(content) == {'k': 'v', 'list': ['a', 'b']}

    def test_rejects_unsafe_objects(self, tmp_path):
        # safe_dump must refuse types it can't serialize — verifies M4 fix.
        out = tmp_path / 'a.yaml'
        with pytest.raises(yaml.representer.RepresenterError):
            save_yaml(str(out), {'k': object()})


class TestSaveText:
    def test_writes_title_records_and_summary(self, tmp_path):
        out = tmp_path / 'a.txt'
        save_text(str(out), [{'a': 1, 'b': 2}], {'total': 1}, title='Demo')
        content = out.read_text()
        assert 'Demo' in content
        assert '====' in content  # underline
        assert 'a: 1' in content and 'b: 2' in content
        assert 'Summary' in content
        assert 'total: 1' in content


# ---------------------------------------------------------------------------
# save_results dispatcher
# ---------------------------------------------------------------------------

class TestSaveResults:
    def test_single_csv_default(self, tmp_path):
        files = save_results(str(tmp_path), 'demo', [{'a': 1}], {'t': 1},
                             ['csv'], headers=['a'])
        assert len(files) == 1
        assert files[0].endswith('demo.csv')
        assert Path(files[0]).exists()

    def test_multi_format_produces_multiple_files(self, tmp_path):
        files = save_results(str(tmp_path), 'demo', [{'a': 1}], {'t': 1},
                             ['csv', 'json', 'yaml', 'text'], headers=['a'])
        assert sorted(Path(f).suffix for f in files) == ['.csv', '.json', '.txt', '.yaml']

    def test_unknown_format_warns_and_skips(self, tmp_path, caplog):
        with caplog.at_level(logging.WARNING, logger=aws_common.LOGGER_NAME):
            files = save_results(str(tmp_path), 'demo', [], {}, ['csv', 'bogus'],
                                 headers=['a'])
        assert len(files) == 1
        assert 'Unknown output format' in caplog.text

    def test_neutralizes_csv_injection(self, tmp_path):
        files = save_results(str(tmp_path), 'demo',
                             [{'name': '=evil', 'other': 'ok'}], {},
                             ['csv'], headers=['name', 'other'])
        # Parse the CSV back; the first data field must NOT start with `=`
        # (Excel/Sheets would treat it as a formula). The original value is
        # preserved via the leading single-quote prefix.
        import csv
        with open(files[0]) as f:
            rows = list(csv.reader(f))
        first_data_field = rows[1][0]
        assert not first_data_field.startswith('='), (
            f"CSV field starts with '=' — formula injection not neutralized: {first_data_field!r}"
        )
        assert first_data_field == "'=evil"

    def test_json_includes_summary_and_records(self, tmp_path):
        files = save_results(str(tmp_path), 'demo', [{'a': 1}], {'count': 1},
                             ['json'], headers=['a'])
        payload = json.loads(Path(files[0]).read_text())
        assert payload == {'summary': {'count': 1}, 'records': [{'a': 1}]}


# ---------------------------------------------------------------------------
# resolve_output_dir
# ---------------------------------------------------------------------------

class TestResolveOutputDir:
    def test_creates_missing_dir(self, tmp_path):
        target = tmp_path / 'a' / 'b'
        result = resolve_output_dir(str(target))
        assert result.exists()
        assert result == target.absolute()

    def test_existing_dir_returned_as_is(self, tmp_path):
        target = tmp_path / 'a'
        target.mkdir()
        assert resolve_output_dir(str(target)) == target.absolute()

    def test_direct_symlink_rejected(self, tmp_path):
        real = tmp_path / 'real'
        real.mkdir()
        link = tmp_path / 'link'
        link.symlink_to(real)
        with pytest.raises(ValueError, match='symlinked'):
            resolve_output_dir(str(link))

    def test_workspace_parent_symlink_rejected(self, tmp_path, monkeypatch):
        workspace = tmp_path / 'ws'
        workspace.mkdir()
        real = tmp_path / 'real'
        real.mkdir()
        bad = workspace / 'redirect'
        bad.symlink_to(real)
        monkeypatch.setenv('WORKSPACE', str(workspace))
        target = bad / 'output'
        with pytest.raises(ValueError, match='symlinked workspace'):
            resolve_output_dir(str(target))

    def test_non_workspace_parent_symlink_tolerated(self, tmp_path):
        # OS-level symlinks above WORKSPACE (e.g. macOS /var → /private/var)
        # must not block normal output.
        real = tmp_path / 'real'
        real.mkdir()
        link = tmp_path / 'link'
        link.symlink_to(real)
        target = link / 'subdir'
        # No WORKSPACE env set ⇒ tolerated.
        result = resolve_output_dir(str(target))
        assert result.exists()


# ---------------------------------------------------------------------------
# CLI parsing helpers
# ---------------------------------------------------------------------------

class TestParseAccountsArg:
    def test_explicit_arg_takes_priority(self):
        assert parse_accounts_arg('123456789012,987654321098') == [
            '123456789012', '987654321098'
        ]

    def test_strips_whitespace(self):
        assert parse_accounts_arg(' 123456789012 , 987654321098 ') == [
            '123456789012', '987654321098'
        ]

    def test_rejects_invalid_id(self):
        with pytest.raises(ValueError, match='Invalid AWS account ID'):
            parse_accounts_arg('1234')

    def test_falls_back_to_config(self, monkeypatch):
        monkeypatch.setattr(aws_common, 'get_all_accounts',
                            lambda: ['123456789012'])
        assert parse_accounts_arg(None) == ['123456789012']

    def test_raises_when_no_source(self, monkeypatch):
        monkeypatch.setattr(aws_common, 'get_all_accounts', lambda: None)
        with pytest.raises(ValueError, match='No accounts specified'):
            parse_accounts_arg(None)

    def test_validates_config_account_ids(self, monkeypatch):
        # A tampered config file with a non-12-digit ID must be refused.
        monkeypatch.setattr(aws_common, 'get_all_accounts',
                            lambda: ['notanid'])
        with pytest.raises(ValueError, match='Invalid AWS account ID'):
            parse_accounts_arg(None)


class TestParseRegionsArg:
    def test_explicit(self):
        assert parse_regions_arg('us-east-1,us-west-2') == ['us-east-1', 'us-west-2']

    def test_falls_back_to_config(self, monkeypatch):
        monkeypatch.setattr(aws_common, 'get_all_regions',
                            lambda: ['us-east-1'])
        assert parse_regions_arg(None) == ['us-east-1']

    def test_raises_when_no_source(self, monkeypatch):
        monkeypatch.setattr(aws_common, 'get_all_regions', lambda: None)
        with pytest.raises(ValueError, match='No regions specified'):
            parse_regions_arg(None)


class TestParseFormatsArg:
    def test_default_is_csv(self):
        assert parse_formats_arg(None) == [DEFAULT_FORMAT]
        assert parse_formats_arg('') == [DEFAULT_FORMAT]

    def test_single_format(self):
        assert parse_formats_arg('json') == ['json']

    def test_multiple_formats(self):
        assert parse_formats_arg('csv,json,yaml') == ['csv', 'json', 'yaml']

    def test_case_insensitive(self):
        assert parse_formats_arg('CSV,Json') == ['csv', 'json']

    def test_dedupes_preserving_order(self):
        assert parse_formats_arg('json,csv,json,csv') == ['json', 'csv']

    def test_rejects_invalid(self):
        with pytest.raises(ValueError, match='Unsupported --format'):
            parse_formats_arg('xml')

    def test_all_supported_round_trip(self):
        assert set(parse_formats_arg(','.join(SUPPORTED_FORMATS))) == set(SUPPORTED_FORMATS)


# ---------------------------------------------------------------------------
# resolve_role
# ---------------------------------------------------------------------------

class TestResolveRole:
    def test_cli_arg_wins(self, monkeypatch):
        monkeypatch.setenv('NSF_AUDIT_ROLE', 'env-role')
        assert resolve_role('cli-role') == 'cli-role'

    def test_env_fallback(self, monkeypatch):
        monkeypatch.setenv('NSF_AUDIT_ROLE', 'env-role')
        assert resolve_role(None) == 'env-role'

    def test_none_if_neither(self):
        # _isolate_env fixture has already removed NSF_AUDIT_ROLE.
        assert resolve_role(None) is None


# ---------------------------------------------------------------------------
# build_session credential dispatch (mocked — no real AWS)
# ---------------------------------------------------------------------------

class TestBuildSession:
    def test_no_role_no_profile_returns_default(self, monkeypatch):
        # Should not touch sts.
        fake_session = mock.MagicMock(name='default-session')
        with mock.patch.object(aws_common.boto3, 'Session', return_value=fake_session) as ctor:
            result = aws_common.build_session()
        assert result is fake_session
        ctor.assert_called_once_with()

    def test_role_assumption_calls_sts(self):
        # Mock chain: boto3.Session() → base_session; base_session.client('sts')
        # → sts client whose assume_role returns synthetic creds; boto3.Session(...)
        # → role session whose client('sts').get_caller_identity() returns a
        # realistic Arn.
        fake_creds = {
            'AccessKeyId': 'AKIA', 'SecretAccessKey': 'SECRET',
            'SessionToken': 'TOK', 'Expiration': None,
        }
        sts_base = mock.MagicMock()
        sts_base.assume_role.return_value = {'Credentials': fake_creds}
        base_session = mock.MagicMock()
        base_session.client.return_value = sts_base

        role_session = mock.MagicMock()
        role_session.client.return_value.get_caller_identity.return_value = {
            'Arn': 'arn:aws:sts::123456789012:assumed-role/x/y'
        }

        with mock.patch.object(aws_common.boto3, 'Session',
                               side_effect=[base_session, role_session]):
            result = aws_common.build_session(
                account_id='123456789012',
                role_name='Role',
                external_id='ext-id-1',
            )
        assert result is role_session
        # ExternalId must have been forwarded to AssumeRole.
        call = sts_base.assume_role.call_args
        assert call.kwargs['RoleArn'] == 'arn:aws:iam::123456789012:role/Role'
        assert call.kwargs['ExternalId'] == 'ext-id-1'
        assert call.kwargs['RoleSessionName'].startswith('nsf-audit-')

    def test_role_without_external_id_omits_kwarg(self):
        fake_creds = {
            'AccessKeyId': 'k', 'SecretAccessKey': 's',
            'SessionToken': 't', 'Expiration': None,
        }
        sts_base = mock.MagicMock()
        sts_base.assume_role.return_value = {'Credentials': fake_creds}
        base_session = mock.MagicMock()
        base_session.client.return_value = sts_base
        role_session = mock.MagicMock()
        role_session.client.return_value.get_caller_identity.return_value = {
            'Arn': 'arn:aws:sts::123456789012:assumed-role/x/y'
        }
        with mock.patch.object(aws_common.boto3, 'Session',
                               side_effect=[base_session, role_session]):
            aws_common.build_session(account_id='123456789012', role_name='R')
        call = sts_base.assume_role.call_args
        assert 'ExternalId' not in call.kwargs

    def test_role_without_account_id_raises(self):
        with pytest.raises(ValueError, match='account_id is required'):
            aws_common.build_session(role_name='R')

    def test_role_with_bad_account_id_raises(self):
        with pytest.raises(ValueError, match='Invalid AWS account ID'):
            aws_common.build_session(account_id='bad', role_name='R')


# ---------------------------------------------------------------------------
# configure_logging / get_logger
# ---------------------------------------------------------------------------

class TestLogging:
    def test_configure_default_level(self):
        log = configure_logging()
        assert log.level == logging.INFO
        assert log.handlers, 'expected at least one handler'

    def test_configure_verbose(self):
        log = configure_logging(verbose=True)
        assert log.level == logging.DEBUG

    def test_configure_quiet(self):
        log = configure_logging(quiet=True)
        assert log.level == logging.WARNING

    def test_configure_rejects_both_verbose_and_quiet(self):
        with pytest.raises(ValueError):
            configure_logging(verbose=True, quiet=True)

    def test_configure_is_idempotent(self):
        configure_logging()
        configure_logging()
        configure_logging()
        log = logging.getLogger(aws_common.LOGGER_NAME)
        # Each call replaces prior handlers, so we end with exactly one.
        assert len(log.handlers) == 1

    def test_log_file_writes_to_file(self, tmp_path):
        log_file = tmp_path / 'audit.log'
        log = configure_logging(log_file=str(log_file))
        log.info('hello-from-test')
        # Flush handler.
        for h in log.handlers:
            h.flush()
        assert 'hello-from-test' in log_file.read_text()
        # Cleanup: re-route to stderr so other tests aren't affected.
        configure_logging()

    def test_get_logger_returns_child_under_namespace(self):
        child = get_logger('nsfN')
        assert child.name == 'nsf_audit.nsfN'
        # And inherits from the root nsf_audit logger.
        assert child.parent is logging.getLogger(aws_common.LOGGER_NAME)
