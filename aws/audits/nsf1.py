#!/usr/bin/env python3
"""
NSF1 Control Audit: Phishing-resistant MFA for Privileged Accounts

Accounts with system management privileges or the ability to change a system
or an application's configuration are privileged/administrator accounts and
should require phishing-resistant MFA.

REF: IA-2(1), AC-2(7) 800-53r5

Phishing-resistant MFA includes:
- Hardware TOTP tokens (Gemalto, etc.)
- FIDO2/WebAuthn security keys (YubiKey, etc.)

NOT phishing-resistant:
- Virtual MFA (Google Authenticator, Authy) - susceptible to phishing
- SMS-based MFA - susceptible to SIM swapping

Usage:
    python -m audits.nsf1
    python -m audits.nsf1 --accounts 123456789012,234567890123

Prerequisites:
    pip install -r requirements.txt
"""

import argparse
import logging
import sys
from pathlib import Path
from typing import Any

# Add parent directory to path for imports when running directly
sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.aws_common import (
    AuditContext,
    add_common_arguments,
    configure_logging,
    current_date,
    get_logger,
    is_permission_error,
    parse_accounts_arg,
    parse_formats_arg,
    permission_failure_count,
    save_results,
)


logger = get_logger('nsf1')



# Policies that indicate privileged/admin access
ADMIN_POLICY_PATTERNS = [
    'AdministratorAccess',
    'PowerUserAccess',
    'IAMFullAccess',
    'SystemAdministrator',
    'SecurityAudit',
]

# Actions that indicate privileged access
PRIVILEGED_ACTIONS = [
    'iam:*',
    'sts:*',
    'organizations:*',
    'ec2:*',
    's3:*',
    'kms:*',
    '*:*',
]


def is_privileged_policy(policy_name: str, policy_arn: str) -> bool:
    """Check if a policy indicates privileged access."""
    for pattern in ADMIN_POLICY_PATTERNS:
        if pattern.lower() in policy_name.lower():
            return True
    # AWS managed admin policies
    if 'arn:aws:iam::aws:policy/Administrator' in policy_arn:
        return True
    return False


def check_policy_document_for_admin(policy_document: dict) -> bool:
    """Check if a policy document grants admin-level access."""
    if not policy_document:
        return False

    statements = policy_document.get('Statement', [])
    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        if statement.get('Effect') != 'Allow':
            continue

        actions = statement.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]

        resources = statement.get('Resource', [])
        if isinstance(resources, str):
            resources = [resources]

        # Check for broad admin access
        for action in actions:
            if action in PRIVILEGED_ACTIONS:
                if '*' in resources or any('*' in r for r in resources):
                    return True

    return False


def get_mfa_type(mfa_device: dict) -> tuple[str, bool]:
    """
    Determine MFA type and whether it's phishing-resistant.

    Returns:
        Tuple of (mfa_type_string, is_phishing_resistant)
    """
    serial = mfa_device.get('SerialNumber', '')

    # Virtual MFA devices have ARN format: arn:aws:iam::ACCOUNT:mfa/USER
    if ':mfa/' in serial:
        return 'Virtual (TOTP)', False

    # Hardware MFA devices have serial numbers that don't contain 'mfa/'
    # They typically look like: arn:aws:iam::ACCOUNT:u2f/USER or physical serial
    if ':u2f/' in serial or ':fido/' in serial:
        return 'FIDO2/U2F', True

    # Other hardware tokens
    if serial and ':mfa/' not in serial:
        return 'Hardware Token', True

    return 'Unknown', False


def audit_account_users(
    iam_client,
    account_id: str
) -> list[dict[str, Any]]:
    """
    Audit IAM users in an account for MFA compliance.

    Args:
        iam_client: boto3 IAM client
        account_id: AWS account ID

    Returns:
        List of user audit results
    """
    results = []

    # Get all users
    paginator = iam_client.get_paginator('list_users')

    for page in paginator.paginate():
        for user in page.get('Users', []):
            user_name = user.get('UserName', '')
            user_arn = user.get('Arn', '')

            # Check if user has privileged access
            is_privileged = False
            privileged_policies = []
            # audit_errors collects permission-denied / token failures that
            # gate compliance determination. A non-empty list means we could
            # not determine compliance and the user MUST be flagged non-compliant.
            audit_errors: list[str] = []

            # Check attached managed policies
            try:
                policy_paginator = iam_client.get_paginator('list_attached_user_policies')
                for policy_page in policy_paginator.paginate(UserName=user_name):
                    for policy in policy_page.get('AttachedPolicies', []):
                        policy_name = policy.get('PolicyName', '')
                        policy_arn = policy.get('PolicyArn', '')
                        if is_privileged_policy(policy_name, policy_arn):
                            is_privileged = True
                            privileged_policies.append(policy_name)
            except Exception as e:
                if is_permission_error(e):
                    audit_errors.append(f"list_attached_user_policies({user_name}): {e}")

            # Check inline policies
            try:
                inline_paginator = iam_client.get_paginator('list_user_policies')
                for inline_page in inline_paginator.paginate(UserName=user_name):
                    for policy_name in inline_page.get('PolicyNames', []):
                        try:
                            policy_response = iam_client.get_user_policy(
                                UserName=user_name,
                                PolicyName=policy_name
                            )
                            policy_doc = policy_response.get('PolicyDocument', {})
                            if check_policy_document_for_admin(policy_doc):
                                is_privileged = True
                                privileged_policies.append(f"{policy_name} (inline)")
                        except Exception as e:
                            if is_permission_error(e):
                                audit_errors.append(
                                    f"get_user_policy({user_name}/{policy_name}): {e}"
                                )
            except Exception as e:
                if is_permission_error(e):
                    audit_errors.append(f"list_user_policies({user_name}): {e}")

            # Check group memberships for admin policies
            try:
                groups_response = iam_client.list_groups_for_user(UserName=user_name)
                for group in groups_response.get('Groups', []):
                    group_name = group.get('GroupName', '')
                    # Check group policies
                    try:
                        group_policy_paginator = iam_client.get_paginator('list_attached_group_policies')
                        for gp_page in group_policy_paginator.paginate(GroupName=group_name):
                            for policy in gp_page.get('AttachedPolicies', []):
                                policy_name = policy.get('PolicyName', '')
                                policy_arn = policy.get('PolicyArn', '')
                                if is_privileged_policy(policy_name, policy_arn):
                                    is_privileged = True
                                    privileged_policies.append(f"{policy_name} (via {group_name})")
                    except Exception as e:
                        if is_permission_error(e):
                            audit_errors.append(
                                f"list_attached_group_policies({group_name}): {e}"
                            )
            except Exception as e:
                if is_permission_error(e):
                    audit_errors.append(f"list_groups_for_user({user_name}): {e}")

            # Get MFA devices
            mfa_enabled = False
            mfa_type = 'None'
            phishing_resistant = False

            try:
                mfa_response = iam_client.list_mfa_devices(UserName=user_name)
                mfa_devices = mfa_response.get('MFADevices', [])

                if mfa_devices:
                    mfa_enabled = True
                    # Check each MFA device
                    for device in mfa_devices:
                        device_type, device_resistant = get_mfa_type(device)
                        mfa_type = device_type
                        if device_resistant:
                            phishing_resistant = True
                            break  # Found a phishing-resistant device
            except Exception as e:
                if is_permission_error(e):
                    audit_errors.append(f"list_mfa_devices({user_name}): {e}")

            # Determine compliance
            issues = []

            if audit_errors:
                # We couldn't determine privilege or MFA state — refuse to mark
                # the user compliant. This avoids false-clean evidence (H1).
                issues.append("Could not determine compliance — see AuditErrors")

            if is_privileged:
                if not mfa_enabled:
                    issues.append("Privileged user without MFA")
                elif not phishing_resistant:
                    issues.append(f"Privileged user with non-phishing-resistant MFA ({mfa_type})")

            compliant = not audit_errors and (len(issues) == 0 if is_privileged else True)

            results.append({
                'account_id': account_id,
                'user_name': user_name,
                'user_arn': user_arn,
                'is_privileged': is_privileged,
                'privileged_policies': '; '.join(privileged_policies) if privileged_policies else 'None',
                'mfa_enabled': mfa_enabled,
                'mfa_type': mfa_type,
                'phishing_resistant': phishing_resistant,
                'compliant': compliant,
                'issues': issues,
                'audit_errors': audit_errors,
            })

    return results


def audit_root_account(iam_client, account_id: str) -> dict[str, Any]:
    """
    Audit the root account MFA status.

    Args:
        iam_client: boto3 IAM client
        account_id: AWS account ID

    Returns:
        Root account audit result
    """
    issues: list[str] = []
    audit_errors: list[str] = []
    mfa_enabled = False

    try:
        summary = iam_client.get_account_summary()
        summary_map = summary.get('SummaryMap', {})
        mfa_enabled = summary_map.get('AccountMFAEnabled', 0) == 1

        if not mfa_enabled:
            issues.append("Root account MFA not enabled")
    except Exception as e:
        if is_permission_error(e):
            audit_errors.append(f"get_account_summary: {e}")
            issues.append("Could not determine root MFA state — see AuditErrors")
        else:
            issues.append(f"Could not check root account: {e}")

    # Note: We cannot determine root MFA type via API
    # It could be virtual or hardware, but we can't tell
    return {
        'account_id': account_id,
        'user_name': '<root_account>',
        'user_arn': f'arn:aws:iam::{account_id}:root',
        'is_privileged': True,
        'privileged_policies': 'Root Account (full access)',
        'mfa_enabled': mfa_enabled,
        'mfa_type': 'Unknown (root)' if mfa_enabled else 'None',
        'phishing_resistant': False,  # Cannot verify for root
        'compliant': mfa_enabled and not audit_errors,
        'issues': issues,
        'audit_errors': audit_errors,
    }


def run_audit(args) -> tuple[str, dict[str, Any]]:
    """
    Run NSF1 audit across all accounts.

    Args:
        args: Parsed command line arguments

    Returns:
        Tuple of (output_file_path, summary_stats)
    """
    accounts = parse_accounts_arg(args.accounts)
    output_dir = args.output_dir
    role_name = args.role
    date = current_date()

    logger.info("NSF1 audit starting: Phishing-resistant MFA for Privileged Accounts")
    logger.info("Date=%s accounts=%d role=%s",
                date, len(accounts), role_name)

    # Statistics
    total_users = 0
    privileged_users = 0
    compliant_users = 0
    non_compliant_users = 0

    # CSV rows
    csv_rows = []

    for account_id in accounts:
        logger.info("Auditing account: %s", account_id)

        try:
            with AuditContext(account_id, role_name=role_name, profile=args.profile, external_id=args.external_id) as ctx:
                iam = ctx.client('iam')

                # Audit root account
                root_result = audit_root_account(iam, account_id)
                total_users += 1
                privileged_users += 1

                if root_result['compliant']:
                    compliant_users += 1
                else:
                    non_compliant_users += 1

                csv_rows.append([
                    root_result['account_id'],
                    root_result['user_name'],
                    root_result['user_arn'],
                    str(root_result['is_privileged']),
                    root_result['privileged_policies'],
                    str(root_result['mfa_enabled']),
                    root_result['mfa_type'],
                    str(root_result['phishing_resistant']),
                    str(root_result['compliant']),
                    '; '.join(root_result['issues']) if root_result['issues'] else 'None',
                    '; '.join(root_result.get('audit_errors', [])) or 'None',
                ])

                # Audit IAM users
                user_results = audit_account_users(iam, account_id)

                for result in user_results:
                    total_users += 1

                    if result['is_privileged']:
                        privileged_users += 1
                        if result['compliant']:
                            compliant_users += 1
                        else:
                            non_compliant_users += 1
                    elif result.get('audit_errors'):
                        # Privilege state couldn't be determined (AccessDenied
                        # on policy lookups). Count as non-compliant so the
                        # summary doesn't hide the unknown — see H1.
                        non_compliant_users += 1

                    csv_rows.append([
                        result['account_id'],
                        result['user_name'],
                        result['user_arn'],
                        str(result['is_privileged']),
                        result['privileged_policies'],
                        str(result['mfa_enabled']),
                        result['mfa_type'],
                        str(result['phishing_resistant']),
                        str(result['compliant']),
                        '; '.join(result['issues']) if result['issues'] else 'None',
                        '; '.join(result.get('audit_errors', [])) or 'None',
                    ])

                logger.info("Audited %d users in account %s", len(user_results), account_id)

        except Exception as e:
            logger.error("Error auditing account %s: %s", account_id, e)
            continue

    # Save CSV
    headers = [
        'AccountId', 'UserName', 'UserArn', 'IsPrivileged', 'PrivilegedPolicies',
        'MFAEnabled', 'MFAType', 'PhishingResistant', 'Compliant', 'Issues',
        'AuditErrors',
    ]

    # Print summary
    summary = {
        'total_users': total_users,
        'privileged_users': privileged_users,
        'compliant': compliant_users,
        'non_compliant': non_compliant_users,
    }

    formats = parse_formats_arg(args.format)
    records = [dict(zip(headers, row)) for row in csv_rows]
    written_files = save_results(
        output_dir, f"nsf1-{date}", records, summary, formats, headers,
        title="NSF1 Audit",
    )

    print("\n" + "=" * 70)
    print("NSF1 AUDIT SUMMARY")
    print("=" * 70)
    print(f"Total Users Scanned:     {total_users}")
    print(f"Privileged Users:        {privileged_users}")
    print(f"Compliant:               {compliant_users}")
    print(f"Non-Compliant:           {non_compliant_users}")
    print("\nReports saved:")
    for fp in written_files:
        print(f"  {fp}")

    return written_files, summary


def main():
    parser = argparse.ArgumentParser(
        description='NSF1: Phishing-resistant MFA for Privileged Accounts',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Audit all accounts
  %(prog)s

  # Audit specific accounts
  %(prog)s --accounts 123456789012,234567890123

  # Custom output directory
  %(prog)s --output-dir ./reports

Compliance Criteria:
  - All privileged/admin users must have MFA enabled
  - MFA should be phishing-resistant (hardware token or FIDO2)
  - Virtual MFA (TOTP apps) is flagged as non-compliant for privileged users
        """
    )

    add_common_arguments(parser)

    args = parser.parse_args()
    configure_logging(verbose=args.verbose, quiet=args.quiet, log_file=args.log_file)

    try:
        written_files, summary = run_audit(args)


        # Return non-zero if there are non-compliant users
        return 1 if summary['non_compliant'] > 0 or permission_failure_count() > 0 else 0

    except KeyboardInterrupt:
        logger.error("Interrupted by user")
        return 130
    except Exception as e:
        logger.error("Audit error: %s", e)
        return 1


if __name__ == '__main__':
    sys.exit(main())
