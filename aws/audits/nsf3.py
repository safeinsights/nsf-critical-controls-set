#!/usr/bin/env python3
"""
NSF3 Control Audit: Limited Scope Administrative Accounts

Privileged/administrative accounts should be restricted in scope
(e.g., separate accounts for web servers, database servers,
system management, network management).

REF: AC-6(4, 5), SC-3, CM-7 800-53r5; 3.1.5 800-171

This audit checks:
- IAM users/roles with overly broad permissions (*:*)
- Accounts with AdministratorAccess policy
- Lack of separation of duties
- Cross-account admin access

Usage:
    python nsf3.py
    python nsf3.py --accounts 123456789012,234567890123

Prerequisites:
    pip install -r requirements.txt
"""

import sys
from pathlib import Path

# Add parent directory to path for imports when running directly
sys.path.insert(0, str(Path(__file__).parent.parent))

import argparse
import logging
import json
import sys
from typing import Any, Optional

from lib.aws_common import (
    AuditContext,
    add_common_arguments,
    configure_logging,
    current_date,
    get_logger,
    parse_accounts_arg,
    parse_formats_arg,
    permission_failure_count,
    save_results,
    warn_permission_error,
)


logger = get_logger('nsf3')



# Policies that grant full admin access
FULL_ADMIN_POLICIES = [
    'arn:aws:iam::aws:policy/AdministratorAccess',
]

# Patterns indicating overly broad access
OVERLY_BROAD_PATTERNS = [
    {'Action': '*', 'Resource': '*'},
    {'Action': ['*'], 'Resource': '*'},
    {'Action': '*', 'Resource': ['*']},
    {'Action': ['*'], 'Resource': ['*']},
]


def analyze_policy_document(policy_document: dict) -> dict[str, Any]:
    """
    Analyze a policy document for scope issues.

    Args:
        policy_document: IAM policy document

    Returns:
        Analysis result with scope description and issues
    """
    if not policy_document:
        return {
            'has_admin_access': False,
            'scope_description': 'Empty policy',
            'issues': []
        }

    issues = []
    has_admin_access = False
    allowed_services = set()
    allowed_actions = []

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

        # Check for full admin access
        for action in actions:
            if action == '*':
                if '*' in resources:
                    has_admin_access = True
                    issues.append("Full admin access (*:* on all resources)")
                allowed_services.add('ALL')
            else:
                # Extract service from action
                if ':' in action:
                    service = action.split(':')[0]
                    allowed_services.add(service)
                    if action.endswith(':*') and '*' in resources:
                        issues.append(f"Full access to {service} service")
                allowed_actions.append(action)

    # Determine scope description
    if has_admin_access:
        scope_description = "UNRESTRICTED - Full admin access"
    elif 'ALL' in allowed_services:
        scope_description = "BROAD - Access to all services"
    elif len(allowed_services) > 10:
        scope_description = f"BROAD - Access to {len(allowed_services)} services"
    elif len(allowed_services) > 5:
        scope_description = f"MODERATE - Access to {len(allowed_services)} services"
    else:
        scope_description = f"LIMITED - Access to: {', '.join(sorted(allowed_services))}"

    return {
        'has_admin_access': has_admin_access,
        'scope_description': scope_description,
        'issues': issues,
        'services': list(allowed_services)
    }


def audit_iam_users(
    iam_client,
    account_id: str
) -> list[dict[str, Any]]:
    """
    Audit IAM users for scope compliance.

    Args:
        iam_client: boto3 IAM client
        account_id: AWS account ID

    Returns:
        List of user audit results
    """
    results = []

    paginator = iam_client.get_paginator('list_users')

    for page in paginator.paginate():
        for user in page.get('Users', []):
            user_name = user.get('UserName', '')
            user_arn = user.get('Arn', '')

            all_issues = []
            has_admin = False
            scope_parts = []

            # Check attached managed policies
            try:
                policy_paginator = iam_client.get_paginator('list_attached_user_policies')
                for policy_page in policy_paginator.paginate(UserName=user_name):
                    for policy in policy_page.get('AttachedPolicies', []):
                        policy_arn = policy.get('PolicyArn', '')
                        policy_name = policy.get('PolicyName', '')

                        if policy_arn in FULL_ADMIN_POLICIES:
                            has_admin = True
                            all_issues.append(f"Has {policy_name} (full admin)")

                        # Get policy document for custom policies
                        if not policy_arn.startswith('arn:aws:iam::aws:policy/'):
                            try:
                                policy_resp = iam_client.get_policy(PolicyArn=policy_arn)
                                default_version = policy_resp['Policy'].get('DefaultVersionId')
                                version_resp = iam_client.get_policy_version(
                                    PolicyArn=policy_arn,
                                    VersionId=default_version
                                )
                                doc = version_resp['PolicyVersion'].get('Document', {})
                                analysis = analyze_policy_document(doc)
                                if analysis['has_admin_access']:
                                    has_admin = True
                                all_issues.extend(analysis['issues'])
                                scope_parts.append(analysis['scope_description'])
                            except Exception as _e:
                                warn_permission_error('aws-read', _e)
            except Exception as e:
                all_issues.append(f"Could not check policies: {e}")

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
                            doc = policy_response.get('PolicyDocument', {})
                            analysis = analyze_policy_document(doc)
                            if analysis['has_admin_access']:
                                has_admin = True
                            all_issues.extend([f"Inline policy '{policy_name}': {i}" for i in analysis['issues']])
                            scope_parts.append(f"Inline({policy_name}): {analysis['scope_description']}")
                        except Exception as _e:
                            warn_permission_error('aws-read', _e)
            except Exception as _e:
                warn_permission_error('aws-read', _e)

            # Determine overall scope
            if has_admin:
                scope_description = "UNRESTRICTED - Has admin access"
            elif scope_parts:
                scope_description = '; '.join(scope_parts[:3])  # Limit to first 3
            else:
                scope_description = "MINIMAL - No significant permissions"

            # Compliance: Admin access without justification is non-compliant
            compliant = not has_admin

            results.append({
                'account_id': account_id,
                'principal_type': 'User',
                'principal_name': user_name,
                'principal_arn': user_arn,
                'has_admin_access': has_admin,
                'scope_description': scope_description,
                'compliant': compliant,
                'issues': all_issues
            })

    return results


def audit_iam_roles(
    iam_client,
    account_id: str
) -> list[dict[str, Any]]:
    """
    Audit IAM roles for scope compliance.

    Args:
        iam_client: boto3 IAM client
        account_id: AWS account ID

    Returns:
        List of role audit results
    """
    results = []

    paginator = iam_client.get_paginator('list_roles')

    for page in paginator.paginate():
        for role in page.get('Roles', []):
            role_name = role.get('RoleName', '')
            role_arn = role.get('Arn', '')

            # Skip AWS service-linked roles
            if '/aws-service-role/' in role_arn:
                continue

            all_issues = []
            has_admin = False
            scope_parts = []

            # Check trust policy for cross-account access
            trust_policy = role.get('AssumeRolePolicyDocument', {})
            trust_principals = []

            statements = trust_policy.get('Statement', [])
            if isinstance(statements, dict):
                statements = [statements]

            for statement in statements:
                if statement.get('Effect') != 'Allow':
                    continue

                principal = statement.get('Principal', {})
                if isinstance(principal, str):
                    if principal == '*':
                        all_issues.append("Role can be assumed by anyone (*)")
                        trust_principals.append('*')
                elif isinstance(principal, dict):
                    aws_principals = principal.get('AWS', [])
                    if isinstance(aws_principals, str):
                        aws_principals = [aws_principals]
                    for p in aws_principals:
                        if p == '*':
                            all_issues.append("Role can be assumed by any AWS account")
                        elif ':root' in p and account_id not in p:
                            # Cross-account access
                            all_issues.append(f"Cross-account trust: {p}")
                        trust_principals.append(p)

            # Check attached managed policies
            try:
                policy_paginator = iam_client.get_paginator('list_attached_role_policies')
                for policy_page in policy_paginator.paginate(RoleName=role_name):
                    for policy in policy_page.get('AttachedPolicies', []):
                        policy_arn = policy.get('PolicyArn', '')
                        policy_name = policy.get('PolicyName', '')

                        if policy_arn in FULL_ADMIN_POLICIES:
                            has_admin = True
                            all_issues.append(f"Has {policy_name} (full admin)")

                        # Get policy document for custom policies
                        if not policy_arn.startswith('arn:aws:iam::aws:policy/'):
                            try:
                                policy_resp = iam_client.get_policy(PolicyArn=policy_arn)
                                default_version = policy_resp['Policy'].get('DefaultVersionId')
                                version_resp = iam_client.get_policy_version(
                                    PolicyArn=policy_arn,
                                    VersionId=default_version
                                )
                                doc = version_resp['PolicyVersion'].get('Document', {})
                                analysis = analyze_policy_document(doc)
                                if analysis['has_admin_access']:
                                    has_admin = True
                                all_issues.extend(analysis['issues'])
                                scope_parts.append(analysis['scope_description'])
                            except Exception as _e:
                                warn_permission_error('aws-read', _e)
            except Exception as e:
                all_issues.append(f"Could not check policies: {e}")

            # Check inline policies
            try:
                inline_paginator = iam_client.get_paginator('list_role_policies')
                for inline_page in inline_paginator.paginate(RoleName=role_name):
                    for policy_name in inline_page.get('PolicyNames', []):
                        try:
                            policy_response = iam_client.get_role_policy(
                                RoleName=role_name,
                                PolicyName=policy_name
                            )
                            doc = policy_response.get('PolicyDocument', {})
                            analysis = analyze_policy_document(doc)
                            if analysis['has_admin_access']:
                                has_admin = True
                            all_issues.extend([f"Inline policy '{policy_name}': {i}" for i in analysis['issues']])
                            scope_parts.append(f"Inline({policy_name}): {analysis['scope_description']}")
                        except Exception as _e:
                            warn_permission_error('aws-read', _e)
            except Exception as _e:
                warn_permission_error('aws-read', _e)

            # Determine overall scope
            if has_admin:
                scope_description = "UNRESTRICTED - Has admin access"
            elif scope_parts:
                scope_description = '; '.join(scope_parts[:3])
            else:
                scope_description = "MINIMAL - No significant permissions"

            # Compliance: Admin access without proper scoping is non-compliant
            # Cross-account admin access is particularly concerning
            compliant = not has_admin

            results.append({
                'account_id': account_id,
                'principal_type': 'Role',
                'principal_name': role_name,
                'principal_arn': role_arn,
                'has_admin_access': has_admin,
                'scope_description': scope_description,
                'compliant': compliant,
                'issues': all_issues
            })

    return results


def run_audit(args) -> tuple[str, dict[str, Any]]:
    """
    Run NSF3 audit across all accounts.

    Args:
        args: Parsed command line arguments

    Returns:
        Tuple of (output_file_path, summary_stats)
    """
    accounts = parse_accounts_arg(args.accounts)
    output_dir = args.output_dir
    role_name = args.role
    date = current_date()

    logger.info("NSF3 audit starting: Limited Scope Administrative Accounts")
    logger.info("Date=%s accounts=%d role=%s",
                date, len(accounts), role_name)

    # Statistics
    total_principals = 0
    admin_principals = 0
    compliant_principals = 0
    non_compliant_principals = 0

    # CSV rows
    csv_rows = []

    for account_id in accounts:
        logger.info("Auditing account: %s", account_id)

        try:
            with AuditContext(account_id, role_name=role_name, profile=args.profile, external_id=args.external_id) as ctx:
                iam = ctx.client('iam')

                # Audit users
                user_results = audit_iam_users(iam, account_id)
                logger.info("Audited %d users in account %s", len(user_results), account_id)

                for result in user_results:
                    total_principals += 1
                    if result['has_admin_access']:
                        admin_principals += 1
                    if result['compliant']:
                        compliant_principals += 1
                    else:
                        non_compliant_principals += 1

                    csv_rows.append([
                        result['account_id'],
                        result['principal_type'],
                        result['principal_name'],
                        result['principal_arn'],
                        str(result['has_admin_access']),
                        result['scope_description'],
                        str(result['compliant']),
                        '; '.join(result['issues']) if result['issues'] else 'None'
                    ])

                # Audit roles
                role_results = audit_iam_roles(iam, account_id)
                print(f"  Audited {len(role_results)} roles")

                for result in role_results:
                    total_principals += 1
                    if result['has_admin_access']:
                        admin_principals += 1
                    if result['compliant']:
                        compliant_principals += 1
                    else:
                        non_compliant_principals += 1

                    csv_rows.append([
                        result['account_id'],
                        result['principal_type'],
                        result['principal_name'],
                        result['principal_arn'],
                        str(result['has_admin_access']),
                        result['scope_description'],
                        str(result['compliant']),
                        '; '.join(result['issues']) if result['issues'] else 'None'
                    ])

        except Exception as e:
            logger.error("Error auditing account %s: %s", account_id, e)
            continue

    # Save CSV
    headers = [
        'AccountId', 'PrincipalType', 'PrincipalName', 'PrincipalArn',
        'HasAdminAccess', 'ScopeDescription', 'Compliant', 'Issues'
    ]

    # Print summary
    summary = {
        'total_principals': total_principals,
        'admin_principals': admin_principals,
        'compliant': compliant_principals,
        'non_compliant': non_compliant_principals
    }

    formats = parse_formats_arg(args.format)
    records = [dict(zip(headers, row)) for row in csv_rows]
    written_files = save_results(
        output_dir, f"nsf3-{date}", records, summary, formats, headers,
        title="NSF3 Audit",
    )

    print("\n" + "=" * 70)
    print("NSF3 AUDIT SUMMARY")
    print("=" * 70)
    print(f"Total Principals Scanned: {total_principals}")
    print(f"With Admin Access:        {admin_principals}")
    print(f"Compliant (scoped):       {compliant_principals}")
    print(f"Non-Compliant (broad):    {non_compliant_principals}")
    print("\nReports saved:")
    for fp in written_files:
        print(f"  {fp}")

    return written_files, summary


def main():
    parser = argparse.ArgumentParser(
        description='NSF3: Limited Scope Administrative Accounts',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Audit all accounts
  %(prog)s

  # Audit specific accounts
  %(prog)s --accounts 123456789012,234567890123

Compliance Criteria:
  - Administrative accounts should not have unrestricted (*:*) access
  - Permissions should be scoped to specific services/resources
  - Separation of duties should be enforced
  - Cross-account admin access should be minimized
        """
    )

    add_common_arguments(parser)

    args = parser.parse_args()
    configure_logging(verbose=args.verbose, quiet=args.quiet, log_file=args.log_file)

    try:
        written_files, summary = run_audit(args)


        # Return non-zero if there are non-compliant principals
        return 1 if summary['non_compliant'] > 0 or permission_failure_count() > 0 else 0

    except KeyboardInterrupt:
        logger.error("Interrupted by user")
        return 130
    except Exception as e:
        logger.error("Audit error: %s", e)
        return 1


if __name__ == '__main__':
    sys.exit(main())
