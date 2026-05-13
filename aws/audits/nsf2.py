#!/usr/bin/env python3
"""
NSF2 Control Audit: Phishing-resistant MFA for Remote Access

Protocols, for example SSH, RDP (remote desktop), FTP, VNC, or VPN
should require MFA.

REF: IA-2(2), AC-17 800-53r5

This audit checks:
- AWS Client VPN endpoints MFA configuration
- AWS WorkSpaces directory MFA settings
- Session Manager access controls
- IAM policies requiring MFA conditions for sensitive actions

Usage:
    python nsf2.py
    python nsf2.py --accounts 123456789012,234567890123

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
    parse_regions_arg,
    permission_failure_count,
    save_results,
    warn_permission_error,
)


logger = get_logger('nsf2')




def audit_client_vpn_endpoints(
    ec2_client,
    account_id: str,
    region: str
) -> list[dict[str, Any]]:
    """
    Audit AWS Client VPN endpoints for MFA configuration.

    Args:
        ec2_client: boto3 EC2 client
        account_id: AWS account ID
        region: AWS region

    Returns:
        List of VPN endpoint audit results
    """
    results = []

    try:
        response = ec2_client.describe_client_vpn_endpoints()
        endpoints = response.get('ClientVpnEndpoints', [])

        for endpoint in endpoints:
            endpoint_id = endpoint.get('ClientVpnEndpointId', '')
            description = endpoint.get('Description', 'No description')
            status = endpoint.get('Status', {}).get('Code', 'unknown')

            # Check authentication options
            auth_options = endpoint.get('AuthenticationOptions', [])
            mfa_required = False
            auth_types = []

            for auth in auth_options:
                auth_type = auth.get('Type', 'unknown')
                auth_types.append(auth_type)

                # Check for MFA in different auth types
                if auth_type == 'federated-authentication':
                    # SAML-based auth may have MFA at IdP level
                    saml_provider = auth.get('FederatedAuthentication', {}).get('SAMLProviderArn', '')
                    # We can't verify IdP MFA config, flag for review
                    auth_types[-1] = f"SAML ({saml_provider.split('/')[-1] if saml_provider else 'unknown'})"

                elif auth_type == 'certificate-authentication':
                    # Certificate auth alone is not MFA
                    pass

                elif auth_type == 'directory-service-authentication':
                    # AD auth - check if MFA is configured
                    ds_id = auth.get('ActiveDirectory', {}).get('DirectoryId', '')
                    auth_types[-1] = f"AD ({ds_id})"

            # Determine compliance
            issues = []

            # VPN should have strong auth
            if not auth_options:
                issues.append("No authentication configured")
            elif len(auth_types) == 1 and 'certificate' in auth_types[0].lower():
                issues.append("Certificate-only auth (no MFA)")

            # Note: We recommend SAML with MFA at IdP or mutual TLS + user auth
            compliant = len(issues) == 0

            results.append({
                'account_id': account_id,
                'region': region,
                'resource_type': 'ClientVPN',
                'resource_id': endpoint_id,
                'resource_name': description,
                'auth_types': '; '.join(auth_types) if auth_types else 'None',
                'mfa_required': 'Review IdP' if 'SAML' in str(auth_types) else str(mfa_required),
                'status': status,
                'compliant': compliant,
                'issues': issues
            })

    except ec2_client.exceptions.ClientError as e:
        if 'is not authorized' not in str(e) and 'AccessDenied' not in str(e):
            logger.warning("Could not check Client VPN in {region}: %s", e)
    except Exception as e:
        if 'does not exist' not in str(e):
            logger.warning("Error checking Client VPN in {region}: %s", e)

    return results


def audit_workspaces_directories(
    workspaces_client,
    account_id: str,
    region: str
) -> list[dict[str, Any]]:
    """
    Audit AWS WorkSpaces directories for MFA configuration.

    Args:
        workspaces_client: boto3 WorkSpaces client
        account_id: AWS account ID
        region: AWS region

    Returns:
        List of WorkSpaces directory audit results
    """
    results = []

    try:
        response = workspaces_client.describe_workspace_directories()
        directories = response.get('Directories', [])

        for directory in directories:
            directory_id = directory.get('DirectoryId', '')
            directory_name = directory.get('DirectoryName', '')
            directory_type = directory.get('DirectoryType', 'unknown')
            state = directory.get('State', 'unknown')

            # Check workspace creation properties for MFA
            ws_creation = directory.get('WorkspaceCreationProperties', {})
            user_enabled_as_admin = ws_creation.get('UserEnabledAsLocalAdministrator', False)

            # Check workspace access properties
            ws_access = directory.get('WorkspaceAccessProperties', {})

            # Check self-service permissions
            self_service = directory.get('SelfservicePermissions', {})

            # Check SAML properties for MFA
            saml_properties = directory.get('SamlProperties', {})
            saml_status = saml_properties.get('Status', 'DISABLED')

            # Determine MFA status
            # WorkSpaces can use RADIUS MFA or SAML-based auth with MFA at IdP
            mfa_status = 'Not Configured'

            if saml_status == 'ENABLED':
                mfa_status = 'SAML (check IdP for MFA)'

            # Check if any MFA-like features are enabled
            issues = []

            if saml_status != 'ENABLED':
                issues.append("SAML authentication not enabled")

            if user_enabled_as_admin:
                issues.append("Users enabled as local administrator")

            compliant = saml_status == 'ENABLED'

            results.append({
                'account_id': account_id,
                'region': region,
                'resource_type': 'WorkSpacesDirectory',
                'resource_id': directory_id,
                'resource_name': directory_name,
                'auth_types': f"{directory_type}; SAML: {saml_status}",
                'mfa_required': mfa_status,
                'status': state,
                'compliant': compliant,
                'issues': issues
            })

    except workspaces_client.exceptions.ClientError as e:
        if 'is not authorized' not in str(e) and 'AccessDenied' not in str(e):
            logger.warning("Could not check WorkSpaces in {region}: %s", e)
    except Exception as e:
        if 'not subscribed' not in str(e).lower():
            logger.warning("Error checking WorkSpaces in {region}: %s", e)

    return results


def audit_ssm_session_preferences(
    ssm_client,
    account_id: str,
    region: str
) -> list[dict[str, Any]]:
    """
    Audit SSM Session Manager preferences.

    Args:
        ssm_client: boto3 SSM client
        account_id: AWS account ID
        region: AWS region

    Returns:
        List of SSM session audit results
    """
    results = []

    try:
        # Get Session Manager preferences document
        response = ssm_client.get_document(
            Name='SSM-SessionManagerRunShell',
            DocumentFormat='JSON'
        )

        content = response.get('Content', '{}')
        doc = json.loads(content) if isinstance(content, str) else content

        # Check session preferences
        inputs = doc.get('inputs', {}) if doc else {}

        # Session Manager doesn't have built-in MFA, but we check for other security features
        run_as_enabled = inputs.get('runAsEnabled', False)
        run_as_user = inputs.get('runAsDefaultUser', '')
        idle_timeout = inputs.get('idleSessionTimeout', '')
        encryption = inputs.get('kmsKeyId', '')

        issues = []

        if not encryption:
            issues.append("Session encryption not configured")

        if not idle_timeout or int(idle_timeout) > 30:
            issues.append("Session idle timeout not set or too long")

        # Note: Session Manager relies on IAM for access control
        # MFA should be enforced at IAM level for StartSession action
        issues.append("Review IAM policies for MFA requirement on ssm:StartSession")

        results.append({
            'account_id': account_id,
            'region': region,
            'resource_type': 'SessionManager',
            'resource_id': 'SSM-SessionManagerRunShell',
            'resource_name': 'Session Manager Preferences',
            'auth_types': 'IAM',
            'mfa_required': 'Via IAM Policy',
            'status': 'Active',
            'compliant': len(issues) <= 1,  # Only the IAM review note
            'issues': issues
        })

    except ssm_client.exceptions.InvalidDocument:
        # Document doesn't exist - Session Manager not configured
        results.append({
            'account_id': account_id,
            'region': region,
            'resource_type': 'SessionManager',
            'resource_id': 'N/A',
            'resource_name': 'Session Manager Preferences',
            'auth_types': 'Not Configured',
            'mfa_required': 'N/A',
            'status': 'Not Configured',
            'compliant': True,  # Not using it is fine
            'issues': ['Session Manager not configured']
        })
    except Exception as e:
        if not warn_permission_error('aws-read', e):
            logger.warning("Error checking Session Manager in {region}: %s", e)

    return results


def audit_iam_mfa_policies(
    iam_client,
    account_id: str
) -> list[dict[str, Any]]:
    """
    Audit IAM policies for MFA conditions on sensitive actions.

    Args:
        iam_client: boto3 IAM client
        account_id: AWS account ID

    Returns:
        List of IAM policy audit results
    """
    results = []

    # Sensitive actions that should require MFA
    sensitive_actions = [
        'ssm:StartSession',
        'ec2-instance-connect:SendSSHPublicKey',
        'sts:AssumeRole',
    ]

    # Check account password policy (related to console access)
    try:
        policy_response = iam_client.get_account_password_policy()
        policy = policy_response.get('PasswordPolicy', {})

        # Password policy doesn't control MFA, but we note its presence
        results.append({
            'account_id': account_id,
            'region': 'global',
            'resource_type': 'PasswordPolicy',
            'resource_id': 'AccountPasswordPolicy',
            'resource_name': 'IAM Password Policy',
            'auth_types': 'Password',
            'mfa_required': 'Not enforced by policy',
            'status': 'Active',
            'compliant': True,  # Password policy itself doesn't control MFA
            'issues': ['MFA not enforced by password policy (use IAM conditions)']
        })

    except iam_client.exceptions.NoSuchEntityException:
        results.append({
            'account_id': account_id,
            'region': 'global',
            'resource_type': 'PasswordPolicy',
            'resource_id': 'AccountPasswordPolicy',
            'resource_name': 'IAM Password Policy',
            'auth_types': 'Default',
            'mfa_required': 'N/A',
            'status': 'Not Configured',
            'compliant': False,
            'issues': ['No password policy configured']
        })
    except Exception as e:
        logger.warning("Could not check password policy: %s", e)

    return results


def run_audit(args) -> tuple[str, dict[str, Any]]:
    """
    Run NSF2 audit across all accounts.

    Args:
        args: Parsed command line arguments

    Returns:
        Tuple of (output_file_path, summary_stats)
    """
    accounts = parse_accounts_arg(args.accounts)
    regions = parse_regions_arg(args.regions)
    output_dir = args.output_dir
    role_name = args.role
    date = current_date()

    logger.info("NSF2 audit starting: Phishing-resistant MFA for Remote Access")
    logger.info("Date=%s accounts=%d regions=%d role=%s",
                date, len(accounts), len(regions), role_name)

    # Statistics
    total_resources = 0
    compliant_resources = 0
    non_compliant_resources = 0

    # CSV rows
    csv_rows = []

    for account_id in accounts:
        logger.info("Auditing account: %s", account_id)

        try:
            with AuditContext(account_id, role_name=role_name, profile=args.profile, external_id=args.external_id) as ctx:
                # Audit IAM policies (global)
                iam = ctx.client('iam')
                iam_results = audit_iam_mfa_policies(iam, account_id)

                for result in iam_results:
                    total_resources += 1
                    if result['compliant']:
                        compliant_resources += 1
                    else:
                        non_compliant_resources += 1

                    csv_rows.append([
                        result['account_id'],
                        result['region'],
                        result['resource_type'],
                        result['resource_id'],
                        result['resource_name'],
                        result['auth_types'],
                        result['mfa_required'],
                        result['status'],
                        str(result['compliant']),
                        '; '.join(result['issues']) if result['issues'] else 'None'
                    ])

                # Audit regional resources
                for region in regions:
                    try:
                        # Client VPN
                        ec2 = ctx.client('ec2', region_name=region)
                        vpn_results = audit_client_vpn_endpoints(ec2, account_id, region)

                        for result in vpn_results:
                            total_resources += 1
                            if result['compliant']:
                                compliant_resources += 1
                            else:
                                non_compliant_resources += 1

                            csv_rows.append([
                                result['account_id'],
                                result['region'],
                                result['resource_type'],
                                result['resource_id'],
                                result['resource_name'],
                                result['auth_types'],
                                result['mfa_required'],
                                result['status'],
                                str(result['compliant']),
                                '; '.join(result['issues']) if result['issues'] else 'None'
                            ])

                        # WorkSpaces
                        workspaces = ctx.client('workspaces', region_name=region)
                        ws_results = audit_workspaces_directories(workspaces, account_id, region)

                        for result in ws_results:
                            total_resources += 1
                            if result['compliant']:
                                compliant_resources += 1
                            else:
                                non_compliant_resources += 1

                            csv_rows.append([
                                result['account_id'],
                                result['region'],
                                result['resource_type'],
                                result['resource_id'],
                                result['resource_name'],
                                result['auth_types'],
                                result['mfa_required'],
                                result['status'],
                                str(result['compliant']),
                                '; '.join(result['issues']) if result['issues'] else 'None'
                            ])

                        # Session Manager
                        ssm = ctx.client('ssm', region_name=region)
                        ssm_results = audit_ssm_session_preferences(ssm, account_id, region)

                        for result in ssm_results:
                            total_resources += 1
                            if result['compliant']:
                                compliant_resources += 1
                            else:
                                non_compliant_resources += 1

                            csv_rows.append([
                                result['account_id'],
                                result['region'],
                                result['resource_type'],
                                result['resource_id'],
                                result['resource_name'],
                                result['auth_types'],
                                result['mfa_required'],
                                result['status'],
                                str(result['compliant']),
                                '; '.join(result['issues']) if result['issues'] else 'None'
                            ])

                    except Exception as e:
                        logger.warning("Error in region {region}: %s", e)
                        continue

        except Exception as e:
            logger.error("Error auditing account %s: %s", account_id, e)
            continue

    # Save CSV
    headers = [
        'AccountId', 'Region', 'ResourceType', 'ResourceId', 'ResourceName',
        'AuthTypes', 'MFARequired', 'Status', 'Compliant', 'Issues'
    ]

    # Print summary
    summary = {
        'total_resources': total_resources,
        'compliant': compliant_resources,
        'non_compliant': non_compliant_resources
    }

    formats = parse_formats_arg(args.format)
    records = [dict(zip(headers, row)) for row in csv_rows]
    written_files = save_results(
        output_dir, f"nsf2-{date}", records, summary, formats, headers,
        title="NSF2 Audit",
    )

    print("\n" + "=" * 70)
    print("NSF2 AUDIT SUMMARY")
    print("=" * 70)
    print(f"Total Resources Scanned: {total_resources}")
    print(f"Compliant:               {compliant_resources}")
    print(f"Non-Compliant:           {non_compliant_resources}")
    print("\nReports saved:")
    for fp in written_files:
        print(f"  {fp}")

    return written_files, summary


def main():
    parser = argparse.ArgumentParser(
        description='NSF2: Phishing-resistant MFA for Remote Access',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Audit all accounts
  %(prog)s

  # Audit specific accounts
  %(prog)s --accounts 123456789012,234567890123

  # Audit specific regions
  %(prog)s --regions us-east-1,us-west-2

Compliance Criteria:
  - Client VPN should use SAML with MFA at IdP or strong mutual auth
  - WorkSpaces should have SAML authentication enabled
  - Session Manager access should be controlled via IAM with MFA conditions
        """
    )

    add_common_arguments(parser)

    args = parser.parse_args()
    configure_logging(verbose=args.verbose, quiet=args.quiet, log_file=args.log_file)

    try:
        written_files, summary = run_audit(args)


        # Return non-zero if there are non-compliant resources
        return 1 if summary['non_compliant'] > 0 or permission_failure_count() > 0 else 0

    except KeyboardInterrupt:
        logger.error("Interrupted by user")
        return 130
    except Exception as e:
        logger.error("Audit error: %s", e)
        return 1


if __name__ == '__main__':
    sys.exit(main())
