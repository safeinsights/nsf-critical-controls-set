#!/usr/bin/env python3
"""
NSF11 Control Audit: Critical Infrastructure Inventory

Create and maintain a current and complete inventory of all critical
infrastructure.

REF: CM-8 800-53r5

This audit checks:
- VPN endpoints (Client VPN, Site-to-Site VPN)
- Identity management (IAM, Identity Center)
- MFA devices inventory
- Network devices (Transit Gateway, Direct Connect)
- Core services (DNS, directory services)
- Tag compliance for critical resources

Usage:
    python nsf11.py
    python nsf11.py --accounts 123456789012,234567890123

Prerequisites:
    pip install -r requirements.txt
"""

import sys
from pathlib import Path

# Add parent directory to path for imports when running directly
sys.path.insert(0, str(Path(__file__).parent.parent))

import argparse
import logging
from datetime import datetime, timezone
from typing import Any

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


logger = get_logger('nsf11')




def inventory_vpn_endpoints(
    ec2_client,
    account_id: str,
    region: str
) -> list[dict[str, Any]]:
    """
    Inventory VPN endpoints.

    Args:
        ec2_client: boto3 EC2 client
        account_id: AWS account ID
        region: AWS region

    Returns:
        List of VPN endpoint inventory items
    """
    results = []

    try:
        # Client VPN endpoints
        try:
            cvpn_response = ec2_client.describe_client_vpn_endpoints()
            for endpoint in cvpn_response.get('ClientVpnEndpoints', []):
                endpoint_id = endpoint.get('ClientVpnEndpointId', '')
                status = endpoint.get('Status', {}).get('Code', 'unknown')
                creation_time = endpoint.get('CreationTime')

                # Get tags
                tags = {tag.get('Key'): tag.get('Value') for tag in endpoint.get('Tags', [])}
                name = tags.get('Name', '')

                has_required_tags = 'Name' in tags and ('Environment' in tags or 'Owner' in tags)
                issues = []
                if not has_required_tags:
                    issues.append("Missing required tags (Name, Environment, Owner)")

                results.append({
                    'account_id': account_id,
                    'region': region,
                    'resource_type': 'ClientVPN',
                    'resource_id': endpoint_id,
                    'resource_name': name,
                    'ci_type': 'VPN/Remote Access',
                    'status': status,
                    'last_updated': creation_time.strftime('%Y-%m-%d') if creation_time else 'Unknown',
                    'tags_compliant': has_required_tags,
                    'compliant': has_required_tags,
                    'issues': issues
                })
        except Exception as _e:
            if not warn_permission_error('aws-read', _e):
                logger.warning("Non-permission error during aws-read: %s", _e)

        # Site-to-Site VPN connections
        try:
            vpn_response = ec2_client.describe_vpn_connections()
            for connection in vpn_response.get('VpnConnections', []):
                vpn_id = connection.get('VpnConnectionId', '')
                state = connection.get('State', 'unknown')

                tags = {tag.get('Key'): tag.get('Value') for tag in connection.get('Tags', [])}
                name = tags.get('Name', '')

                has_required_tags = 'Name' in tags
                issues = []
                if not has_required_tags:
                    issues.append("Missing Name tag")

                results.append({
                    'account_id': account_id,
                    'region': region,
                    'resource_type': 'Site-to-Site VPN',
                    'resource_id': vpn_id,
                    'resource_name': name,
                    'ci_type': 'VPN/Connectivity',
                    'status': state,
                    'last_updated': 'N/A',
                    'tags_compliant': has_required_tags,
                    'compliant': has_required_tags,
                    'issues': issues
                })
        except Exception as _e:
            if not warn_permission_error('aws-read', _e):
                logger.warning("Non-permission error during aws-read: %s", _e)

    except Exception as e:
        if not warn_permission_error('aws-read', e):
            logger.warning("Error inventorying VPN endpoints in %s: %s", region, e)

    return results


def inventory_transit_gateways(
    ec2_client,
    account_id: str,
    region: str
) -> list[dict[str, Any]]:
    """
    Inventory Transit Gateways.

    Args:
        ec2_client: boto3 EC2 client
        account_id: AWS account ID
        region: AWS region

    Returns:
        List of Transit Gateway inventory items
    """
    results = []

    try:
        tgw_response = ec2_client.describe_transit_gateways()
        for tgw in tgw_response.get('TransitGateways', []):
            tgw_id = tgw.get('TransitGatewayId', '')
            state = tgw.get('State', 'unknown')
            owner_id = tgw.get('OwnerId', '')
            creation_time = tgw.get('CreationTime')

            tags = {tag.get('Key'): tag.get('Value') for tag in tgw.get('Tags', [])}
            name = tags.get('Name', '')

            has_required_tags = 'Name' in tags
            issues = []
            if not has_required_tags:
                issues.append("Missing Name tag")

            results.append({
                'account_id': account_id,
                'region': region,
                'resource_type': 'TransitGateway',
                'resource_id': tgw_id,
                'resource_name': name,
                'ci_type': 'Network/Hub',
                'status': state,
                'last_updated': creation_time.strftime('%Y-%m-%d') if creation_time else 'Unknown',
                'tags_compliant': has_required_tags,
                'compliant': has_required_tags,
                'issues': issues
            })

    except Exception as e:
        if not warn_permission_error('aws-read', e):
            logger.warning("Error inventorying Transit Gateways in %s: %s", region, e)

    return results


def inventory_direct_connect(
    dx_client,
    account_id: str,
    region: str
) -> list[dict[str, Any]]:
    """
    Inventory Direct Connect connections.

    Args:
        dx_client: boto3 Direct Connect client
        account_id: AWS account ID
        region: AWS region

    Returns:
        List of Direct Connect inventory items
    """
    results = []

    try:
        dx_response = dx_client.describe_connections()
        for connection in dx_response.get('connections', []):
            conn_id = connection.get('connectionId', '')
            conn_name = connection.get('connectionName', '')
            state = connection.get('connectionState', 'unknown')
            location = connection.get('location', '')
            bandwidth = connection.get('bandwidth', '')

            tags = {tag.get('key'): tag.get('value') for tag in connection.get('tags', [])}

            has_required_tags = 'Name' in tags or bool(conn_name)
            issues = []
            if not has_required_tags:
                issues.append("Missing Name tag")

            results.append({
                'account_id': account_id,
                'region': region,
                'resource_type': 'DirectConnect',
                'resource_id': conn_id,
                'resource_name': conn_name,
                'ci_type': 'Network/Dedicated',
                'status': state,
                'last_updated': 'N/A',
                'tags_compliant': has_required_tags,
                'compliant': has_required_tags,
                'issues': issues
            })

    except Exception as e:
        if not warn_permission_error('aws-read', e):
            logger.warning("Error inventorying Direct Connect in %s: %s", region, e)

    return results


def inventory_directory_services(
    ds_client,
    account_id: str,
    region: str
) -> list[dict[str, Any]]:
    """
    Inventory Directory Service directories.

    Args:
        ds_client: boto3 Directory Service client
        account_id: AWS account ID
        region: AWS region

    Returns:
        List of directory service inventory items
    """
    results = []

    try:
        ds_response = ds_client.describe_directories()
        for directory in ds_response.get('DirectoryDescriptions', []):
            dir_id = directory.get('DirectoryId', '')
            dir_name = directory.get('Name', '')
            dir_type = directory.get('Type', '')
            stage = directory.get('Stage', 'unknown')
            launch_time = directory.get('LaunchTime')

            issues = []
            compliant = bool(dir_name)

            results.append({
                'account_id': account_id,
                'region': region,
                'resource_type': f'Directory-{dir_type}',
                'resource_id': dir_id,
                'resource_name': dir_name,
                'ci_type': 'Identity/Directory',
                'status': stage,
                'last_updated': launch_time.strftime('%Y-%m-%d') if launch_time else 'Unknown',
                'tags_compliant': True,  # Directories don't support standard tags
                'compliant': compliant,
                'issues': issues
            })

    except Exception as e:
        if not warn_permission_error('aws-read', e):
            logger.warning("Error inventorying Directory Services in %s: %s", region, e)

    return results


def inventory_route53_zones(
    route53_client,
    account_id: str,
    region: str
) -> list[dict[str, Any]]:
    """
    Inventory Route53 hosted zones (DNS).

    Args:
        route53_client: boto53 Route53 client
        account_id: AWS account ID
        region: AWS region (only run in us-east-1)

    Returns:
        List of Route53 zone inventory items
    """
    results = []

    # Route53 is global, only run in us-east-1
    if region != 'us-east-1':
        return results

    try:
        paginator = route53_client.get_paginator('list_hosted_zones')
        for page in paginator.paginate():
            for zone in page.get('HostedZones', []):
                zone_id = zone.get('Id', '').replace('/hostedzone/', '')
                zone_name = zone.get('Name', '')
                is_private = zone.get('Config', {}).get('PrivateZone', False)
                record_count = zone.get('ResourceRecordSetCount', 0)

                # Get tags
                tags = {}
                try:
                    tag_response = route53_client.list_tags_for_resource(
                        ResourceType='hostedzone',
                        ResourceId=zone_id
                    )
                    tags = {tag.get('Key'): tag.get('Value') for tag in tag_response.get('ResourceTagSet', {}).get('Tags', [])}
                except Exception as _e:
                    if not warn_permission_error('aws-read', _e):
                        logger.warning("Non-permission error during aws-read: %s", _e)

                has_required_tags = 'Name' in tags or bool(zone_name)
                issues = []
                if not tags:
                    issues.append("No tags configured")

                results.append({
                    'account_id': account_id,
                    'region': 'global',
                    'resource_type': 'Route53Zone',
                    'resource_id': zone_id,
                    'resource_name': zone_name,
                    'ci_type': 'DNS/Private' if is_private else 'DNS/Public',
                    'status': f'{record_count} records',
                    'last_updated': 'N/A',
                    'tags_compliant': has_required_tags,
                    'compliant': has_required_tags,
                    'issues': issues
                })

    except Exception as e:
        if not warn_permission_error('aws-read', e):
            logger.warning("Error inventorying Route53 zones: %s", e)

    return results


def inventory_iam_resources(
    iam_client,
    account_id: str,
    region: str
) -> list[dict[str, Any]]:
    """
    Inventory critical IAM resources (admin users, MFA devices).

    Args:
        iam_client: boto3 IAM client
        account_id: AWS account ID
        region: AWS region (only run in us-east-1)

    Returns:
        List of IAM resource inventory items
    """
    results = []

    # IAM is global, only run in us-east-1
    if region != 'us-east-1':
        return results

    try:
        # MFA Devices
        try:
            mfa_response = iam_client.list_virtual_mfa_devices()
            virtual_mfa_count = len(mfa_response.get('VirtualMFADevices', []))

            results.append({
                'account_id': account_id,
                'region': 'global',
                'resource_type': 'MFADevices',
                'resource_id': 'virtual-mfa',
                'resource_name': f'{virtual_mfa_count} Virtual MFA devices',
                'ci_type': 'Identity/MFA',
                'status': 'Active',
                'last_updated': current_date(),
                'tags_compliant': True,
                'compliant': True,
                'issues': []
            })
        except Exception as _e:
            if not warn_permission_error('aws-read', _e):
                logger.warning("Non-permission error during aws-read: %s", _e)

        # Account password policy
        try:
            policy = iam_client.get_account_password_policy()
            policy_data = policy.get('PasswordPolicy', {})

            min_length = policy_data.get('MinimumPasswordLength', 0)
            require_symbols = policy_data.get('RequireSymbols', False)
            require_numbers = policy_data.get('RequireNumbers', False)
            max_age = policy_data.get('MaxPasswordAge', 0)

            issues = []
            if min_length < 14:
                issues.append(f"Password length {min_length} < 14")
            if not require_symbols:
                issues.append("Symbols not required")
            if max_age > 90 or max_age == 0:
                issues.append(f"Password max age {max_age} days (should be <= 90)")

            results.append({
                'account_id': account_id,
                'region': 'global',
                'resource_type': 'PasswordPolicy',
                'resource_id': 'account-password-policy',
                'resource_name': 'IAM Password Policy',
                'ci_type': 'Identity/Policy',
                'status': 'Configured',
                'last_updated': current_date(),
                'tags_compliant': True,
                'compliant': len(issues) == 0,
                'issues': issues
            })
        except iam_client.exceptions.NoSuchEntityException:
            results.append({
                'account_id': account_id,
                'region': 'global',
                'resource_type': 'PasswordPolicy',
                'resource_id': 'account-password-policy',
                'resource_name': 'IAM Password Policy',
                'ci_type': 'Identity/Policy',
                'status': 'Not Configured',
                'last_updated': current_date(),
                'tags_compliant': True,
                'compliant': False,
                'issues': ['Password policy not configured']
            })

        # Identity providers (SSO/SAML)
        try:
            saml_response = iam_client.list_saml_providers()
            for provider in saml_response.get('SAMLProviderList', []):
                provider_arn = provider.get('Arn', '')
                provider_name = provider_arn.split('/')[-1] if provider_arn else 'Unknown'
                create_date = provider.get('CreateDate')

                results.append({
                    'account_id': account_id,
                    'region': 'global',
                    'resource_type': 'SAMLProvider',
                    'resource_id': provider_arn,
                    'resource_name': provider_name,
                    'ci_type': 'Identity/Federation',
                    'status': 'Active',
                    'last_updated': create_date.strftime('%Y-%m-%d') if create_date else 'Unknown',
                    'tags_compliant': True,
                    'compliant': True,
                    'issues': []
                })
        except Exception as _e:
            if not warn_permission_error('aws-read', _e):
                logger.warning("Non-permission error during aws-read: %s", _e)

    except Exception as e:
        if not warn_permission_error('aws-read', e):
            logger.warning("Error inventorying IAM resources: %s", e)

    return results


def inventory_identity_center(
    sso_admin_client,
    account_id: str,
    region: str
) -> list[dict[str, Any]]:
    """
    Inventory AWS Identity Center instances.

    Args:
        sso_admin_client: boto3 SSO Admin client
        account_id: AWS account ID
        region: AWS region

    Returns:
        List of Identity Center inventory items
    """
    results = []

    try:
        instances_response = sso_admin_client.list_instances()
        for instance in instances_response.get('Instances', []):
            instance_arn = instance.get('InstanceArn', '')
            identity_store_id = instance.get('IdentityStoreId', '')

            results.append({
                'account_id': account_id,
                'region': region,
                'resource_type': 'IdentityCenter',
                'resource_id': instance_arn,
                'resource_name': f'Identity Store: {identity_store_id}',
                'ci_type': 'Identity/SSO',
                'status': 'Active',
                'last_updated': current_date(),
                'tags_compliant': True,
                'compliant': True,
                'issues': []
            })

    except Exception as e:
        if not warn_permission_error('aws-read', e) and 'is not enabled' not in str(e).lower():
            logger.warning("Error inventorying Identity Center in %s: %s", region, e)

    return results


def run_audit(args) -> tuple[str, dict[str, Any]]:
    """
    Run NSF11 audit across all accounts.

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

    logger.info("NSF11 audit starting: Critical Infrastructure Inventory")
    logger.info("Date=%s accounts=%d regions=%d role=%s",
                date, len(accounts), len(regions), role_name)

    # Statistics
    total_ci_resources = 0
    compliant_resources = 0
    non_compliant_resources = 0
    by_ci_type = {}

    # CSV rows
    csv_rows = []

    for account_id in accounts:
        logger.info("Auditing account: %s", account_id)

        try:
            with AuditContext(account_id, role_name=role_name, profile=args.profile, external_id=args.external_id) as ctx:
                for region in regions:
                    try:
                        # VPN endpoints
                        ec2 = ctx.client('ec2', region_name=region)
                        vpn_results = inventory_vpn_endpoints(ec2, account_id, region)

                        for result in vpn_results:
                            total_ci_resources += 1
                            ci_type = result['ci_type']
                            by_ci_type[ci_type] = by_ci_type.get(ci_type, 0) + 1

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
                                result['ci_type'],
                                result['status'],
                                result['last_updated'],
                                str(result['tags_compliant']),
                                str(result['compliant']),
                                '; '.join(result['issues']) if result['issues'] else 'None'
                            ])

                        # Transit Gateways
                        tgw_results = inventory_transit_gateways(ec2, account_id, region)
                        for result in tgw_results:
                            total_ci_resources += 1
                            ci_type = result['ci_type']
                            by_ci_type[ci_type] = by_ci_type.get(ci_type, 0) + 1

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
                                result['ci_type'],
                                result['status'],
                                result['last_updated'],
                                str(result['tags_compliant']),
                                str(result['compliant']),
                                '; '.join(result['issues']) if result['issues'] else 'None'
                            ])

                        # Direct Connect
                        dx = ctx.client('directconnect', region_name=region)
                        dx_results = inventory_direct_connect(dx, account_id, region)
                        for result in dx_results:
                            total_ci_resources += 1
                            ci_type = result['ci_type']
                            by_ci_type[ci_type] = by_ci_type.get(ci_type, 0) + 1

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
                                result['ci_type'],
                                result['status'],
                                result['last_updated'],
                                str(result['tags_compliant']),
                                str(result['compliant']),
                                '; '.join(result['issues']) if result['issues'] else 'None'
                            ])

                        # Directory Services
                        ds = ctx.client('ds', region_name=region)
                        ds_results = inventory_directory_services(ds, account_id, region)
                        for result in ds_results:
                            total_ci_resources += 1
                            ci_type = result['ci_type']
                            by_ci_type[ci_type] = by_ci_type.get(ci_type, 0) + 1

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
                                result['ci_type'],
                                result['status'],
                                result['last_updated'],
                                str(result['tags_compliant']),
                                str(result['compliant']),
                                '; '.join(result['issues']) if result['issues'] else 'None'
                            ])

                        # Route53 (global, only in us-east-1)
                        if region == 'us-east-1':
                            route53 = ctx.client('route53', region_name=region)
                            r53_results = inventory_route53_zones(route53, account_id, region)
                            for result in r53_results:
                                total_ci_resources += 1
                                ci_type = result['ci_type']
                                by_ci_type[ci_type] = by_ci_type.get(ci_type, 0) + 1

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
                                    result['ci_type'],
                                    result['status'],
                                    result['last_updated'],
                                    str(result['tags_compliant']),
                                    str(result['compliant']),
                                    '; '.join(result['issues']) if result['issues'] else 'None'
                                ])

                            # IAM resources (global)
                            iam = ctx.client('iam', region_name=region)
                            iam_results = inventory_iam_resources(iam, account_id, region)
                            for result in iam_results:
                                total_ci_resources += 1
                                ci_type = result['ci_type']
                                by_ci_type[ci_type] = by_ci_type.get(ci_type, 0) + 1

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
                                    result['ci_type'],
                                    result['status'],
                                    result['last_updated'],
                                    str(result['tags_compliant']),
                                    str(result['compliant']),
                                    '; '.join(result['issues']) if result['issues'] else 'None'
                                ])

                        # Identity Center
                        try:
                            sso_admin = ctx.client('sso-admin', region_name=region)
                            sso_results = inventory_identity_center(sso_admin, account_id, region)
                            for result in sso_results:
                                total_ci_resources += 1
                                ci_type = result['ci_type']
                                by_ci_type[ci_type] = by_ci_type.get(ci_type, 0) + 1

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
                                    result['ci_type'],
                                    result['status'],
                                    result['last_updated'],
                                    str(result['tags_compliant']),
                                    str(result['compliant']),
                                    '; '.join(result['issues']) if result['issues'] else 'None'
                                ])
                        except Exception as _e:
                            if not warn_permission_error('aws-read', _e):
                                logger.warning("Non-permission error during aws-read: %s", _e)

                    except Exception as e:
                        logger.warning("Error in region %s: %s", region, e)
                        continue

        except Exception as e:
            logger.error("Error auditing account %s: %s", account_id, e)
            continue

    # Save CSV
    headers = [
        'AccountId', 'Region', 'ResourceType', 'ResourceId',
        'ResourceName', 'CIType', 'Status', 'LastUpdated',
        'TagsCompliant', 'Compliant', 'Issues'
    ]

    # Print summary
    summary = {
        'total_ci_resources': total_ci_resources,
        'compliant': compliant_resources,
        'non_compliant': non_compliant_resources,
        'by_type': by_ci_type
    }

    formats = parse_formats_arg(args.format)
    records = [dict(zip(headers, row)) for row in csv_rows]
    written_files = save_results(
        output_dir, f"nsf11-{date}", records, summary, formats, headers,
        title="NSF11 Audit",
    )

    print("\n" + "=" * 70)
    print("NSF11 AUDIT SUMMARY")
    print("=" * 70)
    print(f"Total CI Resources:    {total_ci_resources}")
    print(f"Compliant:             {compliant_resources}")
    print(f"Non-Compliant:         {non_compliant_resources}")
    print("\nBy CI Type:")
    for ci_type, count in sorted(by_ci_type.items()):
        print(f"  {ci_type}: {count}")
    print("\nReports saved:")
    for fp in written_files:
        print(f"  {fp}")

    return written_files, summary


def main():
    parser = argparse.ArgumentParser(
        description='NSF11: Critical Infrastructure Inventory',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Audit all accounts
  %(prog)s

  # Audit specific accounts
  %(prog)s --accounts 123456789012,234567890123

  # Audit specific regions
  %(prog)s --regions us-east-1,us-west-2

Critical Infrastructure Types Inventoried:
  - VPN/Remote Access: Client VPN endpoints
  - VPN/Connectivity: Site-to-Site VPN connections
  - Network/Hub: Transit Gateways
  - Network/Dedicated: Direct Connect connections
  - Identity/Directory: AWS Directory Service
  - Identity/SSO: AWS Identity Center
  - Identity/MFA: MFA devices
  - Identity/Federation: SAML providers
  - Identity/Policy: Password policy
  - DNS/Public: Route53 public zones
  - DNS/Private: Route53 private zones
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
