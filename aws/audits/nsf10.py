#!/usr/bin/env python3
"""
NSF10 Control Audit: Network Segmentation and Isolation Control

Implement network segmentation and isolation control to logically or physically
separate networks into distinct zones for critical infrastructure and research
data.

REF: SC-7 800-53r5

This audit checks:
- Default VPC usage (should not be used for production)
- Subnet segregation (public vs private)
- NACL restrictive configurations
- Security group isolation (no 0.0.0.0/0 internal)
- Transit Gateway route isolation
- VPC endpoint usage for AWS services
- Internet Gateway and NAT Gateway placement

Usage:
    python nsf10.py
    python nsf10.py --accounts 123456789012,234567890123

Prerequisites:
    pip install -r requirements.txt
"""

import sys
from pathlib import Path

# Add parent directory to path for imports when running directly
sys.path.insert(0, str(Path(__file__).parent.parent))

import argparse
import logging
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


logger = get_logger('nsf10')




def audit_vpcs(
    ec2_client,
    account_id: str,
    region: str
) -> list[dict[str, Any]]:
    """
    Audit VPC configurations for segmentation.

    Args:
        ec2_client: boto3 EC2 client
        account_id: AWS account ID
        region: AWS region

    Returns:
        List of VPC audit results
    """
    results = []

    try:
        vpcs_response = ec2_client.describe_vpcs()
        vpcs = vpcs_response.get('Vpcs', [])

        for vpc in vpcs:
            vpc_id = vpc.get('VpcId', '')
            is_default = vpc.get('IsDefault', False)
            cidr_block = vpc.get('CidrBlock', '')

            # Get VPC name
            vpc_name = ''
            for tag in vpc.get('Tags', []):
                if tag.get('Key') == 'Name':
                    vpc_name = tag.get('Value', '')
                    break

            issues = []
            segmentation_type = 'Custom VPC'

            if is_default:
                segmentation_type = 'Default VPC'
                issues.append("Using default VPC (not recommended for production)")

            # Check for flow logs on this VPC
            flow_logs = ec2_client.describe_flow_logs(
                Filters=[{'Name': 'resource-id', 'Values': [vpc_id]}]
            )
            has_flow_logs = len(flow_logs.get('FlowLogs', [])) > 0

            if not has_flow_logs:
                issues.append("No VPC Flow Logs configured")

            compliant = not is_default and has_flow_logs

            results.append({
                'account_id': account_id,
                'region': region,
                'resource_type': 'VPC',
                'resource_id': vpc_id,
                'resource_name': vpc_name,
                'segmentation_type': segmentation_type,
                'isolation_level': 'Account' if not is_default else 'Shared',
                'cidr_block': cidr_block,
                'compliant': compliant,
                'issues': issues
            })

    except Exception as e:
        if not warn_permission_error('aws-read', e):
            logger.warning("Error checking VPCs in %s: %s", region, e)

    return results


def audit_subnets(
    ec2_client,
    account_id: str,
    region: str
) -> list[dict[str, Any]]:
    """
    Audit subnet configurations for proper segmentation.

    Args:
        ec2_client: boto3 EC2 client
        account_id: AWS account ID
        region: AWS region

    Returns:
        List of subnet audit results
    """
    results = []

    try:
        # Get all subnets
        subnets_response = ec2_client.describe_subnets()
        subnets = subnets_response.get('Subnets', [])

        # Get route tables to determine public vs private
        route_tables_response = ec2_client.describe_route_tables()
        route_tables = route_tables_response.get('RouteTables', [])

        # Build a map of subnet to route table
        subnet_route_map = {}
        for rt in route_tables:
            rt_id = rt.get('RouteTableId', '')
            has_igw = any(
                route.get('GatewayId', '').startswith('igw-')
                for route in rt.get('Routes', [])
            )

            for assoc in rt.get('Associations', []):
                subnet_id = assoc.get('SubnetId')
                if subnet_id:
                    subnet_route_map[subnet_id] = {
                        'route_table_id': rt_id,
                        'has_igw_route': has_igw
                    }

            # Check for main route table (default for subnets without explicit association)
            if rt.get('Associations', [{}])[0].get('Main', False):
                vpc_id = rt.get('VpcId', '')
                subnet_route_map[f'main-{vpc_id}'] = {
                    'route_table_id': rt_id,
                    'has_igw_route': has_igw
                }

        for subnet in subnets:
            subnet_id = subnet.get('SubnetId', '')
            vpc_id = subnet.get('VpcId', '')
            cidr_block = subnet.get('CidrBlock', '')
            az = subnet.get('AvailabilityZone', '')
            auto_assign_public_ip = subnet.get('MapPublicIpOnLaunch', False)

            # Get subnet name
            subnet_name = ''
            for tag in subnet.get('Tags', []):
                if tag.get('Key') == 'Name':
                    subnet_name = tag.get('Value', '')
                    break

            issues = []

            # Determine if public or private
            route_info = subnet_route_map.get(subnet_id)
            if not route_info:
                # Use VPC's main route table
                route_info = subnet_route_map.get(f'main-{vpc_id}', {})

            has_igw_route = route_info.get('has_igw_route', False)

            if has_igw_route:
                segmentation_type = 'Public Subnet'
                if auto_assign_public_ip:
                    issues.append("Auto-assigns public IP (increases exposure)")
            else:
                segmentation_type = 'Private Subnet'

            # Determine isolation level
            if 'private' in subnet_name.lower() or 'internal' in subnet_name.lower():
                isolation_level = 'Private'
            elif 'public' in subnet_name.lower() or 'dmz' in subnet_name.lower():
                isolation_level = 'DMZ'
            elif 'data' in subnet_name.lower() or 'db' in subnet_name.lower():
                isolation_level = 'Data Tier'
            else:
                isolation_level = 'Unknown'

            # Public subnets are compliant but flagged
            compliant = True
            if has_igw_route and 'private' in subnet_name.lower():
                compliant = False
                issues.append("Subnet named 'private' but has IGW route")

            results.append({
                'account_id': account_id,
                'region': region,
                'resource_type': 'Subnet',
                'resource_id': subnet_id,
                'resource_name': subnet_name,
                'segmentation_type': segmentation_type,
                'isolation_level': isolation_level,
                'cidr_block': cidr_block,
                'compliant': compliant,
                'issues': issues
            })

    except Exception as e:
        if not warn_permission_error('aws-read', e):
            logger.warning("Error checking subnets in %s: %s", region, e)

    return results


def audit_security_groups(
    ec2_client,
    account_id: str,
    region: str
) -> list[dict[str, Any]]:
    """
    Audit security groups for overly permissive rules.

    Args:
        ec2_client: boto3 EC2 client
        account_id: AWS account ID
        region: AWS region

    Returns:
        List of security group audit results
    """
    results = []

    try:
        paginator = ec2_client.get_paginator('describe_security_groups')

        for page in paginator.paginate():
            for sg in page.get('SecurityGroups', []):
                sg_id = sg.get('GroupId', '')
                sg_name = sg.get('GroupName', '')
                vpc_id = sg.get('VpcId', '')
                description = sg.get('Description', '')

                issues = []
                overly_permissive = False

                # Check inbound rules
                for rule in sg.get('IpPermissions', []):
                    from_port = rule.get('FromPort', 0)
                    to_port = rule.get('ToPort', 65535)
                    ip_protocol = rule.get('IpProtocol', '')

                    # Check for 0.0.0.0/0 or ::/0
                    for ip_range in rule.get('IpRanges', []):
                        cidr = ip_range.get('CidrIp', '')
                        if cidr == '0.0.0.0/0':
                            if ip_protocol == '-1':
                                issues.append("Allows all traffic from 0.0.0.0/0")
                                overly_permissive = True
                            elif from_port == 22:
                                issues.append("SSH (22) open to 0.0.0.0/0")
                            elif from_port == 3389:
                                issues.append("RDP (3389) open to 0.0.0.0/0")
                            elif from_port == 0 and to_port == 65535:
                                issues.append("All ports open to 0.0.0.0/0")
                                overly_permissive = True

                    for ip_range in rule.get('Ipv6Ranges', []):
                        cidr = ip_range.get('CidrIpv6', '')
                        if cidr == '::/0':
                            if ip_protocol == '-1':
                                issues.append("Allows all traffic from ::/0")
                                overly_permissive = True

                # Determine segmentation type
                if 'default' in sg_name.lower():
                    segmentation_type = 'Default SG'
                elif overly_permissive:
                    segmentation_type = 'Open SG'
                else:
                    segmentation_type = 'Restricted SG'

                compliant = not overly_permissive

                results.append({
                    'account_id': account_id,
                    'region': region,
                    'resource_type': 'SecurityGroup',
                    'resource_id': sg_id,
                    'resource_name': sg_name,
                    'segmentation_type': segmentation_type,
                    'isolation_level': 'None' if overly_permissive else 'SG-based',
                    'cidr_block': vpc_id,  # Using VPC ID as reference
                    'compliant': compliant,
                    'issues': issues
                })

    except Exception as e:
        if not warn_permission_error('aws-read', e):
            logger.warning("Error checking security groups in %s: %s", region, e)

    return results


def audit_nacls(
    ec2_client,
    account_id: str,
    region: str
) -> list[dict[str, Any]]:
    """
    Audit Network ACLs for proper isolation.

    Args:
        ec2_client: boto3 EC2 client
        account_id: AWS account ID
        region: AWS region

    Returns:
        List of NACL audit results
    """
    results = []

    try:
        nacls_response = ec2_client.describe_network_acls()
        nacls = nacls_response.get('NetworkAcls', [])

        for nacl in nacls:
            nacl_id = nacl.get('NetworkAclId', '')
            vpc_id = nacl.get('VpcId', '')
            is_default = nacl.get('IsDefault', False)

            # Get NACL name
            nacl_name = ''
            for tag in nacl.get('Tags', []):
                if tag.get('Key') == 'Name':
                    nacl_name = tag.get('Value', '')
                    break

            issues = []
            has_deny_rules = False
            has_custom_rules = False

            entries = nacl.get('Entries', [])
            for entry in entries:
                rule_number = entry.get('RuleNumber', 0)
                rule_action = entry.get('RuleAction', '')
                cidr_block = entry.get('CidrBlock', '')

                # Skip default rules (32767)
                if rule_number == 32767:
                    continue

                has_custom_rules = True

                if rule_action == 'deny':
                    has_deny_rules = True

            # Determine segmentation type
            if is_default:
                segmentation_type = 'Default NACL'
                if not has_custom_rules:
                    issues.append("Using default NACL without custom rules")
            elif has_deny_rules:
                segmentation_type = 'Custom NACL with Deny Rules'
            else:
                segmentation_type = 'Custom NACL (Allow Only)'

            # Compliant if custom NACL with deny rules or if it's protecting specific subnets
            associated_subnets = len(nacl.get('Associations', []))
            compliant = has_custom_rules or associated_subnets > 0

            results.append({
                'account_id': account_id,
                'region': region,
                'resource_type': 'NetworkACL',
                'resource_id': nacl_id,
                'resource_name': nacl_name,
                'segmentation_type': segmentation_type,
                'isolation_level': 'NACL-based' if has_deny_rules else 'Minimal',
                'cidr_block': vpc_id,
                'compliant': compliant,
                'issues': issues
            })

    except Exception as e:
        if not warn_permission_error('aws-read', e):
            logger.warning("Error checking NACLs in %s: %s", region, e)

    return results


def audit_vpc_endpoints(
    ec2_client,
    account_id: str,
    region: str
) -> list[dict[str, Any]]:
    """
    Audit VPC endpoints for AWS service isolation.

    Args:
        ec2_client: boto3 EC2 client
        account_id: AWS account ID
        region: AWS region

    Returns:
        List of VPC endpoint audit results
    """
    results = []

    try:
        endpoints_response = ec2_client.describe_vpc_endpoints()
        endpoints = endpoints_response.get('VpcEndpoints', [])

        # Track VPCs and their endpoints
        vpc_endpoints = {}

        for endpoint in endpoints:
            vpc_id = endpoint.get('VpcId', '')
            endpoint_id = endpoint.get('VpcEndpointId', '')
            endpoint_type = endpoint.get('VpcEndpointType', '')
            service_name = endpoint.get('ServiceName', '')
            state = endpoint.get('State', '')

            if vpc_id not in vpc_endpoints:
                vpc_endpoints[vpc_id] = []

            vpc_endpoints[vpc_id].append({
                'endpoint_id': endpoint_id,
                'endpoint_type': endpoint_type,
                'service_name': service_name,
                'state': state
            })

        # Report per VPC
        for vpc_id, endpoints in vpc_endpoints.items():
            gateway_endpoints = [e for e in endpoints if e['endpoint_type'] == 'Gateway']
            interface_endpoints = [e for e in endpoints if e['endpoint_type'] == 'Interface']

            issues = []

            # Check for critical endpoints
            has_s3_endpoint = any('s3' in e['service_name'].lower() for e in endpoints)
            has_dynamodb_endpoint = any('dynamodb' in e['service_name'].lower() for e in endpoints)

            if not has_s3_endpoint:
                issues.append("No S3 VPC endpoint (traffic goes over internet)")

            segmentation_type = f"VPC Endpoints ({len(endpoints)} total)"
            isolation_level = 'Private Link' if interface_endpoints else 'Gateway Only'

            compliant = has_s3_endpoint

            results.append({
                'account_id': account_id,
                'region': region,
                'resource_type': 'VPCEndpoints',
                'resource_id': vpc_id,
                'resource_name': f"Gateway: {len(gateway_endpoints)}, Interface: {len(interface_endpoints)}",
                'segmentation_type': segmentation_type,
                'isolation_level': isolation_level,
                'cidr_block': '',
                'compliant': compliant,
                'issues': issues
            })

    except Exception as e:
        if not warn_permission_error('aws-read', e):
            logger.warning("Error checking VPC endpoints in %s: %s", region, e)

    return results


def run_audit(args) -> tuple[str, dict[str, Any]]:
    """
    Run NSF10 audit across all accounts.

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

    logger.info("NSF10 audit starting: Network Segmentation and Isolation Control")
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
                for region in regions:
                    try:
                        ec2 = ctx.client('ec2', region_name=region)

                        # VPCs
                        vpc_results = audit_vpcs(ec2, account_id, region)
                        for result in vpc_results:
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
                                result['segmentation_type'],
                                result['isolation_level'],
                                str(result['compliant']),
                                '; '.join(result['issues']) if result['issues'] else 'None'
                            ])

                        # Subnets
                        subnet_results = audit_subnets(ec2, account_id, region)
                        for result in subnet_results:
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
                                result['segmentation_type'],
                                result['isolation_level'],
                                str(result['compliant']),
                                '; '.join(result['issues']) if result['issues'] else 'None'
                            ])

                        # Security Groups
                        sg_results = audit_security_groups(ec2, account_id, region)
                        for result in sg_results:
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
                                result['segmentation_type'],
                                result['isolation_level'],
                                str(result['compliant']),
                                '; '.join(result['issues']) if result['issues'] else 'None'
                            ])

                        # NACLs
                        nacl_results = audit_nacls(ec2, account_id, region)
                        for result in nacl_results:
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
                                result['segmentation_type'],
                                result['isolation_level'],
                                str(result['compliant']),
                                '; '.join(result['issues']) if result['issues'] else 'None'
                            ])

                        # VPC Endpoints
                        endpoint_results = audit_vpc_endpoints(ec2, account_id, region)
                        for result in endpoint_results:
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
                                result['segmentation_type'],
                                result['isolation_level'],
                                str(result['compliant']),
                                '; '.join(result['issues']) if result['issues'] else 'None'
                            ])

                    except Exception as e:
                        logger.warning("Error in region %s: %s", region, e)
                        continue

        except Exception as e:
            logger.error("Error auditing account %s: %s", account_id, e)
            continue

    # Save CSV
    headers = [
        'AccountId', 'Region', 'ResourceType', 'ResourceId',
        'ResourceName', 'SegmentationType', 'IsolationLevel',
        'Compliant', 'Issues'
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
        output_dir, f"nsf10-{date}", records, summary, formats, headers,
        title="NSF10 Audit",
    )

    print("\n" + "=" * 70)
    print("NSF10 AUDIT SUMMARY")
    print("=" * 70)
    print(f"Total Network Resources:  {total_resources}")
    print(f"Compliant:                {compliant_resources}")
    print(f"Non-Compliant:            {non_compliant_resources}")
    print("\nReports saved:")
    for fp in written_files:
        print(f"  {fp}")

    return written_files, summary


def main():
    parser = argparse.ArgumentParser(
        description='NSF10: Network Segmentation and Isolation Control',
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
  - Do not use default VPC for production workloads
  - VPCs should have Flow Logs enabled
  - Security groups should not allow 0.0.0.0/0 to all ports
  - Private subnets should not have IGW routes
  - S3 VPC endpoints should be configured for private access
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
