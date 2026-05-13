#!/usr/bin/env python3
"""
NSF9 Control Audit: Collect and Monitor System Logs

Collect and monitor logs from all systems required to operate the institution
and conduct research.

REF: AU-2, AU-6, SI-4 800-53r5

This audit checks:
- CloudTrail enabled in all regions
- CloudTrail multi-region configuration
- CloudWatch Logs integration
- VPC Flow Logs enabled
- S3 access logging
- Log retention policies (minimum 1 year)
- Centralized logging configuration

Usage:
    python nsf9.py
    python nsf9.py --accounts 123456789012,234567890123

Prerequisites:
    pip install -r requirements.txt
"""

import sys
from pathlib import Path

# Add parent directory to path for imports when running directly
sys.path.insert(0, str(Path(__file__).parent.parent))

import argparse
import logging
import sys
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


logger = get_logger('nsf9')



# Minimum log retention in days (1 year = 365 days)
MIN_RETENTION_DAYS = 365


def audit_cloudtrail(
    cloudtrail_client,
    account_id: str,
    region: str
) -> list[dict[str, Any]]:
    """
    Audit CloudTrail configuration.

    Args:
        cloudtrail_client: boto3 CloudTrail client
        account_id: AWS account ID
        region: AWS region

    Returns:
        List of CloudTrail audit results
    """
    results = []

    try:
        trails_response = cloudtrail_client.describe_trails()
        trails = trails_response.get('trailList', [])

        if not trails:
            results.append({
                'account_id': account_id,
                'region': region,
                'log_type': 'CloudTrail',
                'resource_id': 'N/A',
                'enabled': False,
                'centralized': False,
                'retention_days': 0,
                'compliant': False,
                'issues': ['No CloudTrail trails configured']
            })
            return results

        for trail in trails:
            trail_name = trail.get('Name', '')
            trail_arn = trail.get('TrailARN', '')
            is_multi_region = trail.get('IsMultiRegionTrail', False)
            is_org_trail = trail.get('IsOrganizationTrail', False)
            s3_bucket = trail.get('S3BucketName', '')
            log_group_arn = trail.get('CloudWatchLogsLogGroupArn', '')
            home_region = trail.get('HomeRegion', region)

            # Only process trails in their home region to avoid duplicates
            if home_region != region and is_multi_region:
                continue

            issues = []

            # Get trail status
            try:
                status = cloudtrail_client.get_trail_status(Name=trail_arn)
                is_logging = status.get('IsLogging', False)
            except Exception:
                is_logging = False

            if not is_logging:
                issues.append("Trail is not logging")

            if not is_multi_region:
                issues.append("Not multi-region trail")

            # Check CloudWatch Logs integration
            has_cloudwatch = bool(log_group_arn)
            if not has_cloudwatch:
                issues.append("Not integrated with CloudWatch Logs")

            # Check for centralization (org trail or cross-account)
            is_centralized = is_org_trail or is_multi_region

            # Determine compliance
            compliant = is_logging and is_multi_region

            results.append({
                'account_id': account_id,
                'region': region,
                'log_type': 'CloudTrail',
                'resource_id': trail_name,
                'enabled': is_logging,
                'centralized': is_centralized,
                'retention_days': 'S3' if s3_bucket else 0,  # S3 handles retention
                'compliant': compliant,
                'issues': issues
            })

    except Exception as e:
        if not warn_permission_error('aws-read', e):
            logger.warning("Error checking CloudTrail in {region}: %s", e)

    return results


def audit_cloudwatch_log_groups(
    logs_client,
    account_id: str,
    region: str
) -> list[dict[str, Any]]:
    """
    Audit CloudWatch Log Groups retention policies.

    Args:
        logs_client: boto3 CloudWatch Logs client
        account_id: AWS account ID
        region: AWS region

    Returns:
        List of log group audit results
    """
    results = []

    # Only check for critical log groups
    critical_patterns = [
        '/aws/cloudtrail',
        '/aws/vpc-flow-logs',
        '/aws/lambda',
        '/aws/rds',
        '/aws/eks',
        'security',
        'audit',
        'access'
    ]

    try:
        paginator = logs_client.get_paginator('describe_log_groups')

        for page in paginator.paginate():
            for log_group in page.get('logGroups', []):
                log_group_name = log_group.get('logGroupName', '')
                retention_days = log_group.get('retentionInDays')  # None means never expire

                # Check if this is a critical log group
                is_critical = any(pattern in log_group_name.lower() for pattern in critical_patterns)

                if not is_critical:
                    continue

                issues = []

                # Check retention
                if retention_days is None:
                    retention_status = 'Never Expire'
                    retention_compliant = True
                elif retention_days >= MIN_RETENTION_DAYS:
                    retention_status = f'{retention_days} days'
                    retention_compliant = True
                else:
                    retention_status = f'{retention_days} days'
                    retention_compliant = False
                    issues.append(f"Retention {retention_days} days < {MIN_RETENTION_DAYS} day requirement")

                results.append({
                    'account_id': account_id,
                    'region': region,
                    'log_type': 'CloudWatchLogGroup',
                    'resource_id': log_group_name,
                    'enabled': True,
                    'centralized': False,  # Individual log groups aren't centralized
                    'retention_days': retention_days if retention_days else 'Never',
                    'compliant': retention_compliant,
                    'issues': issues
                })

    except Exception as e:
        if not warn_permission_error('aws-read', e):
            logger.warning("Error checking CloudWatch Log Groups in {region}: %s", e)

    return results


def audit_vpc_flow_logs(
    ec2_client,
    account_id: str,
    region: str
) -> list[dict[str, Any]]:
    """
    Audit VPC Flow Logs configuration.

    Args:
        ec2_client: boto3 EC2 client
        account_id: AWS account ID
        region: AWS region

    Returns:
        List of VPC Flow Logs audit results
    """
    results = []

    try:
        # Get all VPCs
        vpcs_response = ec2_client.describe_vpcs()
        vpcs = vpcs_response.get('Vpcs', [])

        # Get all flow logs
        flow_logs_response = ec2_client.describe_flow_logs()
        flow_logs = flow_logs_response.get('FlowLogs', [])

        # Map flow logs to VPCs
        vpc_flow_logs = {}
        for fl in flow_logs:
            resource_id = fl.get('ResourceId', '')
            if resource_id.startswith('vpc-'):
                vpc_flow_logs[resource_id] = fl

        for vpc in vpcs:
            vpc_id = vpc.get('VpcId', '')
            is_default = vpc.get('IsDefault', False)

            # Get VPC name
            vpc_name = ''
            for tag in vpc.get('Tags', []):
                if tag.get('Key') == 'Name':
                    vpc_name = tag.get('Value', '')
                    break

            issues = []
            flow_log = vpc_flow_logs.get(vpc_id)

            if flow_log:
                fl_status = flow_log.get('FlowLogStatus', '')
                log_destination = flow_log.get('LogDestination', '')
                traffic_type = flow_log.get('TrafficType', '')

                enabled = fl_status == 'ACTIVE'

                if not enabled:
                    issues.append("Flow log is not active")

                if traffic_type != 'ALL':
                    issues.append(f"Only logging {traffic_type} traffic, not ALL")

                # Check destination for centralization
                centralized = 's3://' in log_destination or 'log-group' in log_destination

                compliant = enabled and traffic_type == 'ALL'

                results.append({
                    'account_id': account_id,
                    'region': region,
                    'log_type': 'VPCFlowLog',
                    'resource_id': f"{vpc_id} ({vpc_name})" if vpc_name else vpc_id,
                    'enabled': enabled,
                    'centralized': centralized,
                    'retention_days': 'Destination-dependent',
                    'compliant': compliant,
                    'issues': issues
                })
            else:
                issues.append("No VPC Flow Logs configured")
                results.append({
                    'account_id': account_id,
                    'region': region,
                    'log_type': 'VPCFlowLog',
                    'resource_id': f"{vpc_id} ({vpc_name})" if vpc_name else vpc_id,
                    'enabled': False,
                    'centralized': False,
                    'retention_days': 0,
                    'compliant': False,
                    'issues': issues
                })

    except Exception as e:
        if not warn_permission_error('aws-read', e):
            logger.warning("Error checking VPC Flow Logs in {region}: %s", e)

    return results


def audit_s3_access_logging(
    s3_client,
    account_id: str,
    region: str
) -> list[dict[str, Any]]:
    """
    Audit S3 bucket access logging configuration.

    Args:
        s3_client: boto3 S3 client
        account_id: AWS account ID
        region: AWS region

    Returns:
        List of S3 access logging audit results
    """
    results = []

    # Only run in us-east-1 since S3 is global
    if region != 'us-east-1':
        return results

    try:
        response = s3_client.list_buckets()
        buckets = response.get('Buckets', [])

        # Track buckets for summary
        buckets_with_logging = 0
        buckets_without_logging = 0

        for bucket in buckets:
            bucket_name = bucket.get('Name', '')

            try:
                logging_response = s3_client.get_bucket_logging(Bucket=bucket_name)
                logging_config = logging_response.get('LoggingEnabled')

                if logging_config:
                    buckets_with_logging += 1
                else:
                    buckets_without_logging += 1

            except Exception:
                buckets_without_logging += 1

        # Summary result
        total_buckets = buckets_with_logging + buckets_without_logging
        logging_percentage = round((buckets_with_logging / total_buckets * 100), 1) if total_buckets > 0 else 0

        issues = []
        if logging_percentage < 80:
            issues.append(f"Only {logging_percentage}% of buckets have access logging")

        results.append({
            'account_id': account_id,
            'region': 'global',
            'log_type': 'S3AccessLogging',
            'resource_id': f"{buckets_with_logging}/{total_buckets} buckets",
            'enabled': logging_percentage > 50,
            'centralized': False,
            'retention_days': 'Bucket-dependent',
            'compliant': logging_percentage >= 80,
            'issues': issues
        })

    except Exception as e:
        if not warn_permission_error('aws-read', e):
            logger.warning("Error checking S3 access logging: %s", e)

    return results


def run_audit(args) -> tuple[str, dict[str, Any]]:
    """
    Run NSF9 audit across all accounts.

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

    logger.info("NSF9 audit starting: Collect and Monitor System Logs")
    logger.info("Date=%s accounts=%d regions=%d role=%s",
                date, len(accounts), len(regions), role_name)

    # Statistics
    total_log_sources = 0
    enabled_sources = 0
    compliant_sources = 0
    non_compliant_sources = 0

    # CSV rows
    csv_rows = []

    for account_id in accounts:
        logger.info("Auditing account: %s", account_id)

        try:
            with AuditContext(account_id, role_name=role_name, profile=args.profile, external_id=args.external_id) as ctx:
                for region in regions:
                    try:
                        # CloudTrail
                        cloudtrail = ctx.client('cloudtrail', region_name=region)
                        ct_results = audit_cloudtrail(cloudtrail, account_id, region)

                        for result in ct_results:
                            total_log_sources += 1
                            if result['enabled']:
                                enabled_sources += 1
                            if result['compliant']:
                                compliant_sources += 1
                            else:
                                non_compliant_sources += 1

                            csv_rows.append([
                                result['account_id'],
                                result['region'],
                                result['log_type'],
                                result['resource_id'],
                                str(result['enabled']),
                                str(result['centralized']),
                                str(result['retention_days']),
                                str(result['compliant']),
                                '; '.join(result['issues']) if result['issues'] else 'None'
                            ])

                        # CloudWatch Log Groups
                        logs = ctx.client('logs', region_name=region)
                        cw_results = audit_cloudwatch_log_groups(logs, account_id, region)

                        for result in cw_results:
                            total_log_sources += 1
                            if result['enabled']:
                                enabled_sources += 1
                            if result['compliant']:
                                compliant_sources += 1
                            else:
                                non_compliant_sources += 1

                            csv_rows.append([
                                result['account_id'],
                                result['region'],
                                result['log_type'],
                                result['resource_id'],
                                str(result['enabled']),
                                str(result['centralized']),
                                str(result['retention_days']),
                                str(result['compliant']),
                                '; '.join(result['issues']) if result['issues'] else 'None'
                            ])

                        # VPC Flow Logs
                        ec2 = ctx.client('ec2', region_name=region)
                        vpc_results = audit_vpc_flow_logs(ec2, account_id, region)

                        for result in vpc_results:
                            total_log_sources += 1
                            if result['enabled']:
                                enabled_sources += 1
                            if result['compliant']:
                                compliant_sources += 1
                            else:
                                non_compliant_sources += 1

                            csv_rows.append([
                                result['account_id'],
                                result['region'],
                                result['log_type'],
                                result['resource_id'],
                                str(result['enabled']),
                                str(result['centralized']),
                                str(result['retention_days']),
                                str(result['compliant']),
                                '; '.join(result['issues']) if result['issues'] else 'None'
                            ])

                        # S3 Access Logging (only in us-east-1)
                        if region == 'us-east-1':
                            s3 = ctx.client('s3', region_name=region)
                            s3_results = audit_s3_access_logging(s3, account_id, region)

                            for result in s3_results:
                                total_log_sources += 1
                                if result['enabled']:
                                    enabled_sources += 1
                                if result['compliant']:
                                    compliant_sources += 1
                                else:
                                    non_compliant_sources += 1

                                csv_rows.append([
                                    result['account_id'],
                                    result['region'],
                                    result['log_type'],
                                    result['resource_id'],
                                    str(result['enabled']),
                                    str(result['centralized']),
                                    str(result['retention_days']),
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
        'AccountId', 'Region', 'LogType', 'ResourceId',
        'Enabled', 'Centralized', 'RetentionDays', 'Compliant', 'Issues'
    ]

    # Print summary
    summary = {
        'total_log_sources': total_log_sources,
        'enabled_sources': enabled_sources,
        'compliant': compliant_sources,
        'non_compliant': non_compliant_sources
    }

    formats = parse_formats_arg(args.format)
    records = [dict(zip(headers, row)) for row in csv_rows]
    written_files = save_results(
        output_dir, f"nsf9-{date}", records, summary, formats, headers,
        title="NSF9 Audit",
    )

    print("\n" + "=" * 70)
    print("NSF9 AUDIT SUMMARY")
    print("=" * 70)
    print(f"Total Log Sources:    {total_log_sources}")
    print(f"Enabled Sources:      {enabled_sources}")
    print(f"Compliant:            {compliant_sources}")
    print(f"Non-Compliant:        {non_compliant_sources}")
    print("\nReports saved:")
    for fp in written_files:
        print(f"  {fp}")

    return written_files, summary


def main():
    parser = argparse.ArgumentParser(
        description='NSF9: Collect and Monitor System Logs',
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
  - CloudTrail should be enabled and logging in all regions
  - CloudTrail should be multi-region
  - VPC Flow Logs should be enabled for all VPCs
  - CloudWatch Log Groups should have >= 365 day retention
  - S3 access logging should be enabled for >= 80%% of buckets
        """
    )

    add_common_arguments(parser)

    args = parser.parse_args()
    configure_logging(verbose=args.verbose, quiet=args.quiet, log_file=args.log_file)

    try:
        written_files, summary = run_audit(args)


        # Return non-zero if there are non-compliant sources
        return 1 if summary['non_compliant'] > 0 or permission_failure_count() > 0 else 0

    except KeyboardInterrupt:
        logger.error("Interrupted by user")
        return 130
    except Exception as e:
        logger.error("Audit error: %s", e)
        return 1


if __name__ == '__main__':
    sys.exit(main())
