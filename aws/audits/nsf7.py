#!/usr/bin/env python3
"""
NSF7 Control Audit: Immutable Backups of Research Data

Ensure that backups of essential research data are created and stored in an
immutable state on a recurring basis.

REF: CP-9 800-53r5

This audit checks:
- S3 buckets tagged as research data
- Object Lock configuration on research buckets
- Cross-region replication for research data
- Lifecycle policies preventing early deletion
- Versioning status

Usage:
    python nsf7.py
    python nsf7.py --accounts 123456789012,234567890123

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


logger = get_logger('nsf7')



# Minimum immutable retention days for compliance
MIN_IMMUTABLE_DAYS = 30

# Tags that identify research data buckets
RESEARCH_DATA_TAGS = [
    'research', 'data', 'scientific', 'dataset', 'experiment',
    'study', 'project', 'analysis', 'results', 'raw-data'
]

# Bucket name patterns that suggest research data
RESEARCH_BUCKET_PATTERNS = [
    'research', 'data', 'dataset', 'scientific', 'experiment',
    'study', 'project', 'results', 'raw', 'analysis'
]


def is_research_bucket(bucket_name: str, tags: dict) -> tuple[bool, str]:
    """
    Determine if a bucket is used for research data.

    Args:
        bucket_name: S3 bucket name
        tags: Dictionary of bucket tags

    Returns:
        Tuple of (is_research, reason)
    """
    # Check tags
    for key, value in tags.items():
        key_lower = key.lower()
        value_lower = value.lower() if value else ''

        # Check for explicit research tags
        if key_lower in ['purpose', 'type', 'category', 'classification']:
            for pattern in RESEARCH_DATA_TAGS:
                if pattern in value_lower:
                    return True, f"Tag {key}={value}"

        # Check for research-related tag keys
        for pattern in RESEARCH_DATA_TAGS:
            if pattern in key_lower:
                return True, f"Tag key contains '{pattern}'"

    # Check bucket name patterns
    bucket_lower = bucket_name.lower()
    for pattern in RESEARCH_BUCKET_PATTERNS:
        if pattern in bucket_lower:
            return True, f"Bucket name contains '{pattern}'"

    return False, ''


def audit_research_data_buckets(
    s3_client,
    account_id: str,
    region: str
) -> list[dict[str, Any]]:
    """
    Audit S3 buckets containing research data for immutability.

    Args:
        s3_client: boto3 S3 client
        account_id: AWS account ID
        region: AWS region

    Returns:
        List of research data bucket audit results
    """
    results = []

    # Only run in us-east-1 since S3 is global
    if region != 'us-east-1':
        return results

    try:
        # List buckets
        response = s3_client.list_buckets()
        buckets = response.get('Buckets', [])

        for bucket in buckets:
            bucket_name = bucket.get('Name', '')

            # Get bucket tags
            tags = {}
            try:
                tag_response = s3_client.get_bucket_tagging(Bucket=bucket_name)
                for tag in tag_response.get('TagSet', []):
                    tags[tag.get('Key', '')] = tag.get('Value', '')
            except s3_client.exceptions.ClientError:
                # No tags or access denied
                pass

            # Check if this is a research data bucket
            is_research, research_reason = is_research_bucket(bucket_name, tags)

            if not is_research:
                continue

            issues = []
            object_lock_enabled = False
            object_lock_mode = 'None'
            retention_days = 0
            versioning_enabled = False
            cross_region_replication = False

            # Get bucket location
            try:
                location = s3_client.get_bucket_location(Bucket=bucket_name)
                bucket_region = location.get('LocationConstraint') or 'us-east-1'
            except Exception:
                bucket_region = 'unknown'

            # Check versioning
            try:
                versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
                versioning_status = versioning.get('Status', 'Disabled')
                versioning_enabled = versioning_status == 'Enabled'
                if not versioning_enabled:
                    issues.append("Versioning not enabled")
            except Exception:
                issues.append("Could not check versioning")

            # Check Object Lock configuration
            try:
                lock_config = s3_client.get_object_lock_configuration(Bucket=bucket_name)
                ol_config = lock_config.get('ObjectLockConfiguration', {})
                object_lock_enabled = ol_config.get('ObjectLockEnabled') == 'Enabled'

                rule = ol_config.get('Rule', {})
                default_retention = rule.get('DefaultRetention', {})

                if default_retention:
                    object_lock_mode = default_retention.get('Mode', 'None')
                    retention_days = default_retention.get('Days', 0)
                    retention_years = default_retention.get('Years', 0)
                    if retention_years:
                        retention_days = retention_years * 365

                if object_lock_enabled and object_lock_mode not in ['GOVERNANCE', 'COMPLIANCE']:
                    issues.append("Object Lock enabled but no default retention mode")

                if retention_days < MIN_IMMUTABLE_DAYS:
                    issues.append(f"Retention {retention_days} days < {MIN_IMMUTABLE_DAYS} day requirement")

            except s3_client.exceptions.ClientError as e:
                if 'ObjectLockConfigurationNotFoundError' in str(e):
                    issues.append("Object Lock not configured")
                else:
                    issues.append("Could not check Object Lock configuration")
            except Exception:
                issues.append("Could not check Object Lock configuration")

            # Check cross-region replication
            try:
                replication = s3_client.get_bucket_replication(Bucket=bucket_name)
                rules = replication.get('ReplicationConfiguration', {}).get('Rules', [])
                if rules:
                    cross_region_replication = True
            except s3_client.exceptions.ClientError as e:
                if 'ReplicationConfigurationNotFoundError' not in str(e):
                    pass  # Replication not configured is OK
            except Exception:
                pass

            # Check lifecycle rules for deletion protection
            lifecycle_protection = False
            try:
                lifecycle = s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
                rules = lifecycle.get('Rules', [])

                for rule in rules:
                    if rule.get('Status') != 'Enabled':
                        continue

                    # Check for NoncurrentVersionExpiration
                    noncurrent_exp = rule.get('NoncurrentVersionExpiration', {})
                    noncurrent_days = noncurrent_exp.get('NoncurrentDays', 0)

                    if noncurrent_days >= MIN_IMMUTABLE_DAYS:
                        lifecycle_protection = True

            except s3_client.exceptions.ClientError:
                pass  # No lifecycle configuration
            except Exception:
                pass

            # Determine compliance
            # Compliant if Object Lock with adequate retention OR lifecycle protection
            immutable_backup = object_lock_enabled and retention_days >= MIN_IMMUTABLE_DAYS
            compliant = immutable_backup or (versioning_enabled and lifecycle_protection)

            if not immutable_backup and not lifecycle_protection:
                issues.append("No immutable backup protection")

            results.append({
                'account_id': account_id,
                'region': bucket_region,
                'bucket_name': bucket_name,
                'is_research_data': True,
                'research_indicator': research_reason,
                'immutable_backup': immutable_backup,
                'object_lock_mode': object_lock_mode,
                'retention_days': retention_days,
                'cross_region_replication': cross_region_replication,
                'versioning_enabled': versioning_enabled,
                'compliant': compliant,
                'issues': issues
            })

    except Exception as e:
        if not warn_permission_error('aws-read', e):
            logger.warning("Error checking research data buckets: %s", e)

    return results


def run_audit(args) -> tuple[str, dict[str, Any]]:
    """
    Run NSF7 audit across all accounts.

    Args:
        args: Parsed command line arguments

    Returns:
        Tuple of (output_file_path, summary_stats)
    """
    accounts = parse_accounts_arg(args.accounts)
    regions = parse_regions_arg(args.regions)
    if "us-east-1" not in regions:
        logger.warning(
            "S3 audit step is gated on us-east-1 (S3 is a global service); "
            "your --regions does not include it, so S3 buckets WILL NOT be inventoried. "
            "Add us-east-1 to --regions for full coverage."
        )
    output_dir = args.output_dir
    role_name = args.role
    date = current_date()

    logger.info("NSF7 audit starting: Immutable Backups of Research Data")
    logger.info("Date=%s accounts=%d regions=%d role=%s",
                date, len(accounts), len(regions), role_name)

    # Statistics
    total_buckets = 0
    with_immutable = 0
    with_replication = 0
    compliant_buckets = 0
    non_compliant_buckets = 0

    # CSV rows
    csv_rows = []

    for account_id in accounts:
        logger.info("Auditing account: %s", account_id)

        try:
            with AuditContext(account_id, role_name=role_name, profile=args.profile, external_id=args.external_id) as ctx:
                for region in regions:
                    try:
                        # S3 is global, only check in us-east-1
                        if region != 'us-east-1':
                            continue

                        s3 = ctx.client('s3', region_name=region)
                        results = audit_research_data_buckets(s3, account_id, region)

                        for result in results:
                            total_buckets += 1
                            if result['immutable_backup']:
                                with_immutable += 1
                            if result['cross_region_replication']:
                                with_replication += 1
                            if result['compliant']:
                                compliant_buckets += 1
                            else:
                                non_compliant_buckets += 1

                            csv_rows.append([
                                result['account_id'],
                                result['region'],
                                result['bucket_name'],
                                str(result['is_research_data']),
                                result['research_indicator'],
                                str(result['immutable_backup']),
                                result['object_lock_mode'],
                                str(result['retention_days']),
                                str(result['cross_region_replication']),
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
        'AccountId', 'Region', 'BucketName', 'IsResearchData',
        'ResearchIndicator', 'ImmutableBackup', 'ObjectLockMode',
        'RetentionDays', 'CrossRegionReplication', 'Compliant', 'Issues'
    ]

    # Print summary
    summary = {
        'total_buckets': total_buckets,
        'with_immutable': with_immutable,
        'with_replication': with_replication,
        'compliant': compliant_buckets,
        'non_compliant': non_compliant_buckets
    }

    formats = parse_formats_arg(args.format)
    records = [dict(zip(headers, row)) for row in csv_rows]
    written_files = save_results(
        output_dir, f"nsf7-{date}", records, summary, formats, headers,
        title="NSF7 Audit",
    )

    print("\n" + "=" * 70)
    print("NSF7 AUDIT SUMMARY")
    print("=" * 70)
    print(f"Research Data Buckets Found:  {total_buckets}")
    print(f"With Immutable Backup:        {with_immutable}")
    print(f"With Cross-Region Replication:{with_replication}")
    print(f"Compliant:                    {compliant_buckets}")
    print(f"Non-Compliant:                {non_compliant_buckets}")
    print("\nReports saved:")
    for fp in written_files:
        print(f"  {fp}")

    return written_files, summary


def main():
    parser = argparse.ArgumentParser(
        description='NSF7: Immutable Backups of Research Data',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Audit all accounts
  %(prog)s

  # Audit specific accounts
  %(prog)s --accounts 123456789012,234567890123

Compliance Criteria:
  - Research data buckets should have Object Lock enabled
  - Object Lock should use COMPLIANCE or GOVERNANCE mode
  - Minimum retention period of 30 days
  - Versioning should be enabled
  - Cross-region replication recommended but not required

Detection Method:
  - Buckets tagged with research-related tags
  - Buckets with names containing research-related keywords
        """
    )

    add_common_arguments(parser)

    args = parser.parse_args()
    configure_logging(verbose=args.verbose, quiet=args.quiet, log_file=args.log_file)

    try:
        written_files, summary = run_audit(args)


        # Return non-zero if there are non-compliant buckets
        return 1 if summary['non_compliant'] > 0 or permission_failure_count() > 0 else 0

    except KeyboardInterrupt:
        logger.error("Interrupted by user")
        return 130
    except Exception as e:
        logger.error("Audit error: %s", e)
        return 1


if __name__ == '__main__':
    sys.exit(main())
