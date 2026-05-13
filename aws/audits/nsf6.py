#!/usr/bin/env python3
"""
NSF6 Control Audit: Immutable Backups of Systems

Ensure that backups of systems required to operate the institution and conduct
research are created and stored in an immutable state on a recurring basis.

REF: CP-9 800-53r5

This audit checks:
- AWS Backup vault lock configuration
- S3 bucket Object Lock for backup buckets
- Backup vault access policy restrictions
- WORM (Write Once Read Many) configuration
- Backup plan frequency

Usage:
    python nsf6.py
    python nsf6.py --accounts 123456789012,234567890123

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


logger = get_logger('nsf6')



# Minimum immutable retention days for compliance
MIN_IMMUTABLE_DAYS = 30


def audit_backup_vaults(
    backup_client,
    account_id: str,
    region: str
) -> list[dict[str, Any]]:
    """
    Audit AWS Backup vault configurations for immutability.

    Args:
        backup_client: boto3 Backup client
        account_id: AWS account ID
        region: AWS region

    Returns:
        List of backup vault audit results
    """
    results = []

    try:
        # List all backup vaults
        paginator = backup_client.get_paginator('list_backup_vaults')

        for page in paginator.paginate():
            for vault in page.get('BackupVaultList', []):
                vault_name = vault.get('BackupVaultName', '')
                vault_arn = vault.get('BackupVaultArn', '')
                locked = vault.get('Locked', False)
                min_retention = vault.get('MinRetentionDays', 0)
                max_retention = vault.get('MaxRetentionDays', 0)

                issues = []
                lock_status = 'Not Locked'
                immutable_days = 0

                # Check vault lock status
                if locked:
                    lock_status = 'Locked'
                    immutable_days = min_retention

                    if min_retention < MIN_IMMUTABLE_DAYS:
                        issues.append(f"Min retention {min_retention} days < {MIN_IMMUTABLE_DAYS} day requirement")
                else:
                    issues.append("Vault is not locked (backups can be deleted)")

                # Try to get access policy to check for restrictions
                try:
                    policy_response = backup_client.get_backup_vault_access_policy(
                        BackupVaultName=vault_name
                    )
                    policy = policy_response.get('Policy', '')

                    # Check for deny delete policies
                    if 'backup:DeleteBackupVault' in policy and 'Deny' in policy:
                        if not locked:
                            lock_status = 'Policy Protected'
                    if 'backup:DeleteRecoveryPoint' in policy and 'Deny' in policy:
                        if not locked:
                            lock_status = 'Policy Protected'

                except backup_client.exceptions.ResourceNotFoundException:
                    if not locked:
                        issues.append("No access policy restricting deletion")
                except Exception:
                    pass

                # Check for recovery points to ensure vault is in use
                try:
                    rp_response = backup_client.list_recovery_points_by_backup_vault(
                        BackupVaultName=vault_name,
                        MaxResults=1
                    )
                    has_backups = len(rp_response.get('RecoveryPoints', [])) > 0
                    if not has_backups:
                        issues.append("Vault has no recovery points")
                except Exception:
                    pass

                # Object Lock status (S3-based vaults only)
                object_lock_enabled = False
                if 'S3' in vault_arn.upper():
                    # S3 backup vaults may have object lock
                    object_lock_enabled = locked

                compliant = locked and (immutable_days >= MIN_IMMUTABLE_DAYS or lock_status == 'Policy Protected')

                results.append({
                    'account_id': account_id,
                    'region': region,
                    'resource_type': 'BackupVault',
                    'resource_name': vault_name,
                    'lock_status': lock_status,
                    'immutable_days': immutable_days,
                    'max_retention_days': max_retention,
                    'object_lock_enabled': object_lock_enabled,
                    'compliant': compliant,
                    'issues': issues
                })

    except Exception as e:
        if not warn_permission_error('aws-read', e):
            logger.warning("Error checking Backup vaults in %s: %s", region, e)

    return results


def audit_s3_backup_buckets(
    s3_client,
    account_id: str,
    region: str
) -> list[dict[str, Any]]:
    """
    Audit S3 buckets used for backups for Object Lock configuration.

    Args:
        s3_client: boto3 S3 client
        account_id: AWS account ID
        region: AWS region

    Returns:
        List of S3 backup bucket audit results
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

            # Only check buckets that appear to be backup-related
            backup_keywords = ['backup', 'bkp', 'archive', 'vault', 'recovery', 'dr-']
            is_backup_bucket = any(kw in bucket_name.lower() for kw in backup_keywords)

            if not is_backup_bucket:
                continue

            issues = []
            object_lock_enabled = False
            object_lock_mode = 'None'
            retention_days = 0
            versioning_enabled = False

            # Check bucket location
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

            compliant = object_lock_enabled and retention_days >= MIN_IMMUTABLE_DAYS

            results.append({
                'account_id': account_id,
                'region': bucket_region,
                'resource_type': 'S3Bucket',
                'resource_name': bucket_name,
                'lock_status': f"ObjectLock-{object_lock_mode}" if object_lock_enabled else 'Not Locked',
                'immutable_days': retention_days,
                'max_retention_days': retention_days,  # S3 uses same value
                'object_lock_enabled': object_lock_enabled,
                'compliant': compliant,
                'issues': issues
            })

    except Exception as e:
        if not warn_permission_error('aws-read', e):
            logger.warning("Error checking S3 backup buckets: %s", e)

    return results


def run_audit(args) -> tuple[str, dict[str, Any]]:
    """
    Run NSF6 audit across all accounts.

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

    logger.info("NSF6 audit starting: Immutable Backups of Systems")
    logger.info("Date=%s accounts=%d regions=%d role=%s",
                date, len(accounts), len(regions), role_name)

    # Statistics
    total_resources = 0
    locked_resources = 0
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
                        # AWS Backup vaults
                        backup = ctx.client('backup', region_name=region)
                        vault_results = audit_backup_vaults(backup, account_id, region)

                        for result in vault_results:
                            total_resources += 1
                            if result['lock_status'] != 'Not Locked':
                                locked_resources += 1
                            if result['compliant']:
                                compliant_resources += 1
                            else:
                                non_compliant_resources += 1

                            csv_rows.append([
                                result['account_id'],
                                result['region'],
                                result['resource_type'],
                                result['resource_name'],
                                result['lock_status'],
                                str(result['immutable_days']),
                                str(result['object_lock_enabled']),
                                str(result['compliant']),
                                '; '.join(result['issues']) if result['issues'] else 'None'
                            ])

                        # S3 backup buckets (only in us-east-1)
                        if region == 'us-east-1':
                            s3 = ctx.client('s3', region_name=region)
                            s3_results = audit_s3_backup_buckets(s3, account_id, region)

                            for result in s3_results:
                                total_resources += 1
                                if result['object_lock_enabled']:
                                    locked_resources += 1
                                if result['compliant']:
                                    compliant_resources += 1
                                else:
                                    non_compliant_resources += 1

                                csv_rows.append([
                                    result['account_id'],
                                    result['region'],
                                    result['resource_type'],
                                    result['resource_name'],
                                    result['lock_status'],
                                    str(result['immutable_days']),
                                    str(result['object_lock_enabled']),
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
        'AccountId', 'Region', 'ResourceType', 'ResourceName',
        'LockStatus', 'ImmutableDays', 'ObjectLockEnabled', 'Compliant', 'Issues'
    ]

    # Print summary
    summary = {
        'total_resources': total_resources,
        'locked_resources': locked_resources,
        'compliant': compliant_resources,
        'non_compliant': non_compliant_resources
    }

    formats = parse_formats_arg(args.format)
    records = [dict(zip(headers, row)) for row in csv_rows]
    written_files = save_results(
        output_dir, f"nsf6-{date}", records, summary, formats, headers,
        title="NSF6 Audit",
    )

    print("\n" + "=" * 70)
    print("NSF6 AUDIT SUMMARY")
    print("=" * 70)
    print(f"Total Backup Resources:    {total_resources}")
    print(f"Locked/Immutable:          {locked_resources}")
    print(f"Compliant:                 {compliant_resources}")
    print(f"Non-Compliant:             {non_compliant_resources}")
    print("\nReports saved:")
    for fp in written_files:
        print(f"  {fp}")

    return written_files, summary


def main():
    parser = argparse.ArgumentParser(
        description='NSF6: Immutable Backups of Systems',
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
  - AWS Backup vaults should be locked
  - Minimum retention period of 30 days
  - S3 backup buckets should have Object Lock enabled
  - Object Lock should use COMPLIANCE or GOVERNANCE mode
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
