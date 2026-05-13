#!/usr/bin/env python3
"""
NSF8 Control Audit: Regular Tests of Backup Integrity

Conduct tests at least annually of the integrity and restoration of backups of
systems required to operate the organization.

REF: CP-9(1) 800-53r5

This audit checks:
- AWS Backup restore job history
- Last successful restore test date
- Restore test frequency (annual minimum)
- Restore job success rate
- RTO validation through restore times

Usage:
    python nsf8.py
    python nsf8.py --accounts 123456789012,234567890123

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
from datetime import datetime, timedelta, timezone
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


logger = get_logger('nsf8')



# Maximum days since last restore test for compliance (annual = 365 days)
MAX_DAYS_SINCE_RESTORE = 365


def audit_restore_jobs(
    backup_client,
    account_id: str,
    region: str
) -> list[dict[str, Any]]:
    """
    Audit AWS Backup restore job history per vault.

    Args:
        backup_client: boto3 Backup client
        account_id: AWS account ID
        region: AWS region

    Returns:
        List of restore job audit results by vault
    """
    results = []
    now = datetime.now(timezone.utc)
    one_year_ago = now - timedelta(days=365)

    # Track restore jobs per vault
    vault_restore_stats = {}

    try:
        # First, get list of vaults
        vault_paginator = backup_client.get_paginator('list_backup_vaults')
        vaults = {}

        for page in vault_paginator.paginate():
            for vault in page.get('BackupVaultList', []):
                vault_name = vault.get('BackupVaultName', '')
                vaults[vault_name] = {
                    'vault_name': vault_name,
                    'vault_arn': vault.get('BackupVaultArn', ''),
                    'restore_jobs': [],
                    'last_restore_date': None,
                    'days_since_restore': None,
                    'success_count': 0,
                    'failed_count': 0,
                    'total_restore_time_seconds': 0
                }

        # Get restore jobs
        paginator = backup_client.get_paginator('list_restore_jobs')

        for page in paginator.paginate():
            for job in page.get('RestoreJobs', []):
                restore_job_id = job.get('RestoreJobId', '')
                status = job.get('Status', '')
                creation_date = job.get('CreationDate')
                completion_date = job.get('CompletionDate')
                recovery_point_arn = job.get('RecoveryPointArn', '')

                # Extract vault name from recovery point ARN
                # Format: arn:aws:backup:region:account:recovery-point:vault-name/recovery-point-id
                vault_name = 'Unknown'
                if recovery_point_arn:
                    try:
                        # Try to get vault name from describe
                        if ':recovery-point:' in recovery_point_arn:
                            parts = recovery_point_arn.split(':recovery-point:')
                            if len(parts) > 1:
                                vault_part = parts[1].split('/')[0]
                                vault_name = vault_part
                    except Exception:
                        pass

                # Initialize vault if not seen
                if vault_name not in vaults:
                    vaults[vault_name] = {
                        'vault_name': vault_name,
                        'vault_arn': '',
                        'restore_jobs': [],
                        'last_restore_date': None,
                        'days_since_restore': None,
                        'success_count': 0,
                        'failed_count': 0,
                        'total_restore_time_seconds': 0
                    }

                # Only count jobs from last year
                if creation_date and creation_date > one_year_ago:
                    vaults[vault_name]['restore_jobs'].append(job)

                    if status == 'COMPLETED':
                        vaults[vault_name]['success_count'] += 1

                        # Track last successful restore
                        if completion_date:
                            if vaults[vault_name]['last_restore_date'] is None:
                                vaults[vault_name]['last_restore_date'] = completion_date
                            elif completion_date > vaults[vault_name]['last_restore_date']:
                                vaults[vault_name]['last_restore_date'] = completion_date

                            # Calculate restore time
                            if creation_date and completion_date:
                                restore_time = (completion_date - creation_date).total_seconds()
                                vaults[vault_name]['total_restore_time_seconds'] += restore_time

                    elif status == 'FAILED':
                        vaults[vault_name]['failed_count'] += 1

        # Generate results per vault
        for vault_name, vault_data in vaults.items():
            issues = []

            # Calculate days since last restore
            if vault_data['last_restore_date']:
                days_since = (now - vault_data['last_restore_date']).days
                vault_data['days_since_restore'] = days_since
            else:
                vault_data['days_since_restore'] = None

            # Determine compliance
            total_jobs = vault_data['success_count'] + vault_data['failed_count']

            # Calculate success rate
            success_rate = 0
            if total_jobs > 0:
                success_rate = round((vault_data['success_count'] / total_jobs) * 100, 1)

            # Calculate average restore time
            avg_restore_time_minutes = 0
            if vault_data['success_count'] > 0:
                avg_restore_time_minutes = round(
                    vault_data['total_restore_time_seconds'] / vault_data['success_count'] / 60, 1
                )

            # Check compliance criteria
            has_annual_test = False
            if vault_data['days_since_restore'] is not None:
                has_annual_test = vault_data['days_since_restore'] <= MAX_DAYS_SINCE_RESTORE
                if not has_annual_test:
                    issues.append(f"Last restore test was {vault_data['days_since_restore']} days ago (>365)")
            else:
                issues.append("No restore tests found in the past year")

            if success_rate < 100 and total_jobs > 0:
                issues.append(f"Restore success rate is {success_rate}% (<100%)")

            compliant = has_annual_test and (success_rate >= 90 or total_jobs == 0)

            results.append({
                'account_id': account_id,
                'region': region,
                'vault_name': vault_name,
                'last_restore_date': vault_data['last_restore_date'].strftime('%Y-%m-%d') if vault_data['last_restore_date'] else 'Never',
                'days_since_restore': vault_data['days_since_restore'] if vault_data['days_since_restore'] is not None else 'N/A',
                'restore_tests_count': total_jobs,
                'success_count': vault_data['success_count'],
                'failed_count': vault_data['failed_count'],
                'success_rate': success_rate,
                'avg_restore_time_minutes': avg_restore_time_minutes,
                'annual_test_compliant': has_annual_test,
                'compliant': compliant,
                'issues': issues
            })

    except Exception as e:
        if not warn_permission_error('aws-read', e):
            logger.warning("Error checking restore jobs in {region}: %s", e)

    return results


def audit_backup_plans_for_restore_testing(
    backup_client,
    account_id: str,
    region: str
) -> list[dict[str, Any]]:
    """
    Check for backup plans that include restore testing.

    Args:
        backup_client: boto3 Backup client
        account_id: AWS account ID
        region: AWS region

    Returns:
        List of backup plan audit results
    """
    results = []

    try:
        paginator = backup_client.get_paginator('list_backup_plans')

        for page in paginator.paginate():
            for plan_meta in page.get('BackupPlansList', []):
                plan_id = plan_meta.get('BackupPlanId', '')
                plan_name = plan_meta.get('BackupPlanName', '')

                # Get plan details
                try:
                    plan_response = backup_client.get_backup_plan(BackupPlanId=plan_id)
                    plan = plan_response.get('BackupPlan', {})

                    rules = plan.get('Rules', [])
                    has_copy_action = False
                    has_lifecycle = False

                    for rule in rules:
                        # Check for copy actions (cross-region/account)
                        copy_actions = rule.get('CopyActions', [])
                        if copy_actions:
                            has_copy_action = True

                        # Check for lifecycle rules
                        lifecycle = rule.get('Lifecycle', {})
                        if lifecycle:
                            has_lifecycle = True

                    # A plan with good backup hygiene likely supports restore testing
                    issues = []
                    if not has_lifecycle:
                        issues.append("No lifecycle rules defined")

                    results.append({
                        'account_id': account_id,
                        'region': region,
                        'resource_type': 'BackupPlan',
                        'resource_name': plan_name,
                        'resource_id': plan_id,
                        'has_copy_action': has_copy_action,
                        'has_lifecycle': has_lifecycle,
                        'supports_restore_testing': True,  # All plans can be tested
                        'issues': issues
                    })

                except Exception as e:
                    if not warn_permission_error('aws-read', e):
                        logger.warning("Error getting backup plan {plan_id}: %s", e)

    except Exception as e:
        if not warn_permission_error('aws-read', e):
            logger.warning("Error listing backup plans in {region}: %s", e)

    return results


def run_audit(args) -> tuple[str, dict[str, Any]]:
    """
    Run NSF8 audit across all accounts.

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

    logger.info("NSF8 audit starting: Regular Tests of Backup Integrity")
    logger.info("Date=%s accounts=%d regions=%d role=%s",
                date, len(accounts), len(regions), role_name)

    # Statistics
    total_vaults = 0
    vaults_with_tests = 0
    compliant_vaults = 0
    non_compliant_vaults = 0

    # CSV rows
    csv_rows = []

    for account_id in accounts:
        logger.info("Auditing account: %s", account_id)

        try:
            with AuditContext(account_id, role_name=role_name, profile=args.profile, external_id=args.external_id) as ctx:
                for region in regions:
                    try:
                        backup = ctx.client('backup', region_name=region)

                        # Audit restore jobs by vault
                        results = audit_restore_jobs(backup, account_id, region)

                        for result in results:
                            total_vaults += 1
                            if result['restore_tests_count'] > 0:
                                vaults_with_tests += 1
                            if result['compliant']:
                                compliant_vaults += 1
                            else:
                                non_compliant_vaults += 1

                            csv_rows.append([
                                result['account_id'],
                                result['region'],
                                result['vault_name'],
                                result['last_restore_date'],
                                str(result['days_since_restore']),
                                str(result['restore_tests_count']),
                                str(result['success_count']),
                                str(result['failed_count']),
                                str(result['success_rate']),
                                str(result['avg_restore_time_minutes']),
                                str(result['annual_test_compliant']),
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
        'AccountId', 'Region', 'VaultName', 'LastRestoreTestDate',
        'DaysSinceTest', 'RestoreTestsCount', 'SuccessCount', 'FailedCount',
        'SuccessRate', 'AvgRestoreTimeMinutes', 'AnnualTestCompliant',
        'Compliant', 'Issues'
    ]

    # Print summary
    summary = {
        'total_vaults': total_vaults,
        'vaults_with_tests': vaults_with_tests,
        'compliant': compliant_vaults,
        'non_compliant': non_compliant_vaults
    }

    formats = parse_formats_arg(args.format)
    records = [dict(zip(headers, row)) for row in csv_rows]
    written_files = save_results(
        output_dir, f"nsf8-{date}", records, summary, formats, headers,
        title="NSF8 Audit",
    )

    print("\n" + "=" * 70)
    print("NSF8 AUDIT SUMMARY")
    print("=" * 70)
    print(f"Total Backup Vaults:        {total_vaults}")
    print(f"Vaults with Restore Tests:  {vaults_with_tests}")
    print(f"Compliant:                  {compliant_vaults}")
    print(f"Non-Compliant:              {non_compliant_vaults}")
    print("\nReports saved:")
    for fp in written_files:
        print(f"  {fp}")

    return written_files, summary


def main():
    parser = argparse.ArgumentParser(
        description='NSF8: Regular Tests of Backup Integrity',
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
  - At least one restore test per vault within the past 365 days
  - Restore success rate should be >= 90%%
  - Restore jobs should complete successfully

Note:
  This audit examines AWS Backup restore job history to verify
  that backup restoration tests are being performed regularly.
  Manual restore tests outside of AWS Backup are not tracked.
        """
    )

    add_common_arguments(parser)

    args = parser.parse_args()
    configure_logging(verbose=args.verbose, quiet=args.quiet, log_file=args.log_file)

    try:
        written_files, summary = run_audit(args)


        # Return non-zero if there are non-compliant vaults
        return 1 if summary['non_compliant'] > 0 or permission_failure_count() > 0 else 0

    except KeyboardInterrupt:
        logger.error("Interrupted by user")
        return 130
    except Exception as e:
        logger.error("Audit error: %s", e)
        return 1


if __name__ == '__main__':
    sys.exit(main())
