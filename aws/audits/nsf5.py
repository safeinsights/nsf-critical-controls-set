#!/usr/bin/env python3
"""
NSF5 Control Audit: Anti-malware Includes EDR Functionality

Ensure that anti-malware software includes endpoint detection and response (EDR)
capabilities.

REF: SI-3 800-53r5

This audit checks:
- GuardDuty Runtime Monitoring for EC2
- GuardDuty Runtime Monitoring for ECS
- GuardDuty Runtime Monitoring for EKS
- GuardDuty RDS Protection
- GuardDuty Lambda Protection
- Overall EDR coverage statistics

Usage:
    python nsf5.py
    python nsf5.py --accounts 123456789012,234567890123

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


logger = get_logger('nsf5')



# Regions where GuardDuty EDR should be enabled
CRITICAL_REGIONS = [
    'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
    'eu-west-1', 'eu-central-1'
]

# GuardDuty features that provide EDR functionality
EDR_FEATURES = [
    'RUNTIME_MONITORING',
    'EKS_RUNTIME_MONITORING',
    'ECS_FARGATE_AGENT_MANAGEMENT',
    'EC2_AGENT_MANAGEMENT',
    'RDS_LOGIN_EVENTS',
    'LAMBDA_NETWORK_LOGS',
    'EKS_AUDIT_LOGS',
]


def audit_guardduty_edr(
    guardduty_client,
    account_id: str,
    region: str
) -> list[dict[str, Any]]:
    """
    Audit GuardDuty EDR feature configuration.

    Args:
        guardduty_client: boto3 GuardDuty client
        account_id: AWS account ID
        region: AWS region

    Returns:
        List of EDR feature audit results
    """
    results = []

    try:
        # List detectors
        detectors_response = guardduty_client.list_detectors()
        detector_ids = detectors_response.get('DetectorIds', [])

        if not detector_ids:
            # No GuardDuty detector - all EDR features are missing
            is_critical = region in CRITICAL_REGIONS
            for feature_name in EDR_FEATURES:
                results.append({
                    'account_id': account_id,
                    'region': region,
                    'feature_name': feature_name,
                    'status': 'Not Available',
                    'additional_config': '',
                    'coverage_percent': 0,
                    'compliant': not is_critical,
                    'issues': ['GuardDuty not enabled'] if is_critical else ['GuardDuty not enabled (non-critical region)']
                })
            return results

        for detector_id in detector_ids:
            # Get detector details
            detector = guardduty_client.get_detector(DetectorId=detector_id)

            if detector.get('Status') != 'ENABLED':
                for feature_name in EDR_FEATURES:
                    results.append({
                        'account_id': account_id,
                        'region': region,
                        'feature_name': feature_name,
                        'status': 'Detector Disabled',
                        'additional_config': '',
                        'coverage_percent': 0,
                        'compliant': False,
                        'issues': ['GuardDuty detector is disabled']
                    })
                continue

            # Get features configuration
            features = detector.get('Features', [])
            feature_map = {}

            for feature in features:
                name = feature.get('Name', '')
                status = feature.get('Status', 'DISABLED')
                additional = feature.get('AdditionalConfiguration', [])
                feature_map[name] = {
                    'status': status,
                    'additional': additional
                }

            # Check each EDR feature
            for feature_name in EDR_FEATURES:
                feature_info = feature_map.get(feature_name, {})
                status = feature_info.get('status', 'NOT_CONFIGURED')
                additional = feature_info.get('additional', [])

                # Build additional config string
                additional_configs = []
                for config in additional:
                    config_name = config.get('Name', '')
                    config_status = config.get('Status', '')
                    if config_name and config_status:
                        additional_configs.append(f"{config_name}={config_status}")

                additional_config_str = ', '.join(additional_configs)

                issues = []
                is_enabled = status == 'ENABLED'

                if not is_enabled:
                    issues.append(f"{feature_name} is {status}")

                # Check for partially enabled configurations
                for config in additional:
                    if config.get('Status') != 'ENABLED':
                        issues.append(f"{config.get('Name', 'Unknown')} sub-feature is {config.get('Status', 'DISABLED')}")

                results.append({
                    'account_id': account_id,
                    'region': region,
                    'feature_name': feature_name,
                    'status': status,
                    'additional_config': additional_config_str,
                    'coverage_percent': 100 if is_enabled else 0,
                    'compliant': is_enabled,
                    'issues': issues
                })

            # Try to get coverage statistics
            try:
                coverage_stats = guardduty_client.get_coverage_statistics(
                    DetectorId=detector_id,
                    StatisticsType=['COUNT_BY_COVERAGE_STATUS']
                )

                counts = coverage_stats.get('CoverageStatistics', {}).get('CountByCoverageStatus', [])

                total_resources = 0
                covered_resources = 0

                for count in counts:
                    status = count.get('Status', '')
                    count_val = count.get('Count', 0)
                    total_resources += count_val
                    if status == 'HEALTHY':
                        covered_resources += count_val

                if total_resources > 0:
                    coverage_pct = round((covered_resources / total_resources) * 100, 1)

                    results.append({
                        'account_id': account_id,
                        'region': region,
                        'feature_name': 'OVERALL_COVERAGE',
                        'status': 'Enabled' if coverage_pct > 80 else 'Partial',
                        'additional_config': f"{covered_resources}/{total_resources} resources",
                        'coverage_percent': coverage_pct,
                        'compliant': coverage_pct >= 80,
                        'issues': [] if coverage_pct >= 80 else [f"Only {coverage_pct}% coverage"]
                    })

            except Exception:
                # Coverage statistics not available
                pass

    except guardduty_client.exceptions.BadRequestException:
        # GuardDuty not available in this region
        pass
    except Exception as e:
        if not warn_permission_error('aws-read', e):
            logger.warning("Error checking GuardDuty EDR in {region}: %s", e)

    return results


def run_audit(args) -> tuple[str, dict[str, Any]]:
    """
    Run NSF5 audit across all accounts.

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

    logger.info("NSF5 audit starting: Anti-malware Includes EDR Functionality")
    logger.info("Date=%s accounts=%d regions=%d role=%s",
                date, len(accounts), len(regions), role_name)

    # Statistics
    total_features = 0
    enabled_features = 0
    compliant_features = 0
    non_compliant_features = 0

    # CSV rows
    csv_rows = []

    for account_id in accounts:
        logger.info("Auditing account: %s", account_id)

        try:
            with AuditContext(account_id, role_name=role_name, profile=args.profile, external_id=args.external_id) as ctx:
                for region in regions:
                    try:
                        guardduty = ctx.client('guardduty', region_name=region)
                        results = audit_guardduty_edr(guardduty, account_id, region)

                        for result in results:
                            total_features += 1
                            if result['status'] == 'ENABLED' or result['status'] == 'Enabled':
                                enabled_features += 1
                            if result['compliant']:
                                compliant_features += 1
                            else:
                                non_compliant_features += 1

                            csv_rows.append([
                                result['account_id'],
                                result['region'],
                                result['feature_name'],
                                result['status'],
                                result['additional_config'],
                                str(result['coverage_percent']),
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
        'AccountId', 'Region', 'FeatureName', 'Status',
        'AdditionalConfig', 'CoveragePercent', 'Compliant', 'Issues'
    ]

    # Print summary
    summary = {
        'total_features': total_features,
        'enabled_features': enabled_features,
        'compliant': compliant_features,
        'non_compliant': non_compliant_features
    }

    formats = parse_formats_arg(args.format)
    records = [dict(zip(headers, row)) for row in csv_rows]
    written_files = save_results(
        output_dir, f"nsf5-{date}", records, summary, formats, headers,
        title="NSF5 Audit",
    )

    print("\n" + "=" * 70)
    print("NSF5 AUDIT SUMMARY")
    print("=" * 70)
    print(f"Total EDR Features Checked:  {total_features}")
    print(f"Enabled Features:            {enabled_features}")
    print(f"Compliant:                   {compliant_features}")
    print(f"Non-Compliant:               {non_compliant_features}")
    print("\nReports saved:")
    for fp in written_files:
        print(f"  {fp}")

    return written_files, summary


def main():
    parser = argparse.ArgumentParser(
        description='NSF5: Anti-malware Includes EDR Functionality',
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
  - GuardDuty Runtime Monitoring should be enabled
  - EKS Runtime Monitoring should be enabled for EKS clusters
  - ECS Runtime Monitoring should be enabled for ECS tasks
  - RDS Protection should be enabled
  - Lambda Protection should be enabled
  - Overall coverage should be >= 80%%
        """
    )

    add_common_arguments(parser)

    args = parser.parse_args()
    configure_logging(verbose=args.verbose, quiet=args.quiet, log_file=args.log_file)

    try:
        written_files, summary = run_audit(args)


        # Return non-zero if there are non-compliant features
        return 1 if summary['non_compliant'] > 0 or permission_failure_count() > 0 else 0

    except KeyboardInterrupt:
        logger.error("Interrupted by user")
        return 130
    except Exception as e:
        logger.error("Audit error: %s", e)
        return 1


if __name__ == '__main__':
    sys.exit(main())
