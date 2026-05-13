#!/usr/bin/env python3
"""
NSF4 Control Audit: Deploy and Maintain Anti-malware Software

Deploy anti-malware software to systems capable of running such software.
For a variety of reasons some systems (e.g. instrumentation, HPC, embedded
systems, control systems) may not be able to run anti-malware software and
are thus excluded from this control.

REF: SI-3 800-53r5

This audit checks:
- GuardDuty enabled in all regions
- GuardDuty Malware Protection enabled
- EC2 instances managed by SSM (can receive anti-malware)
- Security Hub enabled for centralized findings

Usage:
    python nsf4.py
    python nsf4.py --accounts 123456789012,234567890123

Prerequisites:
    pip install -r requirements.txt
"""

import sys
from pathlib import Path

# Add parent directory to path for imports when running directly
sys.path.insert(0, str(Path(__file__).parent.parent))

import argparse
import logging
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


logger = get_logger('nsf4')



# Regions where GuardDuty should be enabled
CRITICAL_REGIONS = [
    'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
    'eu-west-1', 'eu-central-1'
]


def audit_guardduty(
    guardduty_client,
    account_id: str,
    region: str
) -> list[dict[str, Any]]:
    """
    Audit GuardDuty configuration for anti-malware coverage.

    Args:
        guardduty_client: boto3 GuardDuty client
        account_id: AWS account ID
        region: AWS region

    Returns:
        List of GuardDuty audit results
    """
    results = []

    try:
        # List detectors
        detectors_response = guardduty_client.list_detectors()
        detector_ids = detectors_response.get('DetectorIds', [])

        if not detector_ids:
            # No GuardDuty detector
            is_critical = region in CRITICAL_REGIONS
            results.append({
                'account_id': account_id,
                'region': region,
                'resource_type': 'GuardDuty',
                'resource_id': 'N/A',
                'anti_malware_status': 'Not Enabled',
                'coverage_type': 'None',
                'malware_protection': False,
                'ebs_malware_protection': False,
                'compliant': not is_critical,
                'issues': ['GuardDuty not enabled'] if is_critical else ['GuardDuty not enabled (non-critical region)']
            })
            return results

        for detector_id in detector_ids:
            # Get detector details
            detector = guardduty_client.get_detector(DetectorId=detector_id)

            status = detector.get('Status', 'DISABLED')
            finding_frequency = detector.get('FindingPublishingFrequency', 'SIX_HOURS')

            # Check data sources / features
            data_sources = detector.get('DataSources', {})
            features = detector.get('Features', [])

            # Malware Protection status
            malware_protection = False
            ebs_malware_protection = False
            s3_protection = False

            # Check via Features (newer API)
            for feature in features:
                name = feature.get('Name', '')
                feature_status = feature.get('Status', 'DISABLED')

                if name == 'EBS_MALWARE_PROTECTION' and feature_status == 'ENABLED':
                    ebs_malware_protection = True
                    malware_protection = True
                elif name == 'S3_DATA_EVENTS' and feature_status == 'ENABLED':
                    s3_protection = True
                elif name == 'MALWARE_PROTECTION' and feature_status == 'ENABLED':
                    malware_protection = True

            # Check via DataSources (older API, for compatibility)
            if not malware_protection:
                malware_ds = data_sources.get('MalwareProtection', {})
                scan_ec2 = malware_ds.get('ScanEc2InstanceWithFindings', {})
                ebs_volumes = scan_ec2.get('EbsVolumes', {})
                if ebs_volumes.get('Status') == 'ENABLED':
                    ebs_malware_protection = True
                    malware_protection = True

            if not s3_protection:
                s3_ds = data_sources.get('S3Logs', {})
                if s3_ds.get('Status') == 'ENABLED':
                    s3_protection = True

            # Determine compliance
            issues = []

            if status != 'ENABLED':
                issues.append("GuardDuty detector is disabled")

            if not malware_protection:
                issues.append("Malware Protection not enabled")

            if not ebs_malware_protection:
                issues.append("EBS Malware Protection not enabled")

            # Coverage type description
            coverage_parts = []
            if malware_protection:
                coverage_parts.append("Malware")
            if ebs_malware_protection:
                coverage_parts.append("EBS")
            if s3_protection:
                coverage_parts.append("S3")

            coverage_type = ', '.join(coverage_parts) if coverage_parts else 'None'

            compliant = status == 'ENABLED' and malware_protection

            results.append({
                'account_id': account_id,
                'region': region,
                'resource_type': 'GuardDuty',
                'resource_id': detector_id,
                'anti_malware_status': 'Enabled' if status == 'ENABLED' else 'Disabled',
                'coverage_type': coverage_type,
                'malware_protection': malware_protection,
                'ebs_malware_protection': ebs_malware_protection,
                'compliant': compliant,
                'issues': issues
            })

    except guardduty_client.exceptions.BadRequestException:
        # GuardDuty not available in this region
        pass
    except Exception as e:
        if not warn_permission_error('aws-read', e):
            logger.warning("Error checking GuardDuty in %s: %s", region, e)

    return results


def audit_ssm_managed_instances(
    ssm_client,
    ec2_client,
    account_id: str,
    region: str
) -> list[dict[str, Any]]:
    """
    Audit EC2 instances for SSM management (anti-malware capability).

    Args:
        ssm_client: boto3 SSM client
        ec2_client: boto3 EC2 client
        account_id: AWS account ID
        region: AWS region

    Returns:
        List of instance audit results
    """
    results = []

    try:
        # Get all running EC2 instances
        ec2_paginator = ec2_client.get_paginator('describe_instances')
        all_instances = {}

        for page in ec2_paginator.paginate(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]):
            for reservation in page.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    instance_id = instance.get('InstanceId', '')
                    instance_type = instance.get('InstanceType', '')
                    platform = instance.get('Platform', 'Linux')  # Windows or Linux

                    # Get instance name from tags
                    instance_name = ''
                    for tag in instance.get('Tags', []):
                        if tag.get('Key') == 'Name':
                            instance_name = tag.get('Value', '')
                            break

                    all_instances[instance_id] = {
                        'instance_id': instance_id,
                        'instance_name': instance_name,
                        'instance_type': instance_type,
                        'platform': platform
                    }

        if not all_instances:
            return results

        # Get SSM managed instances
        ssm_paginator = ssm_client.get_paginator('describe_instance_information')
        managed_instances = set()

        for page in ssm_paginator.paginate():
            for instance_info in page.get('InstanceInformationList', []):
                instance_id = instance_info.get('InstanceId', '')
                managed_instances.add(instance_id)

        # Check each instance
        for instance_id, instance_data in all_instances.items():
            is_managed = instance_id in managed_instances

            issues = []
            if not is_managed:
                issues.append("Not managed by SSM (cannot receive anti-malware updates)")

            results.append({
                'account_id': account_id,
                'region': region,
                'resource_type': 'EC2Instance',
                'resource_id': instance_id,
                'anti_malware_status': 'SSM Managed' if is_managed else 'Not Managed',
                'coverage_type': 'SSM' if is_managed else 'None',
                'malware_protection': is_managed,
                'ebs_malware_protection': False,  # Checked separately via GuardDuty
                'compliant': is_managed,
                'issues': issues
            })

    except Exception as e:
        if not warn_permission_error('aws-read', e):
            logger.warning("Error checking SSM instances in %s: %s", region, e)

    return results


def audit_security_hub(
    securityhub_client,
    account_id: str,
    region: str
) -> list[dict[str, Any]]:
    """
    Audit Security Hub for centralized security findings.

    Args:
        securityhub_client: boto3 Security Hub client
        account_id: AWS account ID
        region: AWS region

    Returns:
        List of Security Hub audit results
    """
    results = []

    try:
        hub = securityhub_client.describe_hub()

        hub_arn = hub.get('HubArn', '')
        auto_enable = hub.get('AutoEnableControls', False)

        # Get enabled standards
        standards_response = securityhub_client.get_enabled_standards()
        enabled_standards = standards_response.get('StandardsSubscriptions', [])

        standard_names = []
        for standard in enabled_standards:
            standard_arn = standard.get('StandardsArn', '')
            # Extract standard name from ARN
            if 'cis-aws' in standard_arn.lower():
                standard_names.append('CIS')
            elif 'aws-foundational' in standard_arn.lower():
                standard_names.append('AWS Foundational')
            elif 'pci-dss' in standard_arn.lower():
                standard_names.append('PCI-DSS')

        issues = []
        if not enabled_standards:
            issues.append("No security standards enabled")

        results.append({
            'account_id': account_id,
            'region': region,
            'resource_type': 'SecurityHub',
            'resource_id': hub_arn.split('/')[-1] if hub_arn else 'hub',
            'anti_malware_status': 'Enabled',
            'coverage_type': ', '.join(standard_names) if standard_names else 'None',
            'malware_protection': True,  # Hub aggregates GuardDuty findings
            'ebs_malware_protection': False,
            'compliant': len(enabled_standards) > 0,
            'issues': issues
        })

    except securityhub_client.exceptions.InvalidAccessException:
        # Security Hub not enabled
        is_critical = region in CRITICAL_REGIONS
        results.append({
            'account_id': account_id,
            'region': region,
            'resource_type': 'SecurityHub',
            'resource_id': 'N/A',
            'anti_malware_status': 'Not Enabled',
            'coverage_type': 'None',
            'malware_protection': False,
            'ebs_malware_protection': False,
            'compliant': not is_critical,
            'issues': ['Security Hub not enabled']
        })
    except Exception as e:
        if not warn_permission_error('aws-read', e) and 'not subscribed' not in str(e).lower():
            logger.warning("Error checking Security Hub in %s: %s", region, e)

    return results


def run_audit(args) -> tuple[str, dict[str, Any]]:
    """
    Run NSF4 audit across all accounts.

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

    logger.info("NSF4 audit starting: Deploy and Maintain Anti-malware Software")
    logger.info("Date=%s accounts=%d regions=%d role=%s",
                date, len(accounts), len(regions), role_name)

    # Statistics
    total_resources = 0
    with_protection = 0
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
                        # GuardDuty
                        guardduty = ctx.client('guardduty', region_name=region)
                        gd_results = audit_guardduty(guardduty, account_id, region)

                        for result in gd_results:
                            total_resources += 1
                            if result['malware_protection']:
                                with_protection += 1
                            if result['compliant']:
                                compliant_resources += 1
                            else:
                                non_compliant_resources += 1

                            csv_rows.append([
                                result['account_id'],
                                result['region'],
                                result['resource_type'],
                                result['resource_id'],
                                result['anti_malware_status'],
                                result['coverage_type'],
                                str(result['malware_protection']),
                                str(result['ebs_malware_protection']),
                                str(result['compliant']),
                                '; '.join(result['issues']) if result['issues'] else 'None'
                            ])

                        # Security Hub
                        securityhub = ctx.client('securityhub', region_name=region)
                        sh_results = audit_security_hub(securityhub, account_id, region)

                        for result in sh_results:
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
                                result['anti_malware_status'],
                                result['coverage_type'],
                                str(result['malware_protection']),
                                str(result['ebs_malware_protection']),
                                str(result['compliant']),
                                '; '.join(result['issues']) if result['issues'] else 'None'
                            ])

                        # SSM Managed Instances (only check in critical regions for performance)
                        if region in CRITICAL_REGIONS:
                            ssm = ctx.client('ssm', region_name=region)
                            ec2 = ctx.client('ec2', region_name=region)
                            ssm_results = audit_ssm_managed_instances(ssm, ec2, account_id, region)

                            for result in ssm_results:
                                total_resources += 1
                                if result['malware_protection']:
                                    with_protection += 1
                                if result['compliant']:
                                    compliant_resources += 1
                                else:
                                    non_compliant_resources += 1

                                csv_rows.append([
                                    result['account_id'],
                                    result['region'],
                                    result['resource_type'],
                                    result['resource_id'],
                                    result['anti_malware_status'],
                                    result['coverage_type'],
                                    str(result['malware_protection']),
                                    str(result['ebs_malware_protection']),
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
        'AntiMalwareStatus', 'CoverageType', 'MalwareProtection',
        'EBSMalwareProtection', 'Compliant', 'Issues'
    ]

    # Print summary
    summary = {
        'total_resources': total_resources,
        'with_protection': with_protection,
        'compliant': compliant_resources,
        'non_compliant': non_compliant_resources
    }

    formats = parse_formats_arg(args.format)
    records = [dict(zip(headers, row)) for row in csv_rows]
    written_files = save_results(
        output_dir, f"nsf4-{date}", records, summary, formats, headers,
        title="NSF4 Audit",
    )

    print("\n" + "=" * 70)
    print("NSF4 AUDIT SUMMARY")
    print("=" * 70)
    print(f"Total Resources Scanned:  {total_resources}")
    print(f"With Anti-malware:        {with_protection}")
    print(f"Compliant:                {compliant_resources}")
    print(f"Non-Compliant:            {non_compliant_resources}")
    print("\nReports saved:")
    for fp in written_files:
        print(f"  {fp}")

    return written_files, summary


def main():
    parser = argparse.ArgumentParser(
        description='NSF4: Deploy and Maintain Anti-malware Software',
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
  - GuardDuty should be enabled in all critical regions
  - GuardDuty Malware Protection should be enabled
  - EC2 instances should be managed by SSM for patching
  - Security Hub should be enabled for centralized findings
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
