#!/usr/bin/env python3
"""
NSF13 Control Audit: Hardening Standards / Secure Configuration

Create and implement a secure configuration standard applied to all systems
under direct management.

REF: CM-2, CM-6 800-53r5

This audit checks:
- AWS Config recorder enabled and recording all resource types
- AWS Config delivery channel configured
- Count of Config rules with NON_COMPLIANT resources
- AWS Config conformance packs deployed
- Security Hub standards enabled (CIS AWS Foundations, AWS Foundational, PCI)
- SSM State Manager associations exist (configuration enforcement)

Usage:
    python nsf13.py
    python nsf13.py --accounts 123456789012,234567890123
    python nsf13.py --regions us-east-1,us-west-2
    python nsf13.py --format json,yaml

Prerequisites:
    pip install -r requirements.txt
"""

import sys
from pathlib import Path

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


logger = get_logger('nsf13')


def audit_config_service(
    config_client,
    account_id: str,
    region: str,
) -> list[dict[str, Any]]:
    """Check AWS Config recorder, delivery channel, and rule compliance."""
    results: list[dict[str, Any]] = []

    # Recorders
    recorder_running = False
    recording_all = False
    try:
        recorders = config_client.describe_configuration_recorders().get('ConfigurationRecorders', [])
        status_list = config_client.describe_configuration_recorder_status().get(
            'ConfigurationRecordersStatus', []
        )
        for rec in recorders:
            recording_all = recording_all or rec.get('recordingGroup', {}).get('allSupported', False)
        for st in status_list:
            recorder_running = recorder_running or st.get('recording', False)
    except Exception as e:
        if not warn_permission_error('aws-read', e):
            logger.warning("Config recorder check failed in {region}: %s", e)

    # Delivery channel
    delivery_configured = False
    try:
        channels = config_client.describe_delivery_channels().get('DeliveryChannels', [])
        delivery_configured = len(channels) > 0
    except Exception as _e:
        warn_permission_error('aws-read', _e)

    issues: list[str] = []
    if not recorder_running:
        issues.append("Config recorder not running")
    if not recording_all:
        issues.append("Config recorder not recording all resource types")
    if not delivery_configured:
        issues.append("Config delivery channel not configured")

    results.append({
        'AccountId': account_id,
        'Region': region,
        'Service': 'AWSConfig',
        'CheckType': 'Recorder',
        'ResourceId': 'config-recorder',
        'Status': 'Recording' if recorder_running else 'Stopped',
        'Detail': f'allSupported={recording_all}; deliveryChannel={delivery_configured}',
        'Compliant': recorder_running and recording_all and delivery_configured,
        'Issues': issues,
    })

    # Rules with non-compliant resources
    non_compliant_rules = 0
    total_rules = 0
    non_compliant_rule_names: list[str] = []
    try:
        paginator = config_client.get_paginator('describe_compliance_by_config_rule')
        for page in paginator.paginate(
            ComplianceTypes=['NON_COMPLIANT', 'COMPLIANT']
        ):
            for item in page.get('ComplianceByConfigRules', []):
                total_rules += 1
                comp = item.get('Compliance', {}).get('ComplianceType')
                if comp == 'NON_COMPLIANT':
                    non_compliant_rules += 1
                    name = item.get('ConfigRuleName', '')
                    if len(non_compliant_rule_names) < 20 and name:
                        non_compliant_rule_names.append(name)
    except Exception as e:
        if not warn_permission_error('aws-read', e):
            logger.warning("Config rule compliance failed in {region}: %s", e)

    rule_issues: list[str] = []
    if total_rules == 0:
        rule_issues.append("No Config rules deployed")
    elif non_compliant_rules > 0:
        rule_issues.append(
            f"{non_compliant_rules}/{total_rules} rules NON_COMPLIANT "
            f"(e.g. {', '.join(non_compliant_rule_names[:5])})"
        )

    results.append({
        'AccountId': account_id,
        'Region': region,
        'Service': 'AWSConfig',
        'CheckType': 'Rules',
        'ResourceId': 'config-rules',
        'Status': f'{non_compliant_rules}/{total_rules} non-compliant',
        'Detail': '; '.join(non_compliant_rule_names) if non_compliant_rule_names else 'None',
        'Compliant': total_rules > 0 and non_compliant_rules == 0,
        'Issues': rule_issues,
    })

    # Conformance packs
    conformance_pack_count = 0
    try:
        paginator = config_client.get_paginator('describe_conformance_packs')
        for page in paginator.paginate():
            conformance_pack_count += len(page.get('ConformancePackDetails', []))
    except Exception as _e:
        warn_permission_error('aws-read', _e)

    pack_issues: list[str] = []
    if conformance_pack_count == 0:
        pack_issues.append("No conformance packs deployed (e.g. CIS, Operational Best Practices)")

    results.append({
        'AccountId': account_id,
        'Region': region,
        'Service': 'AWSConfig',
        'CheckType': 'ConformancePacks',
        'ResourceId': 'conformance-packs',
        'Status': f'{conformance_pack_count} deployed',
        'Detail': 'N/A',
        'Compliant': conformance_pack_count > 0,
        'Issues': pack_issues,
    })

    return results


def audit_security_hub_standards(
    securityhub_client,
    account_id: str,
    region: str,
) -> list[dict[str, Any]]:
    """Check which Security Hub standards (CIS, FSBP, PCI) are enabled."""
    results: list[dict[str, Any]] = []

    enabled_standards: list[str] = []
    try:
        subs = securityhub_client.get_enabled_standards()
        for sub in subs.get('StandardsSubscriptions', []):
            arn = sub.get('StandardsArn', '')
            if 'cis-aws-foundations-benchmark' in arn:
                enabled_standards.append('CIS-AWS-Foundations')
            elif 'aws-foundational-security-best-practices' in arn:
                enabled_standards.append('AWS-Foundational')
            elif 'pci-dss' in arn:
                enabled_standards.append('PCI-DSS')
            elif 'nist-800-53' in arn:
                enabled_standards.append('NIST-800-53')
    except Exception as e:
        if not warn_permission_error('aws-read', e) and 'not subscribed' not in str(e).lower():
            logger.warning("Security Hub standards check failed in {region}: %s", e)

    issues: list[str] = []
    if not enabled_standards:
        issues.append("No Security Hub hardening standards enabled")
    elif 'CIS-AWS-Foundations' not in enabled_standards and 'AWS-Foundational' not in enabled_standards:
        issues.append("Neither CIS nor AWS Foundational standard enabled")

    results.append({
        'AccountId': account_id,
        'Region': region,
        'Service': 'SecurityHub',
        'CheckType': 'Standards',
        'ResourceId': 'sh-standards',
        'Status': 'Enabled' if enabled_standards else 'None',
        'Detail': ', '.join(enabled_standards) if enabled_standards else 'None',
        'Compliant': len(issues) == 0,
        'Issues': issues,
    })
    return results


def audit_ssm_state_manager(
    ssm_client,
    account_id: str,
    region: str,
) -> list[dict[str, Any]]:
    """Check SSM State Manager associations exist for configuration enforcement."""
    results: list[dict[str, Any]] = []

    association_count = 0
    try:
        paginator = ssm_client.get_paginator('list_associations')
        for page in paginator.paginate():
            association_count += len(page.get('Associations', []))
    except Exception as e:
        if not warn_permission_error('aws-read', e):
            logger.warning("SSM State Manager check failed in {region}: %s", e)

    issues: list[str] = []
    if association_count == 0:
        issues.append("No SSM State Manager associations (no automated config enforcement)")

    results.append({
        'AccountId': account_id,
        'Region': region,
        'Service': 'SSMStateManager',
        'CheckType': 'Associations',
        'ResourceId': 'state-manager',
        'Status': f'{association_count} associations',
        'Detail': 'N/A',
        'Compliant': association_count > 0,
        'Issues': issues,
    })
    return results


def run_audit(args) -> tuple[list[str], dict[str, Any]]:
    accounts = parse_accounts_arg(args.accounts)
    regions = parse_regions_arg(args.regions)
    output_dir = args.output_dir
    role_name = args.role
    date = current_date()

    logger.info("NSF13 audit starting: Hardening Standards / Secure Configuration")
    logger.info("Date=%s accounts=%d regions=%d role=%s",
                date, len(accounts), len(regions), role_name)

    total = 0
    compliant_count = 0
    non_compliant_count = 0
    csv_rows: list[list[Any]] = []

    headers = [
        'AccountId', 'Region', 'Service', 'CheckType', 'ResourceId',
        'Status', 'Detail', 'Compliant', 'Issues',
    ]

    for account_id in accounts:
        logger.info("Auditing account: %s", account_id)
        try:
            with AuditContext(account_id, role_name=role_name, profile=args.profile, external_id=args.external_id) as ctx:
                for region in regions:
                    try:
                        cfg = ctx.client('config', region_name=region)
                        for r in audit_config_service(cfg, account_id, region):
                            total += 1
                            compliant_count += 1 if r['Compliant'] else 0
                            non_compliant_count += 0 if r['Compliant'] else 1
                            csv_rows.append([r.get(h) for h in headers])

                        sh = ctx.client('securityhub', region_name=region)
                        for r in audit_security_hub_standards(sh, account_id, region):
                            total += 1
                            compliant_count += 1 if r['Compliant'] else 0
                            non_compliant_count += 0 if r['Compliant'] else 1
                            csv_rows.append([r.get(h) for h in headers])

                        ssm = ctx.client('ssm', region_name=region)
                        for r in audit_ssm_state_manager(ssm, account_id, region):
                            total += 1
                            compliant_count += 1 if r['Compliant'] else 0
                            non_compliant_count += 0 if r['Compliant'] else 1
                            csv_rows.append([r.get(h) for h in headers])

                    except Exception as e:
                        logger.warning("Error in region {region}: %s", e)
                        continue
        except Exception as e:
            logger.error("Error auditing account %s: %s", account_id, e)
            continue

    summary = {
        'total_checks': total,
        'compliant': compliant_count,
        'non_compliant': non_compliant_count,
    }

    formats = parse_formats_arg(args.format)
    records = [dict(zip(headers, row)) for row in csv_rows]
    written_files = save_results(
        output_dir, f"nsf13-{date}", records, summary, formats, headers,
        title="NSF13 Audit",
    )

    print("\n" + "=" * 70)
    print("NSF13 AUDIT SUMMARY")
    print("=" * 70)
    print(f"Total Checks:    {total}")
    print(f"Compliant:       {compliant_count}")
    print(f"Non-Compliant:   {non_compliant_count}")
    print("\nReports saved:")
    for fp in written_files:
        print(f"  {fp}")

    return written_files, summary


def main():
    parser = argparse.ArgumentParser(
        description='NSF13: Hardening Standards / Secure Configuration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s
  %(prog)s --accounts 123456789012 --regions us-east-1
  %(prog)s --format yaml --output-dir ./reports

Checks Performed:
  - AWS Config recorder + delivery channel
  - AWS Config rules compliance (non-compliant rule count)
  - AWS Config conformance packs deployed
  - Security Hub hardening standards (CIS, AWS Foundational, PCI, NIST)
  - SSM State Manager associations (config enforcement)
        """
    )
    add_common_arguments(parser)
    args = parser.parse_args()
    configure_logging(verbose=args.verbose, quiet=args.quiet, log_file=args.log_file)

    try:
        _, summary = run_audit(args)
        return 1 if summary['non_compliant'] > 0 or permission_failure_count() > 0 else 0
    except KeyboardInterrupt:
        logger.error("Interrupted by user")
        return 130
    except Exception as e:
        logger.error("Audit error: %s", e)
        return 1


if __name__ == '__main__':
    sys.exit(main())
