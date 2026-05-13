#!/usr/bin/env python3
"""
NSF12 Control Audit: Vulnerability Management

A vulnerability management program is a framework for managing vulnerabilities
in systems and software throughout the CI.

REF: RA-5 800-53r5

This audit checks:
- Amazon Inspector v2 enablement (EC2, ECR, Lambda)
- Inspector findings counts by severity (CRITICAL / HIGH / MEDIUM / LOW)
- Security Hub finding counts by severity (filtered to active, failed findings)
- SSM Patch Manager compliance summaries per managed instance

Usage:
    python nsf12.py
    python nsf12.py --accounts 123456789012,234567890123
    python nsf12.py --regions us-east-1,us-west-2
    python nsf12.py --format json,csv

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


logger = get_logger('nsf12')


SEVERITIES = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL')


def audit_inspector(
    inspector_client,
    account_id: str,
    region: str,
) -> list[dict[str, Any]]:
    """Check Inspector v2 enablement and findings counts by severity."""
    results: list[dict[str, Any]] = []

    # Enablement status
    enabled_for: list[str] = []
    try:
        status = inspector_client.batch_get_account_status(accountIds=[account_id])
        for acct in status.get('accounts', []):
            resources = acct.get('resourceState', {})
            for rtype in ('ec2', 'ecr', 'lambda', 'lambdaCode'):
                state = resources.get(rtype, {}).get('status', 'UNKNOWN')
                if state == 'ENABLED':
                    enabled_for.append(rtype)
    except Exception as e:
        if not warn_permission_error('aws-read', e):
            logger.warning("Inspector status check failed in %s: %s", region, e)

    # Findings counts by severity
    severity_counts: dict[str, int] = {s: 0 for s in SEVERITIES}
    try:
        paginator = inspector_client.get_paginator('list_findings')
        for page in paginator.paginate(
            filterCriteria={'findingStatus': [{'comparison': 'EQUALS', 'value': 'ACTIVE'}]}
        ):
            for finding in page.get('findings', []):
                sev = finding.get('severity', 'UNKNOWN')
                if sev in severity_counts:
                    severity_counts[sev] += 1
    except Exception as e:
        if not warn_permission_error('aws-read', e) and 'not enabled' not in str(e).lower():
            logger.warning("Inspector findings list failed in %s: %s", region, e)

    issues: list[str] = []
    if not enabled_for:
        issues.append("Inspector not enabled for any resource type")
    if severity_counts['CRITICAL'] > 0:
        issues.append(f"{severity_counts['CRITICAL']} CRITICAL findings")
    if severity_counts['HIGH'] > 0:
        issues.append(f"{severity_counts['HIGH']} HIGH findings")

    results.append({
        'AccountId': account_id,
        'Region': region,
        'Service': 'Inspector',
        'ResourceId': 'inspector-v2',
        'Status': 'Enabled' if enabled_for else 'Disabled',
        'EnabledFor': ','.join(enabled_for) if enabled_for else 'None',
        'CriticalFindings': severity_counts['CRITICAL'],
        'HighFindings': severity_counts['HIGH'],
        'MediumFindings': severity_counts['MEDIUM'],
        'LowFindings': severity_counts['LOW'],
        'Compliant': len(issues) == 0,
        'Issues': issues,
    })
    return results


def audit_security_hub(
    securityhub_client,
    account_id: str,
    region: str,
) -> list[dict[str, Any]]:
    """Check Security Hub enablement and active failed findings by severity."""
    results: list[dict[str, Any]] = []

    enabled = False
    try:
        hub = securityhub_client.describe_hub()
        enabled = bool(hub.get('HubArn'))
    except Exception:
        enabled = False

    severity_counts: dict[str, int] = {s: 0 for s in SEVERITIES}
    if enabled:
        try:
            filters = {
                'WorkflowStatus': [{'Value': 'NEW', 'Comparison': 'EQUALS'}],
                'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}],
                'ComplianceStatus': [{'Value': 'FAILED', 'Comparison': 'EQUALS'}],
            }
            paginator = securityhub_client.get_paginator('get_findings')
            for page in paginator.paginate(Filters=filters):
                for finding in page.get('Findings', []):
                    sev = finding.get('Severity', {}).get('Label', 'UNKNOWN')
                    if sev in severity_counts:
                        severity_counts[sev] += 1
        except Exception as e:
            if not warn_permission_error('aws-read', e):
                logger.warning("Security Hub findings list failed in %s: %s", region, e)

    issues: list[str] = []
    if not enabled:
        issues.append("Security Hub not enabled")
    if severity_counts['CRITICAL'] > 0:
        issues.append(f"{severity_counts['CRITICAL']} CRITICAL findings")
    if severity_counts['HIGH'] > 0:
        issues.append(f"{severity_counts['HIGH']} HIGH findings")

    results.append({
        'AccountId': account_id,
        'Region': region,
        'Service': 'SecurityHub',
        'ResourceId': 'security-hub',
        'Status': 'Enabled' if enabled else 'Disabled',
        'EnabledFor': 'N/A',
        'CriticalFindings': severity_counts['CRITICAL'],
        'HighFindings': severity_counts['HIGH'],
        'MediumFindings': severity_counts['MEDIUM'],
        'LowFindings': severity_counts['LOW'],
        'Compliant': len(issues) == 0,
        'Issues': issues,
    })
    return results


def audit_ssm_patch_compliance(
    ssm_client,
    account_id: str,
    region: str,
) -> list[dict[str, Any]]:
    """Summarize SSM Patch Manager compliance across managed instances."""
    results: list[dict[str, Any]] = []

    total = 0
    compliant = 0
    non_compliant = 0
    try:
        paginator = ssm_client.get_paginator('list_resource_compliance_summaries')
        for page in paginator.paginate(
            Filters=[{'Key': 'ComplianceType', 'Type': 'EQUAL', 'Values': ['Patch']}]
        ):
            for item in page.get('ResourceComplianceSummaryItems', []):
                total += 1
                if item.get('Status') == 'COMPLIANT':
                    compliant += 1
                else:
                    non_compliant += 1
    except Exception as e:
        if not warn_permission_error('aws-read', e):
            logger.warning("SSM patch compliance list failed in %s: %s", region, e)

    issues: list[str] = []
    if total == 0:
        # No instances reporting is not necessarily a failure — flag for review
        issues.append("No SSM patch compliance data (no managed instances or Patch Manager not configured)")
    elif non_compliant > 0:
        issues.append(f"{non_compliant} of {total} instances non-compliant with patch baseline")

    results.append({
        'AccountId': account_id,
        'Region': region,
        'Service': 'SSMPatchManager',
        'ResourceId': 'patch-compliance-summary',
        'Status': 'Reporting' if total > 0 else 'NoData',
        'EnabledFor': f'{total} instances',
        'CriticalFindings': non_compliant,  # reuse field for non-compliant count
        'HighFindings': 0,
        'MediumFindings': 0,
        'LowFindings': 0,
        'Compliant': total > 0 and non_compliant == 0,
        'Issues': issues,
    })
    return results


def run_audit(args) -> tuple[list[str], dict[str, Any]]:
    accounts = parse_accounts_arg(args.accounts)
    regions = parse_regions_arg(args.regions)
    output_dir = args.output_dir
    role_name = args.role
    date = current_date()

    logger.info("NSF12 audit starting: Vulnerability Management")
    logger.info("Date=%s accounts=%d regions=%d role=%s",
                date, len(accounts), len(regions), role_name)

    total = 0
    compliant_count = 0
    non_compliant_count = 0
    csv_rows: list[list[Any]] = []

    headers = [
        'AccountId', 'Region', 'Service', 'ResourceId', 'Status',
        'EnabledFor', 'CriticalFindings', 'HighFindings',
        'MediumFindings', 'LowFindings', 'Compliant', 'Issues',
    ]

    for account_id in accounts:
        logger.info("Auditing account: %s", account_id)
        try:
            with AuditContext(account_id, role_name=role_name, profile=args.profile, external_id=args.external_id) as ctx:
                for region in regions:
                    try:
                        inspector = ctx.client('inspector2', region_name=region)
                        for r in audit_inspector(inspector, account_id, region):
                            total += 1
                            compliant_count += 1 if r['Compliant'] else 0
                            non_compliant_count += 0 if r['Compliant'] else 1
                            csv_rows.append([r.get(h) for h in headers])

                        sh = ctx.client('securityhub', region_name=region)
                        for r in audit_security_hub(sh, account_id, region):
                            total += 1
                            compliant_count += 1 if r['Compliant'] else 0
                            non_compliant_count += 0 if r['Compliant'] else 1
                            csv_rows.append([r.get(h) for h in headers])

                        ssm = ctx.client('ssm', region_name=region)
                        for r in audit_ssm_patch_compliance(ssm, account_id, region):
                            total += 1
                            compliant_count += 1 if r['Compliant'] else 0
                            non_compliant_count += 0 if r['Compliant'] else 1
                            csv_rows.append([r.get(h) for h in headers])

                    except Exception as e:
                        logger.warning("Error in region %s: %s", region, e)
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
        output_dir, f"nsf12-{date}", records, summary, formats, headers,
        title="NSF12 Audit",
    )

    print("\n" + "=" * 70)
    print("NSF12 AUDIT SUMMARY")
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
        description='NSF12: Vulnerability Management',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s
  %(prog)s --accounts 123456789012 --regions us-east-1
  %(prog)s --format json,csv --output-dir ./reports

Checks Performed:
  - Amazon Inspector v2 enablement and finding counts (EC2, ECR, Lambda)
  - Security Hub enablement and active failed findings
  - SSM Patch Manager compliance summary
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
