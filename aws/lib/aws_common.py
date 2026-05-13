#!/usr/bin/env python3
"""
Common AWS utilities for NSF Critical Controls audit scripts.

Shared functionality used by all NSF audit scripts:
- Configuration loading (accounts, regions, identity stores) — optional
- AWS session creation: assume-role, named profile, or default credentials
- Output writers for CSV / JSON / YAML / human-readable text
- A single `save_results` dispatcher that can emit any combination of formats
- Common argparse helpers and an `AuditContext` manager

Usage:
    from lib.aws_common import (
        AuditContext, add_common_arguments, build_session,
        current_date, parse_accounts_arg, parse_regions_arg,
        parse_formats_arg, resolve_role, save_results,
    )
"""

import csv
import json
import logging
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import boto3
import yaml
from botocore.exceptions import BotoCoreError, ClientError


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
# All audit scripts log under the `nsf_audit` namespace. A child logger
# per-script (`nsf_audit.nsf1`, `nsf_audit.nsf12`, …) is recommended so the
# log line identifies which audit emitted it.

LOGGER_NAME = 'nsf_audit'
logger = logging.getLogger(LOGGER_NAME)

DEFAULT_LOG_FORMAT = '%(asctime)s [%(levelname)-7s] %(name)s: %(message)s'
DEFAULT_DATE_FORMAT = '%Y-%m-%dT%H:%M:%S%z'


def configure_logging(
    verbose: bool = False,
    quiet: bool = False,
    log_file: Optional[str] = None,
    log_format: str = DEFAULT_LOG_FORMAT,
) -> logging.Logger:
    """
    Configure the `nsf_audit` logger hierarchy. Idempotent — safe to call
    multiple times; existing handlers on the namespace are replaced.

    Output goes to stderr (so stdout is reserved for written-file paths if a
    script chooses to print them), or to `log_file` if provided. Verbose
    enables DEBUG, quiet limits to WARNING and above.
    """
    if verbose and quiet:
        raise ValueError("--verbose and --quiet are mutually exclusive")
    level = logging.DEBUG if verbose else (logging.WARNING if quiet else logging.INFO)

    nsf_logger = logging.getLogger(LOGGER_NAME)
    nsf_logger.setLevel(level)
    nsf_logger.propagate = False
    # Replace any prior handlers so configure_logging is idempotent.
    for h in list(nsf_logger.handlers):
        nsf_logger.removeHandler(h)

    if log_file:
        handler: logging.Handler = logging.FileHandler(log_file, encoding='utf-8')
    else:
        handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(log_format, datefmt=DEFAULT_DATE_FORMAT))
    nsf_logger.addHandler(handler)
    return nsf_logger


def get_logger(suffix: str) -> logging.Logger:
    """Return a child logger of `nsf_audit` (e.g. get_logger('nsf1'))."""
    return logging.getLogger(f"{LOGGER_NAME}.{suffix}")


# Bump on every release. Surfaced in the `nsfN --version` CLI output and in
# the JSON report's summary block so auditors can identify the build that
# produced a given evidence file.
__version__ = '1.0.0'

# Directories
SCRIPT_DIR = Path(__file__).parent           # lib/
CONFIG_DIR = SCRIPT_DIR.parent / 'config'    # aws/config/

# Env var names
ENV_ROLE = 'NSF_AUDIT_ROLE'
ENV_PROFILE = 'AWS_PROFILE'
ENV_EXTERNAL_ID = 'AWS_EXTERNAL_ID'

# Supported output formats
SUPPORTED_FORMATS = ('csv', 'json', 'yaml', 'text')
DEFAULT_FORMAT = 'csv'

# AWS account IDs are exactly 12 digits.
ACCOUNT_ID_RE = re.compile(r'^[0-9]{12}$')

# Error codes that indicate the caller lacks permission, has expired creds,
# or is otherwise unable to read the data (NOT "the resource doesn't exist").
# When any of these is raised, the audit must record an explicit error and
# refuse to mark the affected record compliant.
PERMISSION_ERROR_CODES = frozenset({
    'AccessDenied',
    'AccessDeniedException',
    'AuthFailure',
    'ExpiredToken',
    'ExpiredTokenException',
    'InvalidClientTokenId',
    'SignatureDoesNotMatch',
    'TokenRefreshRequired',
    'UnauthorizedOperation',
    'UnrecognizedClientException',
})

# CSV formula-injection neutralization. Excel / Google Sheets execute fields
# starting with these as formulas, so we prefix any matching value with a
# single quote when writing CSV. CWE-1236.
_CSV_DANGEROUS_PREFIXES = ('=', '+', '-', '@', '\t', '\r')


class AuditPermissionError(Exception):
    """Raised when an AWS API call fails because the audit role lacks permission.

    Audit code MUST NOT silently swallow this — a failed permission check
    means we cannot determine compliance, so the affected record must be
    flagged with an explicit error rather than recorded as compliant.
    """


def is_permission_error(exc: BaseException) -> bool:
    """Return True if exc indicates the audit role lacks read permission."""
    if isinstance(exc, AuditPermissionError):
        return True
    if isinstance(exc, ClientError):
        code = exc.response.get('Error', {}).get('Code', '')
        return code in PERMISSION_ERROR_CODES
    return False


# Counter incremented every time warn_permission_error() flags a real
# permission failure. Audit scripts inspect this at exit and bump their
# exit code so CI fails — never silently — when evidence was missed.
_permission_failures: list[str] = []


def warn_permission_error(operation: str, exc: BaseException) -> bool:
    """
    If `exc` is a permission error, log an ERROR with a stable
    `NSF-AUDIT-PERMISSION-ERROR` marker (greppable in CI logs) and record it
    in the process-wide counter. Returns True if a warning was emitted.

    Use in audit `except` blocks where the call gates compliance:

        except Exception as e:
            if not warn_permission_error("ListUsers", e):
                pass  # non-permission error — keep prior swallow behavior

    Audit scripts MUST surface a non-zero exit if `permission_failure_count()`
    is non-zero at the end of a run, otherwise the report may falsely show
    compliance for resources we couldn't actually read.
    """
    if not is_permission_error(exc):
        return False
    code = ''
    if isinstance(exc, ClientError):
        code = exc.response.get('Error', {}).get('Code', '')
    msg = f"NSF-AUDIT-PERMISSION-ERROR {operation}: {code or type(exc).__name__}: {exc}"
    logger.error(msg)
    _permission_failures.append(msg)
    return True


def permission_failure_count() -> int:
    """Return the number of permission errors observed during this process."""
    return len(_permission_failures)


def permission_failures() -> list[str]:
    """Return the list of permission-error messages observed during this process."""
    return list(_permission_failures)


def reset_permission_failures() -> None:
    """Reset the permission-error counter (mainly for tests)."""
    _permission_failures.clear()


def _neutralize_csv_value(value: Any) -> Any:
    """Defuse CSV formula injection (CWE-1236) for fields opened in Excel/Sheets."""
    if isinstance(value, str) and value and value[0] in _CSV_DANGEROUS_PREFIXES:
        return "'" + value
    return value


def validate_account_id(account_id: str) -> str:
    """Validate that account_id is a 12-digit AWS account ID. Returns it on success."""
    if not isinstance(account_id, str) or not ACCOUNT_ID_RE.match(account_id):
        raise ValueError(
            f"Invalid AWS account ID: {account_id!r}. Expected 12 numeric digits."
        )
    return account_id


def resolve_output_dir(path: str) -> Path:
    """
    Resolve --output-dir to an absolute path, refusing symlinks at the target
    or anywhere inside the workspace-controlled portion of the path.

    Defends against an attacker (or accident) replacing the chosen output
    directory — or any directory under $WORKSPACE — with a symlink pointing
    outside the workspace. OS-level symlinks above $WORKSPACE (e.g. macOS
    /var → /private/var) are tolerated because they are not the attack
    surface here.
    """
    raw = Path(path).expanduser()
    absolute = raw.absolute()

    # Always refuse if the target itself is a symlink.
    if absolute.is_symlink():
        raise ValueError(
            f"Refusing to write into symlinked path: {absolute} (from {path!r})"
        )

    # If we're inside a Jenkins-style WORKSPACE, also refuse if any component
    # between $WORKSPACE and the target is a symlink — that is the realistic
    # attack: a malicious commit / job that introduces a symlink under the
    # workspace to redirect evidence elsewhere.
    workspace = os.environ.get('WORKSPACE')
    if workspace:
        try:
            ws = Path(workspace).expanduser().absolute()
            rel = absolute.relative_to(ws)
        except ValueError:
            rel = None  # output is outside WORKSPACE — skip this check
        if rel is not None:
            walker = ws
            for part in rel.parts:
                walker = walker / part
                if walker.is_symlink():
                    raise ValueError(
                        f"Refusing to write through symlinked workspace "
                        f"component: {walker} (from {path!r})"
                    )

    absolute.mkdir(parents=True, exist_ok=True)
    return absolute


# ---------------------------------------------------------------------------
# Configuration loading (optional — only used if --accounts/--regions absent)
# ---------------------------------------------------------------------------

def load_json_config(filename: str) -> Optional[Any]:
    """Load a JSON config file from aws/config/. Returns None if file is absent."""
    config_path = CONFIG_DIR / filename
    if not config_path.exists():
        return None
    with open(config_path, 'r') as f:
        return json.load(f)


def get_all_accounts() -> Optional[list[str]]:
    """Get account IDs from config/accounts.json, or None if file is absent."""
    return load_json_config('accounts.json')


def get_all_regions() -> Optional[list[str]]:
    """Get region names from config/regions.json, or None if file is absent."""
    return load_json_config('regions.json')


def get_identity_stores() -> Optional[list[dict]]:
    """Get Identity Center store configs, or None if config/identity-stores.json is absent."""
    return load_json_config('identity-stores.json')


# ---------------------------------------------------------------------------
# AWS session / role resolution
# ---------------------------------------------------------------------------

def resolve_role(role_arg: Optional[str]) -> Optional[str]:
    """Resolve the IAM role name from --role CLI arg or NSF_AUDIT_ROLE env var."""
    return role_arg or os.environ.get(ENV_ROLE)


def build_session(
    account_id: Optional[str] = None,
    role_name: Optional[str] = None,
    profile: Optional[str] = None,
    session_name: Optional[str] = None,
    region_name: Optional[str] = None,
    external_id: Optional[str] = None,
) -> boto3.Session:
    """
    Build a boto3 session using one of three credential strategies:
      1. If `role_name` is provided, assume `arn:aws:iam::<account_id>:role/<role_name>`
         starting from the profile (if any) or default credentials.
         An `external_id` is forwarded to AssumeRole if provided.
      2. Else if `profile` is provided, return a session for that named profile.
      3. Else return a default session (env vars / EC2 / SSO / shared credentials).
    """
    base_session = boto3.Session(profile_name=profile) if profile else boto3.Session()

    if role_name:
        if not account_id:
            raise ValueError("account_id is required when assuming a role")
        validate_account_id(account_id)
        role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
        sts = base_session.client('sts')
        if session_name is None:
            session_name = f"nsf-audit-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        logger.info("Assuming role: %s (external_id=%s)",
                    role_arn, 'set' if external_id else 'not set')
        assume_kwargs: dict[str, Any] = {
            'RoleArn': role_arn,
            'RoleSessionName': session_name,
        }
        if external_id:
            assume_kwargs['ExternalId'] = external_id
        response = sts.assume_role(**assume_kwargs)
        creds = response['Credentials']
        session = boto3.Session(
            aws_access_key_id=creds['AccessKeyId'],
            aws_secret_access_key=creds['SecretAccessKey'],
            aws_session_token=creds['SessionToken'],
            region_name=region_name,
        )
        identity = session.client('sts').get_caller_identity()
        logger.info("Assumed identity: %s", identity['Arn'])
        return session

    if region_name:
        return boto3.Session(profile_name=profile, region_name=region_name) if profile \
            else boto3.Session(region_name=region_name)
    return base_session


# ---------------------------------------------------------------------------
# Date / filesystem helpers
# ---------------------------------------------------------------------------

def current_date() -> str:
    return datetime.now().strftime('%Y-%m-%d')


def previous_date(days_ago: int = 1) -> str:
    return (datetime.now() - timedelta(days=days_ago)).strftime('%Y-%m-%d')


def ensure_directory(path: str) -> Path:
    dir_path = Path(path)
    dir_path.mkdir(parents=True, exist_ok=True)
    return dir_path


# ---------------------------------------------------------------------------
# Output writers
# ---------------------------------------------------------------------------

def save_csv(file_path: str, rows: list[list[Any]], headers: Optional[list[str]] = None) -> str:
    path = Path(file_path)
    ensure_directory(path.parent)
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        if headers:
            writer.writerow(headers)
        writer.writerows(rows)
    logger.info("Saved CSV: %s (%d rows)", path, len(rows))
    return str(path.absolute())


def save_json(file_path: str, data: Any) -> str:
    path = Path(file_path)
    ensure_directory(path.parent)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, default=str)
    logger.info("Saved JSON: %s", path)
    return str(path.absolute())


def save_yaml(file_path: str, data: Any) -> str:
    path = Path(file_path)
    ensure_directory(path.parent)
    with open(path, 'w', encoding='utf-8') as f:
        yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)
    logger.info("Saved YAML: %s", path)
    return str(path.absolute())


def save_text(
    file_path: str,
    records: list[dict[str, Any]],
    summary: Optional[dict[str, Any]] = None,
    title: Optional[str] = None,
) -> str:
    """Write a human-readable plain-text report."""
    path = Path(file_path)
    ensure_directory(path.parent)
    lines: list[str] = []
    if title:
        lines.append(title)
        lines.append('=' * len(title))
        lines.append('')
    for i, rec in enumerate(records, 1):
        lines.append(f"[{i}]")
        for k, v in rec.items():
            lines.append(f"  {k}: {v}")
        lines.append('')
    if summary:
        lines.append('Summary')
        lines.append('-------')
        for k, v in summary.items():
            lines.append(f"  {k}: {v}")
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')
    logger.info("Saved TEXT: %s", path)
    return str(path.absolute())


def _records_to_rows(
    records: list[dict[str, Any]],
    headers: list[str],
) -> list[list[Any]]:
    """Project dict records to row lists in `headers` order. Lists become '; '-joined strings.

    String fields whose first character would be interpreted as a formula by
    Excel/Google Sheets (`=`, `+`, `-`, `@`, tab, CR) are prefixed with a
    single quote — see CWE-1236.
    """
    rows: list[list[Any]] = []
    for rec in records:
        row: list[Any] = []
        for h in headers:
            v = rec.get(h)
            if isinstance(v, list):
                v = '; '.join(str(x) for x in v) if v else 'None'
            elif isinstance(v, bool):
                v = str(v)
            elif v is None:
                v = ''
            row.append(_neutralize_csv_value(v))
        rows.append(row)
    return rows


def save_results(
    output_dir: str,
    base_name: str,
    records: list[dict[str, Any]],
    summary: dict[str, Any],
    formats: list[str],
    headers: list[str],
    title: Optional[str] = None,
) -> list[str]:
    """
    Emit `records` + `summary` in every requested format.

    Args:
        output_dir: directory to write into
        base_name:  filename stem (e.g. 'nsf1-2026-05-13'); extension is added per format
        records:    list of dicts (one per audited item). Keys should be a superset of `headers`.
        summary:    summary stats dict (included in JSON/YAML/text; ignored by CSV)
        formats:    any of csv, json, yaml, text (case-insensitive, may be a duplicate-free list)
        headers:    CSV column order; also used for stable JSON/YAML field ordering
        title:      optional report title for the text format

    Returns:
        List of absolute file paths written.
    """
    out_dir = resolve_output_dir(output_dir)
    written: list[str] = []
    formats = [f.lower() for f in formats]

    # Embed the toolkit version and a UTC timestamp in the JSON/YAML/text
    # payloads so an auditor can identify which build produced this evidence.
    summary_with_meta = {
        'toolkit_version': __version__,
        'generated_at_utc': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        **summary,
    }

    for fmt in formats:
        if fmt == 'csv':
            rows = _records_to_rows(records, headers)
            written.append(save_csv(str(out_dir / f"{base_name}.csv"), rows, headers))
        elif fmt == 'json':
            payload = {'summary': summary_with_meta, 'records': records}
            written.append(save_json(str(out_dir / f"{base_name}.json"), payload))
        elif fmt == 'yaml':
            payload = {'summary': summary_with_meta, 'records': records}
            written.append(save_yaml(str(out_dir / f"{base_name}.yaml"), payload))
        elif fmt == 'text':
            written.append(save_text(
                str(out_dir / f"{base_name}.txt"), records, summary_with_meta, title=title))
        else:
            logger.warning("Unknown output format '%s', skipping.", fmt)
    return written


# ---------------------------------------------------------------------------
# Argparse helpers
# ---------------------------------------------------------------------------

def parse_formats_arg(formats_arg: Optional[str]) -> list[str]:
    """Parse the --format CLI arg (comma-separated). Validates against SUPPORTED_FORMATS."""
    if not formats_arg:
        return [DEFAULT_FORMAT]
    values = [v.strip().lower() for v in formats_arg.split(',') if v.strip()]
    invalid = [v for v in values if v not in SUPPORTED_FORMATS]
    if invalid:
        raise ValueError(
            f"Unsupported --format value(s): {', '.join(invalid)}. "
            f"Supported: {', '.join(SUPPORTED_FORMATS)}"
        )
    # de-dupe while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for v in values:
        if v not in seen:
            seen.add(v)
            unique.append(v)
    return unique or [DEFAULT_FORMAT]


def parse_accounts_arg(accounts_arg: Optional[str]) -> list[str]:
    """
    Resolve account IDs in priority order:
      1. --accounts CLI arg (comma-separated)
      2. config/accounts.json

    All IDs are validated as 12-digit numeric strings — refuses tampered
    config that could redirect role assumption to an attacker-owned account.
    Raises ValueError on missing or invalid input.
    """
    if accounts_arg:
        raw = [a.strip() for a in accounts_arg.split(',') if a.strip()]
    else:
        cfg = get_all_accounts()
        if not cfg:
            raise ValueError(
                "No accounts specified. Pass --accounts <id,id,...> "
                "or create aws/config/accounts.json"
            )
        raw = list(cfg)

    for acct in raw:
        validate_account_id(acct)
    return raw


def parse_regions_arg(regions_arg: Optional[str]) -> list[str]:
    """
    Resolve regions in priority order:
      1. --regions CLI arg (comma-separated)
      2. config/regions.json
    Raises ValueError if neither is available.
    """
    if regions_arg:
        return [r.strip() for r in regions_arg.split(',') if r.strip()]
    cfg = get_all_regions()
    if cfg:
        return cfg
    raise ValueError(
        "No regions specified. Pass --regions <region,region,...> "
        "or create aws/config/regions.json"
    )


def add_common_arguments(parser) -> None:
    """Add the CLI args common to every NSF audit script."""
    parser.add_argument(
        '--version',
        action='version',
        version=f'%(prog)s (NSF Critical Controls toolkit {__version__})',
        help='Print the toolkit version and exit.',
    )
    parser.add_argument(
        '--accounts',
        help='Comma-separated AWS account IDs (default: config/accounts.json, required if absent)'
    )
    parser.add_argument(
        '--regions',
        help='Comma-separated AWS regions (default: config/regions.json, required if absent)'
    )
    parser.add_argument(
        '--role',
        default=None,
        help=f'IAM role name to assume in each account '
             f'(default: ${ENV_ROLE} env var; if neither is set, uses --profile or default credentials)'
    )
    parser.add_argument(
        '--profile',
        default=None,
        help='Named AWS profile to use (e.g. from ~/.aws/credentials). '
             'Used as the base session before role assumption, or alone if --role is not set.'
    )
    parser.add_argument(
        '--output-dir',
        default='.',
        help='Output directory for reports (default: current directory)'
    )
    parser.add_argument(
        '--format',
        default=DEFAULT_FORMAT,
        help=f'Output format(s), comma-separated. '
             f'Supported: {", ".join(SUPPORTED_FORMATS)}. Default: {DEFAULT_FORMAT}'
    )
    parser.add_argument(
        '--external-id',
        default=None,
        help=f'External ID to pass to sts:AssumeRole '
             f'(default: ${ENV_EXTERNAL_ID} env var). '
             f'Required if the audit role\'s trust policy enforces an ExternalId condition.'
    )
    log_group = parser.add_mutually_exclusive_group()
    log_group.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable DEBUG-level logging (per-API-call detail).'
    )
    log_group.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Suppress INFO logs; only WARNING and above are emitted.'
    )
    parser.add_argument(
        '--log-file',
        default=None,
        help='Write logs to this file instead of stderr.'
    )


# ---------------------------------------------------------------------------
# AuditContext
# ---------------------------------------------------------------------------

class AuditContext:
    """
    Context manager for per-account audit sessions.

    Picks the credential strategy based on which of `role_name` / `profile` are set:
      - role_name + (profile or default creds) -> assume role into account_id
      - profile only                            -> use that named profile
      - neither                                 -> use default credentials

    Usage:
        with AuditContext(account_id, role_name=args.role, profile=args.profile) as ctx:
            ec2 = ctx.client('ec2', region_name='us-east-1')
    """

    def __init__(
        self,
        account_id: str,
        role_name: Optional[str] = None,
        profile: Optional[str] = None,
        session_name: Optional[str] = None,
        external_id: Optional[str] = None,
    ):
        validate_account_id(account_id)
        self.account_id = account_id
        self.role_name = role_name
        self.profile = profile
        self.session_name = session_name
        # External ID falls back to env var so callers don't have to thread it everywhere.
        self.external_id = external_id or os.environ.get(ENV_EXTERNAL_ID)
        self.session: Optional[boto3.Session] = None

    def __enter__(self) -> 'AuditContext':
        self.session = build_session(
            account_id=self.account_id,
            role_name=self.role_name,
            profile=self.profile,
            session_name=self.session_name,
            external_id=self.external_id,
        )
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session = None
        logger.debug("Released session for account %s", self.account_id)
        return False

    def client(self, service_name: str, region_name: Optional[str] = None):
        if self.session is None:
            raise RuntimeError("AuditContext must be used as a context manager")
        return self.session.client(service_name, region_name=region_name)

    def resource(self, service_name: str, region_name: Optional[str] = None):
        if self.session is None:
            raise RuntimeError("AuditContext must be used as a context manager")
        return self.session.resource(service_name, region_name=region_name)


# ---------------------------------------------------------------------------
# Misc legacy helpers retained for compatibility with existing scripts
# ---------------------------------------------------------------------------

def build_role_arn(account_id: str, role_name: str) -> str:
    return f"arn:aws:iam::{account_id}:role/{role_name}"


def load_csv(file_path: str) -> tuple[list[str], list[list[str]]]:
    with open(file_path, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        rows = list(reader)
    if not rows:
        return [], []
    return rows[0], rows[1:]


def load_yaml(file_path: str) -> Any:
    with open(file_path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)


def format_issues(issues: list[str]) -> str:
    return '; '.join(issues) if issues else 'None'


if __name__ == '__main__':
    print("NSF Critical Controls - AWS Common Utilities Module")
    print(f"Config directory:  {CONFIG_DIR}")
    print(f"Accounts (config): {get_all_accounts()}")
    print(f"Regions (config):  {get_all_regions() and len(get_all_regions())}")
    print(f"Identity Stores:   {get_identity_stores()}")
    print(f"Today:             {current_date()}")
