# Contributing

Thanks for your interest in improving the NSF Critical Controls AWS Audit
Toolkit. This document is for people who want to:

- Report a bug or request a feature
- Add an audit for a control that isn't covered yet
- Improve an existing audit (more checks, fewer false positives, better
  error handling)
- Improve the library, tests, or documentation

If you only want to *use* the toolkit, the [README](README.md) is the
right place. Come back here when you want to change the code.

---

## Table of contents

1. [Code of conduct](#code-of-conduct)
2. [Reporting bugs / asking for features](#reporting-bugs--asking-for-features)
3. [Security issues — please don't open a public issue](#security-issues--please-dont-open-a-public-issue)
4. [Development setup](#development-setup)
5. [Project conventions](#project-conventions)
6. [Running the tests](#running-the-tests)
7. [Pull-request checklist](#pull-request-checklist)
8. [Adding a new audit script (step-by-step)](#adding-a-new-audit-script-step-by-step)
9. [Updating IAM policy and trust documents](#updating-iam-policy-and-trust-documents)
10. [Style and tooling](#style-and-tooling)
11. [Release process](#release-process)

---

## Code of conduct

Be kind, be specific, assume good faith. Disagreements get worked out
through the issue and the PR review — not personally. If something feels
off, raise it with the maintainers privately first.

---

## Reporting bugs / asking for features

Open an issue with:

- **What you tried** — the exact command you ran (redact account IDs /
  ARNs / customer names).
- **What you expected.**
- **What actually happened** — copy the relevant log lines, including any
  `NSF-AUDIT-PERMISSION-ERROR` markers.
- **Environment** — `python3 --version`, OS, AWS region(s), whether you
  used `--role` / `--profile` / default credentials.
- **The script's exit code.**

For feature requests, describe the *control* you want better coverage for
and the kind of evidence you want produced (CSV columns, fields, etc.).
Tying the ask back to an NSF control reference (e.g. "AC-2(7) 800-53r5")
makes scoping easier.

---

## Security issues — please don't open a public issue

If you find a vulnerability in the toolkit itself — for example, an audit
script that could be coerced into mutating AWS state, an injection in CSV
output, a leak of credentials in logs — **do not file a public issue**.
Email the maintainers (security@safeinsights.org) with:

- A clear description of the issue
- The smallest reproducer you can produce
- Whether you intend to disclose it publicly and a reasonable timeline

We will respond within five business days, work on a fix, and credit you
in the changelog if you'd like.

The toolkit ships read-only AWS permissions on purpose (see
[aws/policy/nsf-audit-policy.json](aws/policy/nsf-audit-policy.json)).
Reports of "the script could be modified to do X" are not vulnerabilities
— a malicious fork can do anything. The security-relevant surface is what
the *upstream* code does when run with the documented IAM policy.

---

## Development setup

You need Python 3.10+. The exact steps mirror the operator setup in
[README §4](README.md#4-installation-walkthrough), with two extra packages:

```bash
git clone https://github.com/SafeInsights/nsf-critical-controls-set.git
cd nsf-critical-controls-set/aws
python3 -m venv venv
. venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
```

Confirm the suite passes before you change anything:

```bash
python3 -m pytest
```

You should see `207 passed` (or higher if tests have been added).

---

## Project conventions

These are the rules the existing code follows. New code should follow
them too. Most are mechanically enforced by the tests; the rest are
reviewer judgment calls.

### 1. Every audit is a standalone script

`aws/audits/nsfN.py` is invocable directly:

```bash
python3 aws/audits/nsfN.py --accounts 123456789012 --regions us-east-1
```

No `python -m`, no setup.py, no installable package. Drop-in
deployability is a feature, not an accident.

### 2. Use the shared library, don't reinvent

`aws/lib/aws_common.py` is the only place that knows about:

- Session / role assumption (`AuditContext`, `build_session`)
- Config loading (`parse_accounts_arg`, `parse_regions_arg`,
  `parse_formats_arg`)
- Output writers (`save_results` dispatches to CSV / JSON / YAML / text)
- Logging (`configure_logging`, `get_logger`)
- Permission-error classification (`is_permission_error`,
  `warn_permission_error`, `permission_failure_count`)
- CSV formula-injection neutralization
- Output-dir symlink rejection
- 12-digit account-ID validation

If you find yourself writing one of those in an audit script, stop —
add or extend a helper in `aws_common.py` and import it.

### 3. Logging, not print()

```python
from lib.aws_common import get_logger
logger = get_logger('nsfN')  # child of 'nsf_audit'

logger.info("Auditing account: %s", account_id)
logger.debug("Inspecting region %s", region)
logger.warning("Error inventorying VPN endpoints in %s: %s", region, e)
```

`print()` is reserved for the operator-facing audit summary banner at the
end of a run (stdout). Everything else goes to stderr via the logger.

**Use `%s` formatting in log calls**, never f-strings. The pre-1.0 review
caught 45 lines where `{region}` was an f-string-style placeholder that
never got substituted — don't reintroduce that bug.

### 4. Permission errors must be loud

Never silently swallow `AccessDenied`, `ExpiredToken`,
`UnauthorizedOperation`, or related codes. Use the helper:

```python
try:
    iam.list_users()
except Exception as e:
    if not warn_permission_error('iam:ListUsers', e):
        # non-permission failure (Throttling, NoSuchEntity, parse error…)
        logger.warning("Non-permission error during iam:ListUsers: %s", e)
```

The helper logs with the `NSF-AUDIT-PERMISSION-ERROR` marker and
increments a process-wide counter. Audit scripts MUST exit non-zero when
`permission_failure_count() > 0`, even if no other "non-compliant"
finding was recorded:

```python
return 1 if summary['non_compliant'] > 0 or permission_failure_count() > 0 else 0
```

If a per-record evidence column makes more sense (nsf1's `AuditErrors`
column is the canonical example), use that *in addition*.

### 5. Output is structured, not stringified

Build a `list[dict]` of records and call `save_results(...)`. Don't
hand-roll CSV writing. The dispatcher handles all four formats, embeds
toolkit version / timestamp in the summary, and neutralizes CSV formula
injection.

```python
headers = ['AccountId', 'ResourceId', 'Compliant', 'Issues']
records = [
    {'AccountId': '...', 'ResourceId': '...', 'Compliant': True, 'Issues': []},
    ...
]
summary = {'total': len(records), 'non_compliant': N}
written = save_results(
    output_dir, f'nsfN-{current_date()}', records, summary,
    parse_formats_arg(args.format), headers,
    title="NSFN Audit",
)
```

### 6. Comments only when the WHY isn't obvious

Don't narrate the *what* — the code is right there. Comment only when:

- A subtle invariant would surprise the next reader.
- A workaround exists for a documented AWS quirk (e.g. why nsf9 dedups
  CloudTrail trails by home region).
- A change is gated on a constraint that isn't visible locally (e.g.
  S3 ListBuckets being global, which is why nsf6/7/9 emit the
  "missing us-east-1" warning).

No `# Step 1`, `# Step 2`, `# TODO: figure this out later`.

### 7. Tests must pass

Run `python3 -m pytest` before sending a PR. The full suite is fast
(<1 second). If you change a public helper in `aws_common.py`, add or
update a test in `tests/test_aws_common.py`. If you add a new audit,
the smoke tests in `tests/test_audits_smoke.py` will pick it up
automatically — but consider adding a focused test like
`tests/test_nsf1_integration.py` if the audit has non-trivial logic.

---

## Running the tests

```bash
# Full suite
python3 -m pytest

# Focused — one file
python3 -m pytest tests/test_aws_common.py

# Focused — one keyword
python3 -m pytest -k 'permission_error'

# Verbose
python3 -m pytest -v

# With coverage (install coverage first: pip install coverage)
python3 -m coverage run -m pytest && python3 -m coverage report
```

The tests never contact AWS. They use stub IAM clients and mocked boto3
sessions. If you find yourself wanting to write a test that does, stop
and refactor — the boundary should be the boto3 client, not the network.

---

## Pull-request checklist

Before requesting review, please confirm:

- [ ] `python3 -m pytest` passes (207+ tests).
- [ ] Every audit script you touched still imports and `--help`-renders:
      `for f in audits/nsf*.py; do python3 $f --help > /dev/null; done`
- [ ] No `print()` calls added outside the audit summary banner.
- [ ] No `except Exception: pass` silent swallow of AWS errors. Use
      `warn_permission_error()` + an `else` branch.
- [ ] If you added an AWS API call, the corresponding action is in
      `aws/policy/nsf-audit-policy.json`. (See
      [§9](#updating-iam-policy-and-trust-documents).)
- [ ] No real account IDs / ARNs / customer names in tests, docs, or
      commit messages.
- [ ] README updated if a flag, output column, or behavior changed.
- [ ] CHANGELOG entry (if `CHANGELOG.md` exists by the time you read this).
- [ ] Commit message in active voice, present tense, ≤72 chars first line.

---

## Adding a new audit script (step-by-step)

Say you want to add `nsfN.py` for a new control. Use an existing script
as a starting point — `nsf4.py` (regional, multi-service) or `nsf3.py`
(IAM-only, global) are good templates depending on scope.

### Step 1 — Copy a template

```bash
cp aws/audits/nsf4.py aws/audits/nsfN.py
```

### Step 2 — Rewrite the module docstring

Top of the file: explain *what* the control requires, the relevant NIST
800-53 / 800-171 reference, and *exactly* what your script checks. The
operator and the auditor both read this — be precise.

### Step 3 — Set the logger namespace

```python
logger = get_logger('nsfN')   # child of nsf_audit
```

The smoke test enforces this.

### Step 4 — Write the audit functions

Each AWS service you inspect should have its own `audit_<service>(client,
account_id, region) -> list[dict]` function. Catch permission errors with
`warn_permission_error`; surface non-permission errors with
`logger.warning`. Return a list of record dicts that share a set of keys
you'll declare as `headers` later.

### Step 5 — `run_audit(args)` glue

Iterate accounts × regions inside `AuditContext`, call each audit
function, accumulate records and summary stats, then:

```python
headers = ['AccountId', 'Region', 'ResourceId', 'Compliant', 'Issues', ...]
records = [...]
summary = {'total': N, 'compliant': X, 'non_compliant': Y}
written = save_results(
    args.output_dir, f'nsfN-{current_date()}', records, summary,
    parse_formats_arg(args.format), headers, title='NSFN Audit',
)
return written, summary
```

### Step 6 — `main()`

```python
def main():
    parser = argparse.ArgumentParser(
        description='NSFN: <one-line description>',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --accounts 123456789012 --regions us-east-1
  %(prog)s --format json,csv --output-dir ./reports

Compliance Criteria:
  - <bullet>
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
```

**Watch out for `%` characters in the epilog** — argparse treats them as
format placeholders. Escape literal percent signs as `%%`.

### Step 7 — Add the Jenkinsfile

```bash
cp aws/pipelines/nsf4.Jenkinsfile aws/pipelines/nsfN.Jenkinsfile
$EDITOR aws/pipelines/nsfN.Jenkinsfile
```

Update the stage name, the cron expression (stagger it from existing
audits — see existing Jenkinsfiles for the pattern), the audit-script
name, and the failure-email subject/body. The `environment{}` block at
the top is already parameterized.

### Step 8 — Update the IAM policy

Every new boto3 call needs a matching action in
[aws/policy/nsf-audit-policy.json](aws/policy/nsf-audit-policy.json). The
action must be read-only (`Get*` / `List*` / `Describe*` /
`BatchGet*`). No `Put*`, no `iam:PassRole`, no `kms:Decrypt`. If you find
yourself needing a non-read action, your design is probably wrong —
audits read, they don't mutate.

### Step 9 — Update docs

- README §2 controls table: add the new row.
- README §8 ("The controls explained"): add the script's row with a
  plain-English "what compliant looks like".
- If the audit only partially covers the control, add a Scope Caveat in
  the same section (see NSF4, NSF5, NSF8, NSF12, NSF13 for patterns).

### Step 10 — Tests

The smoke tests automatically pick up the new script and verify import,
`main()`, logger namespace, `--help`, common args, and `--version`.
Consider adding a focused integration test like
`tests/test_nsfN_integration.py` if your audit has non-trivial
classification logic (see `test_nsf1_integration.py` for the pattern —
fake boto3 client, no real AWS calls).

### Step 11 — Run the full suite

```bash
python3 -m pytest
python3 aws/audits/nsfN.py --help
python3 aws/audits/nsfN.py --version
```

Done. Open a PR.

---

## Updating IAM policy and trust documents

Two files live in [aws/policy/](aws/policy/):

- `nsf-audit-policy.json` — what the audit role can do. Every boto3
  action the scripts call must be granted here. The action list is
  hand-extracted; when adding a new API call:

  1. Note the boto3 method name (e.g. `inspector_client.list_findings`).
  2. Look up the matching IAM action (e.g. `inspector2:ListFindings`).
  3. Add it to the appropriate `Sid` block in the policy.
  4. Confirm with the AWS docs that it's a read-only action.

- `nsf-audit-trust-policy.json` — who can assume the audit role. The
  template uses three placeholders (`REPLACE_AUDIT_PRINCIPAL_ACCOUNT_ID`,
  `REPLACE_AUDIT_PRINCIPAL_ROLE_NAME`, `REPLACE_EXTERNAL_ID`) and ships
  the recommended baseline: specific role ARN + external ID condition.
  Do not relax this without a documented reason in your PR description.

Both files have a sub-README at [aws/policy/README.md](aws/policy/README.md)
— keep it in sync if you change the policy structure.

---

## Style and tooling

The codebase doesn't run a formatter on save, but the existing style is:

- Standard library + `boto3` + `pyyaml` only. No new runtime dependencies
  without a discussion.
- Type hints on public function signatures. `dict[str, Any]` is fine for
  AWS response dicts; introduce TypedDicts only if a structure is
  reused across many functions.
- 4-space indentation, ~88-char soft line limit.
- Single-quoted strings unless the literal contains a single quote.
- One-blank-line separator between functions; two blanks between top-level
  blocks.
- `from lib.aws_common import (...)` imports are alphabetized.

If you want to run a linter / formatter locally, `ruff format` and
`ruff check` produce results consistent with the existing code.

---

## Release process

This section is mostly for maintainers.

1. Bump `__version__` in `aws/lib/aws_common.py`.
2. Update `CHANGELOG.md` (if present) with the date and summary.
3. Run `python3 -m pytest` — must pass.
4. Run every `nsfN.py --help` and `nsfN.py --version` — must succeed.
5. Tag the release: `git tag vX.Y.Z && git push --tags`.
6. Cut a GitHub Release from the tag, including the CHANGELOG entry as
   the description.

Versioning follows [semver](https://semver.org/):

- **Major** — IAM policy or output schema breaks; existing reports may
  not parse cleanly with the new build. Required after a removed CLI
  flag or a renamed CSV column.
- **Minor** — new audit script, new flag, new optional output. No
  breaking changes to existing reports or IAM permissions.
- **Patch** — bug fix, doc fix, dependency bump.

The toolkit version is embedded in every JSON/YAML/text report
(`summary.toolkit_version`) so an auditor can match evidence back to a
specific build.

---

Thanks for contributing.
