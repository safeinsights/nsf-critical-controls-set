# NSF Critical Control Set — AWS Audit Toolkit

Python scripts that collect evidence from your AWS accounts to show how
well you meet each of the
[NSF Critical Controls](https://nsf-gov-resources.nsf.gov/files/Research-Infrastructure-Guide-January-2025.pdf), section 5.3.6, page 308. One script per
control. Each script logs into AWS (read-only), inspects the relevant
services, and writes a report you can hand to an auditor.

> **TL;DR for the experienced user**
>
> ```bash
> cd aws
> python3 -m venv venv && . venv/bin/activate
> pip install -r requirements.txt
> python3 audits/nsf1.py --accounts 123456789012 --regions us-east-1
> ```
>
> Reports land in the current directory as `nsf1-YYYY-MM-DD.csv`. Read on
> for setup, AWS credentials, troubleshooting, and what each report means.

---

## Table of contents

1. [What this does, in plain English](#1-what-this-does-in-plain-english)
2. [The controls explained](#2-the-controls-explained)
3. [Glossary — terms you'll see](#3-glossary--terms-youll-see)
4. [Before you start (prerequisites)](#4-before-you-start-prerequisites)
5. [Installation walkthrough](#5-installation-walkthrough)
6. [Setting up AWS access](#6-setting-up-aws-access)
7. [Running your first audit](#7-running-your-first-audit)
8. [Understanding the report](#8-understanding-the-report)
9. [Configuration files](#9-configuration-files)
10. [Output formats](#10-output-formats)
11. [Logging and verbosity](#11-logging-and-verbosity)
12. [Troubleshooting common errors](#12-troubleshooting-common-errors)
13. [Scheduling with Jenkins (or other CI)](#13-scheduling-with-jenkins-or-other-ci)
14. [Uploading reports elsewhere](#14-uploading-reports-elsewhere)
15. [Evidence integrity guarantees](#15-evidence-integrity-guarantees)
16. [Required IAM permissions](#16-required-iam-permissions)
17. [Running the test suite](#17-running-the-test-suite)
18. [CLI reference (all flags)](#18-cli-reference-all-flags)
19. [Frequently asked questions](#19-frequently-asked-questions)

---

## 1. What this does, in plain English

The U.S. National Science Foundation publishes a set of "Critical Controls"
that funded research infrastructure is expected to meet — things like
"administrators must use phishing-resistant multi-factor authentication"
and "backups must be tamper-proof". Most of those controls can be partially
verified by inspecting what you have configured in AWS.

This toolkit is **13 Python scripts**, one per control, that automate that
inspection. Each script:

1. Logs into your AWS account using credentials you provide.
2. Reads (never writes) the AWS configuration that matters for its control
   — for example, `nsf1.py` reads your IAM users and their MFA devices.
3. Decides for each finding whether it's compliant, non-compliant, or
   couldn't be determined.
4. Writes a report file (CSV by default; JSON / YAML / plain text on
   request).

You give the reports to your auditor as evidence. You also use the reports
yourself to find and fix non-compliant resources.

**The scripts never change anything in AWS.** They only read. The included
IAM policy ([aws/policy/nsf-audit-policy.json](aws/policy/nsf-audit-policy.json))
contains nothing but `Get*`, `List*`, and `Describe*` actions.

---

## 2. The controls explained

Each script audits one NSF Critical Control. Click the script link to read
its docstring and code.

| # | Script | What it checks | What "compliant" looks like |
|---|---|---|---|
| 1 | [nsf1.py](aws/audits/nsf1.py) | Privileged-account MFA | Every IAM user with admin-grade policies has a FIDO2 / hardware MFA device. |
| 2 | [nsf2.py](aws/audits/nsf2.py) | Remote-access MFA | Client VPN, WorkSpaces, and remote-access IAM policies require MFA. |
| 3 | [nsf3.py](aws/audits/nsf3.py) | Limited admin scope | No IAM users / roles have unbounded `*:*` admin permissions outside dedicated admin accounts. |
| 4 | [nsf4.py](aws/audits/nsf4.py) | Anti-malware deployed **(AWS-only — see note)** | GuardDuty + Security Hub enabled across regions; EC2 instances are SSM-managed (can receive AV). |
| 5 | [nsf5.py](aws/audits/nsf5.py) | EDR functionality **(AWS-only — see note)** | GuardDuty Runtime Monitoring is enabled for EC2 / ECS / EKS. |
| 6 | [nsf6.py](aws/audits/nsf6.py) | Immutable system backups | AWS Backup vaults have vault-lock; backup S3 buckets have Object Lock + WORM. |
| 7 | [nsf7.py](aws/audits/nsf7.py) | Immutable research-data backups | S3 buckets tagged as research data have versioning, Object Lock, and lifecycle rules preventing early deletion. |
| 8 | [nsf8.py](aws/audits/nsf8.py) | Backup integrity testing **(partial — see note)** | AWS Backup has a successful restore job per vault within the past year. |
| 9 | [nsf9.py](aws/audits/nsf9.py) | Log collection | CloudTrail multi-region trail with CloudWatch Logs integration; VPC Flow Logs on every VPC; log retention ≥ 365 days. |
| 10 | [nsf10.py](aws/audits/nsf10.py) | Network segmentation | No default-VPC use; security groups don't allow `0.0.0.0/0`; subnets are properly public/private. |
| 11 | [nsf11.py](aws/audits/nsf11.py) | CI inventory | VPN endpoints, Transit Gateways, Direct Connect, DNS zones, IAM resources are all tagged and discoverable. |
| 12 | [nsf12.py](aws/audits/nsf12.py) | Vulnerability mgmt **(partial)** | Inspector v2 enabled; Security Hub high/critical findings count; SSM Patch Manager compliance. |
| 13 | [nsf13.py](aws/audits/nsf13.py) | Hardening standards **(AWS-only)** | AWS Config recording all resource types with rules + conformance packs; Security Hub CIS / AWS-Foundational standards enabled; SSM State Manager associations exist. |

### Scope caveats (read this before drawing conclusions)

**NSF4 (Anti-malware deployed)** — `nsf4.py` only checks AWS-native
signal: GuardDuty enablement (incl. Malware Protection for EC2),
Security Hub enablement, and whether EC2 instances are registered with
Systems Manager (a prerequisite for centrally deploying any AV agent).
It does **not** know whether a third-party endpoint protection product
(CrowdStrike, SentinelOne, Microsoft Defender, ClamAV, etc.) is actually
installed and running on each host. If you rely on a third-party AV /
EDR, pull that coverage report from the vendor's console (or your MDM /
SCCM / Intune inventory) and combine it with this script's output for a
complete picture. Hosts outside AWS (developer laptops, on-prem
research equipment, lab instrumentation) are out of scope here and must
be reported from their own management systems.

**NSF5 (EDR functionality)** — `nsf5.py` only checks AWS-native EDR
signal: GuardDuty Runtime Monitoring coverage for EC2, ECS, and EKS,
plus RDS / Lambda protection. It does **not** know whether a third-party
EDR agent (CrowdStrike Falcon, SentinelOne, Microsoft Defender for
Endpoint, Carbon Black, Elastic Defend, etc.) is installed and reporting
on each host. If your endpoint detection-and-response strategy depends
on a vendor EDR, pull the coverage / health report from that vendor's
console and combine it with this script's output. Hosts outside AWS
(developer laptops, on-prem research equipment, instrument workstations)
are out of scope here and must be reported from their own management
systems.

**NSF8 (Backup integrity testing)** — `nsf8.py` only verifies that AWS
Backup has *executed* a restore job per vault within the past year and
that the job reported success. AWS reports "success" the moment the
restore operation finishes — it does **not** confirm that the restored
data is usable. A complete integrity test must *also* include a manual or
scripted step that proves the restored copy is functional: opening the
database, comparing checksums against the original, walking a sample of
files, running an application against the recovered volume, etc. Keep a
log of those manual verification steps and pair them with the report
this script produces. Backups for systems and data **not** managed by
AWS Backup (e.g. third-party SaaS exports, on-premises tape, Snowflake
exports) are out of scope here and must be tested separately.

**NSF12 (Vulnerability management)** — `nsf12.py` only covers AWS-native
signal. A complete vulnerability-management program must *also* include
scans of any software you build or operate: SAST/DAST on applications,
SCA / dependency scanning, container image scanning, and penetration
testing. Pull that evidence from your CI / SCA / registry / pen-test
tooling — it isn't in AWS to read.

**NSF13 (Hardening / secure configuration)** — `nsf13.py` only audits
AWS-side hardening. Hardening of operating systems, endpoints, containers,
network appliances, SaaS configuration, and any non-AWS infrastructure is
out of scope. Collect that evidence from CIS-CAT, OpenSCAP,
Ansible/Chef/Puppet compliance, MDM, etc.

**NSF14** (Incident Response Plan + annual tabletop) is a
documentation/process control with no meaningful AWS-API signal and is
intentionally not automated. You need to maintain the IR Plan document and
the tabletop exercise records by hand.

---

## 3. Glossary — terms you'll see

If any of these are unfamiliar, the rest of this README will make a lot more
sense after a quick read of this section.

| Term | What it means here |
|---|---|
| **AWS account** | A separate AWS bill / login. Has a 12-digit numeric ID like `123456789012`. Most organizations have several (production, staging, sandbox, …). |
| **Region** | A geographic location where AWS runs your stuff — e.g. `us-east-1` (Virginia), `us-west-2` (Oregon). Many services are per-region; the scripts loop over the regions you care about. |
| **IAM** | "Identity and Access Management". The AWS service that controls *who* can do *what*. |
| **IAM role** | A named bundle of permissions that other things (a person, a server, a script, another AWS account) can *temporarily assume*. The audit role is the role this toolkit uses while running. |
| **Assume role** | The act of asking AWS for short-lived credentials that grant you a specific role's permissions. The scripts do this once per AWS account. |
| **IAM policy** | A JSON document that lists allowed (or denied) AWS actions. Two flavors here: a **permissions policy** says what the role can *do*; a **trust policy** says who can *become* the role. |
| **MFA** | Multi-factor authentication. Phishing-resistant MFA = FIDO2/WebAuthn keys (YubiKey, etc.) or hardware OTP tokens. Virtual MFA apps (Google Authenticator, Authy) are *not* phishing-resistant. |
| **External ID** | An extra secret string the assume-role caller must present. Recommended baseline for trust policies — defeats the "confused deputy" risk. |
| **AWS profile** | A named set of credentials in your `~/.aws/credentials` file. Useful if you switch between multiple AWS environments. |
| **CloudTrail / GuardDuty / Inspector / Security Hub / AWS Config** | AWS services this toolkit reads from. You don't have to enable all of them, but where they are enabled they provide evidence for several controls. |
| **CSV** | Comma-Separated Values — the default report format. Opens in Excel / Google Sheets. |
| **CI / Jenkins** | "Continuous Integration" — a server that runs scripts on a schedule. The toolkit ships Jenkinsfiles so you can run audits nightly. |

---

## 4. Before you start (prerequisites)

You'll need:

- **A computer running macOS, Linux, or Windows (WSL).** The scripts haven't
  been tested on native Windows PowerShell but should work; WSL is safer.
- **Python 3.10 or newer.** Check with `python3 --version`. If you don't
  have it, install from [python.org](https://www.python.org/downloads/) or
  via your package manager (`brew install python3` / `apt install python3`).
- **Internet access** to download Python packages and to talk to AWS.
- **AWS read access** to whichever accounts you want to audit (see
  [§6 Setting up AWS access](#6-setting-up-aws-access)).
- **About 30 minutes** for first-time setup, then ~1 minute per audit run
  thereafter.

You do **not** need to be a developer, but you should be comfortable with:

- Opening a terminal / command prompt.
- Copy-pasting commands.
- Editing a text file.

---

## 5. Installation walkthrough

### 5a. Open a terminal in the project folder

Wherever you cloned this repo, change into the `nsf-critical-control-set`
directory:

```bash
cd path/to/nsf-critical-control-set
```

### 5b. Create a Python virtual environment

A *virtual environment* keeps the toolkit's Python packages separate from
the rest of your system. Run this once:

```bash
cd aws
python3 -m venv venv
```

That creates a folder called `venv/` inside `aws/`.

### 5c. Activate the virtual environment

You need to do this **every time** you open a new terminal:

```bash
# macOS / Linux
. venv/bin/activate

# Windows PowerShell
.\venv\Scripts\Activate.ps1
```

Your prompt will gain a `(venv)` prefix. That tells you the right Python
is active.

### 5d. Install the dependencies

```bash
pip install -r requirements.txt
```

This installs `boto3` (AWS SDK) and `pyyaml` (YAML support). Should take
under a minute.

### 5e. Sanity check

```bash
python3 audits/nsf1.py --help
```

You should see a help screen listing flags like `--accounts` and
`--regions`. If you get a `ModuleNotFoundError`, step 4d didn't run inside
the activated venv — re-do step 4c, then 4d.

You're done with installation.

---

## 6. Setting up AWS access

The scripts need to read your AWS configuration. There are three ways to
give them access, in order of recommendation:

### 6a. Recommended: a dedicated read-only audit role (production)

This is the right setup for any recurring / unattended audit (Jenkins, cron).

1. In **each** AWS account you want to audit, create an IAM role named
   `NSF-AuditReadOnly` (any name works — this is the example).
2. Attach the permissions policy at
   [aws/policy/nsf-audit-policy.json](aws/policy/nsf-audit-policy.json) to
   that role.
3. Set the role's trust policy so that the principal who runs the audit
   (a person, an EC2 instance, or a Jenkins server) is allowed to *assume*
   the role. Use [aws/policy/nsf-audit-trust-policy.json](aws/policy/nsf-audit-trust-policy.json)
   as a template — replace the three placeholders.
4. Read [aws/policy/README.md](aws/policy/README.md) for the exact
   `aws iam create-role` / `aws iam put-role-policy` commands.

Then run the scripts with `--role NSF-AuditReadOnly` (and, if your trust
policy requires it, `--external-id <secret>`).

### 6b. Simpler: an AWS named profile (workstation)

If you already use the AWS CLI and have profiles configured in
`~/.aws/credentials` / `~/.aws/config`, you can point the scripts at one:

```bash
python3 audits/nsf1.py --profile my-audit-profile --accounts 123456789012 --regions us-east-1
```

Don't have profiles yet? Run `aws configure` (from the AWS CLI) and follow
the prompts. AWS provides
[a guide here](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html).

### 6c. Simplest (one-off): export AWS credentials in your shell

If you have temporary AWS credentials (from SSO or `aws sts assume-role`),
export them and run with no `--role` / `--profile` flag:

```bash
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...      # if temporary credentials
python3 audits/nsf1.py --accounts 123456789012 --regions us-east-1
```

### Which credential method does the script actually use?

The script picks one strategy per AWS account, in this priority order:

1. **Assume a role** — if `--role` (or the `NSF_AUDIT_ROLE` environment
   variable) is set, the script calls AWS STS and assumes that role into
   each account. This is what you want for production.
2. **Named profile** — if only `--profile` is set, that profile's
   credentials are used directly. The script does **not** call AWS STS in
   this mode; it expects the profile to already grant the needed
   read-only permissions.
3. **Default credentials** — if neither is set, boto3's default credential
   chain runs (environment variables → shared credentials → EC2 instance
   role → SSO).

---

## 7. Running your first audit

Let's run `nsf1.py` — the simplest audit (it only reads IAM, which is a
global service, so no `--regions` is required).

### 7a. Make sure your credentials are working

```bash
aws sts get-caller-identity
```

You should see your account ID and a user/role ARN. If you get an error,
your AWS credentials aren't set up — go back to [§6](#6-setting-up-aws-access).

### 7b. Run the audit

If you have a single AWS account and are using your default credentials:

```bash
python3 audits/nsf1.py --accounts 123456789012
```

Replace `123456789012` with your real account ID (12 digits).

### 7c. Read the output

While the script runs you'll see log lines on stderr:

```
2026-05-13T12:00:00-0500 [INFO   ] nsf_audit.nsf1: NSF1 audit starting: Phishing-resistant MFA for Privileged Accounts
2026-05-13T12:00:00-0500 [INFO   ] nsf_audit.nsf1: Date=2026-05-13 accounts=1 role=None
2026-05-13T12:00:00-0500 [INFO   ] nsf_audit.nsf1: Auditing account: 123456789012
2026-05-13T12:00:02-0500 [INFO   ] nsf_audit.nsf1: Audited 12 users in account 123456789012
2026-05-13T12:00:02-0500 [INFO   ] nsf_audit: Saved CSV: /…/nsf1-2026-05-13.csv (13 rows)
```

Then a summary on stdout:

```
======================================================================
NSF1 AUDIT SUMMARY
======================================================================
Total Users Scanned:     13
Privileged Users:        4
Compliant:               3
Non-Compliant:           1

Reports saved:
  /path/to/cwd/nsf1-2026-05-13.csv
```

A report file `nsf1-2026-05-13.csv` is now in your current directory. Open
it in Excel, Numbers, or Google Sheets.

### 7d. The script's exit code

The script returns an exit code so you (or CI) can tell whether the audit
"passed":

| Exit code | Meaning |
|---|---|
| `0` | All audited resources are compliant. |
| `1` | One or more non-compliant findings **OR** one or more permission errors during the run (see [§15](#15-evidence-integrity-guarantees)). |
| `130` | You hit Ctrl+C. |

In CI, treat non-zero as "review the report".

---

## 8. Understanding the report

Each report is a flat table. Columns vary by control, but the last three
are always:

- **Compliant** — `True` if this resource meets the control's bar, `False`
  otherwise.
- **Issues** — short text describing *why* the resource is non-compliant
  (e.g. "Privileged user without MFA").
- **AuditErrors** (some scripts) — populated when the script couldn't read
  what it needed to (typically AWS returned AccessDenied). Any non-empty
  value here means *you can't trust the Compliant column for this row* —
  fix the IAM permissions and re-run.

### Example: `nsf1-2026-05-13.csv`

| AccountId | UserName | UserArn | IsPrivileged | PrivilegedPolicies | MFAEnabled | MFAType | PhishingResistant | Compliant | Issues | AuditErrors |
|---|---|---|---|---|---|---|---|---|---|---|
| 123456789012 | `<root_account>` | arn:...:root | True | Root Account (full access) | True | Unknown (root) | False | True | None | None |
| 123456789012 | alice | arn:...:user/alice | True | AdministratorAccess | True | FIDO2/U2F | True | True | None | None |
| 123456789012 | bob | arn:...:user/bob | True | AdministratorAccess | True | Virtual (TOTP) | False | False | Privileged user with non-phishing-resistant MFA (Virtual (TOTP)) | None |
| 123456789012 | carol | arn:...:user/carol | False | None | False | None | False | True | None | None |

How to read this:
- **alice** (admin with a YubiKey) — compliant.
- **bob** (admin with only Google Authenticator) — *non-compliant*; you
  need to issue bob a hardware key.
- **carol** (regular user without MFA) — compliant for *this* control;
  this control only governs *privileged* users.
- **root account** — has MFA enabled. AWS doesn't expose the MFA type for
  the root account, so the script can only confirm "MFA on/off", not
  whether it's phishing-resistant. You should manually verify the root
  account uses a hardware key.

---


## 9. Configuration files

Three optional JSON files in [aws/config/](aws/config/) let you avoid
passing the same flags every time. Two ship as `*.example.json`
templates — copy them to the real names and edit before use.

| File | Content | Used by |
|---|---|---|
| `accounts.json` (template: `accounts.example.json`) | JSON list of 12-digit account ID strings — **your** accounts | All scripts when `--accounts` is omitted |
| `regions.json` | JSON list of region names | Region-scoped scripts when `--regions` is omitted |
| `identity-stores.json` (template: `identity-stores.example.json`) | List of `{ "account": "...", "region": "...", "identityStoreId": "..." }` objects | Audits that walk AWS Identity Center |

**To use them:**

```bash
cp aws/config/accounts.example.json aws/config/accounts.json
$EDITOR aws/config/accounts.json    # replace placeholders with your real account IDs
```

`accounts.json` and `identity-stores.json` are gitignored so your
customised copies don't get committed (only the templates are tracked).
`regions.json` ships as a full catalog of AWS regions and can be edited
or pruned in place.

If a file is missing and you don't pass the matching flag, the script
fails with a clear error telling you what to do. This is deliberate: no
silent default means the audit can never accidentally run against a
placeholder account ID.

Account IDs are validated as `^[0-9]{12}$` — non-numeric or wrong-length
values are refused (so a tampered config can't redirect a role assumption
to a malformed account).

---

## 10. Output formats

Every script accepts `--format`, comma-separated. Files are written to
`<output-dir>/nsfN-YYYY-MM-DD.<ext>`.

| Format | Extension | Best for |
|---|---|---|
| `csv` (default) | `.csv` | Auditors. Opens in Excel / Sheets. CSV formula-injection is neutralized (CWE-1236). |
| `json` | `.json` | Downstream tools / dashboards. Shape: `{ "summary": {...}, "records": [...] }`. |
| `yaml` | `.yaml` | Same shape as JSON, human-readable. |
| `text` | `.txt` | Quick eyeballing in a terminal. Includes summary at the end. |

**Multiple formats in one run:**

```bash
python3 audits/nsf1.py --accounts 123456789012 --format csv,json,yaml
# produces nsf1-2026-05-13.csv, .json, .yaml
```

---

## 11. Logging and verbosity

All scripts log via Python's standard `logging` module under the
`nsf_audit` namespace. Per-script child loggers (`nsf_audit.nsf1`, …)
identify which script emitted each line. **Logs go to stderr; the audit
summary banner stays on stdout** so you can pipe them separately.

Default format:

```
2026-05-13T12:00:00-0500 [INFO   ] nsf_audit.nsf1: Auditing account: 123456789012
2026-05-13T12:00:01-0500 [ERROR  ] nsf_audit.nsf4: NSF-AUDIT-PERMISSION-ERROR ListDetectors: AccessDenied: …
```

Permission errors are tagged with the stable prefix
**`NSF-AUDIT-PERMISSION-ERROR`** — grep that string in CI logs to find the
most operationally important events.

CLI flags:

| Flag | Effect |
|---|---|
| `-v` / `--verbose` | DEBUG level (per-region, per-resource detail). Mutually exclusive with `--quiet`. |
| `-q` / `--quiet` | Only WARNING and above. |
| `--log-file PATH` | Write logs to PATH instead of stderr. Useful for unattended runs. |

```bash
# Verbose run, with logs written to a file
python3 audits/nsf12.py --accounts 123456789012 --regions us-east-1 \
    --verbose --log-file /tmp/nsf12.log
```

---

## 12. Troubleshooting common errors

### `ModuleNotFoundError: No module named 'boto3'`

Your virtual environment isn't activated, or `pip install -r requirements.txt`
hasn't run. Redo [§5c–5d](#5c-activate-the-virtual-environment).

### `botocore.exceptions.NoCredentialsError: Unable to locate credentials`

The script couldn't find any AWS credentials. Check
[§6](#6-setting-up-aws-access) — pass `--profile`, set `AWS_ACCESS_KEY_ID`/
`AWS_SECRET_ACCESS_KEY`, or run inside something that grants credentials
automatically (EC2 instance role, SSO session).

Verify with `aws sts get-caller-identity` *before* running the audit.

### `botocore.exceptions.ClientError: An error occurred (AccessDenied) when calling the AssumeRole operation`

The principal you're running as isn't allowed to assume the audit role in
the target account. Check the audit role's **trust policy** in that
account ([aws/policy/nsf-audit-trust-policy.json](aws/policy/nsf-audit-trust-policy.json)):

- Does the `Principal.AWS` match the role/user/account running the audit?
- If a `Condition: StringEquals: sts:ExternalId` is set, are you passing
  `--external-id` (or `AWS_EXTERNAL_ID`) with the matching value?

### Many `NSF-AUDIT-PERMISSION-ERROR` lines in the log

The audit role lacks one or more read permissions. The most common cause
is using a role with `ViewOnlyAccess` for NSF12/13 — those need extra
read access (Inspector v2, Security Hub, AWS Config). Re-attach
[aws/policy/nsf-audit-policy.json](aws/policy/nsf-audit-policy.json) to
the role.

The script will exit non-zero whenever any permission errors occurred
(even if no compliance failures were found) so this gets noticed in CI.

### `ValueError: Invalid AWS account ID: '1234'. Expected 12 numeric digits.`

The script refused an account ID because it isn't 12 digits. Check your
`--accounts` value or `aws/config/accounts.json`.

### `ValueError: Refusing to write into symlinked path: …`

Someone made `--output-dir` a symbolic link, or (under Jenkins) a parent
directory inside `$WORKSPACE` is a symlink. The script refuses these as a
safety measure. Use a regular directory.

### The CSV opens in Excel and starts with `'=…`

That's the formula-injection defense (a tag value or resource name in your
AWS account starts with `=`, `+`, `-`, or `@`). The leading single quote
is stripped by Excel on display; the underlying value is intact. This is
intentional.

### `argparse` error: `not enough arguments for format string`

You're on an old copy of the toolkit. Re-pull the repo — this was an
escaping bug in nsf5/nsf8/nsf9 argparse help text that's been fixed.

---

## 13. Scheduling with Jenkins (or other CI)

Sample Jenkinsfiles for each control live in [aws/pipelines/](aws/pipelines/).
Each one:

1. Checks out this repo.
2. Builds the Python virtual environment.
3. Runs the audit, writing reports into `$WORKSPACE/output/`.
4. Archives the reports as Jenkins build artifacts.

Each Jenkinsfile has its own cron schedule (staggered to avoid AWS API
rate limits when run in parallel). The pipelines **do not upload anywhere
external** — see [§14](#14-uploading-reports-elsewhere) for that.

To use them:

1. In your Jenkins, create one pipeline job per audit, pointed at the
   matching `.Jenkinsfile`.
2. Configure the Jenkins credentials it needs (the audit IAM role
   credentials, plus `github-pat` for repo checkout).
3. Make sure the Jenkins agent has Python 3.10+ on its `PATH` and a
   `jenkins` label.

For other CI systems (GitHub Actions, GitLab CI, Azure Pipelines, etc.),
copy the shell commands from the Jenkinsfiles' `sh '''…'''` blocks.

---

## 14. Uploading reports elsewhere

> Earlier versions of this toolkit shipped a built-in Google Drive
> uploader. **That has been removed** to keep the scripts portable: they
> shouldn't require Google service-account keys or any vendor-specific
> dependency.

If you want reports in Google Drive, S3, SharePoint, an internal artifact
store, etc., add an upload step *after* the audit in your wrapping
script / pipeline. The scripts write files to `--output-dir`; pick them
up from there with whatever tooling fits your environment.

The Jenkinsfiles use `archiveArtifacts` only. To add a Drive / S3 upload,
add another stage that runs your uploader of choice after the audit
stage.

---

## 15. Evidence integrity guarantees

The toolkit enforces several properties so the reports are
trustworthy attestation evidence. These are not just "best effort" — they
are unit-tested ([§17](#17-running-the-test-suite)) and will fail loudly
if they ever regress.

- **Account IDs are validated as 12 numeric digits.** A tampered
  `accounts.json` (or `--accounts` value) cannot redirect role assumption
  to a malformed / attacker-supplied ARN.
- **AWS permission errors are loud, not silent.** Every `AccessDenied`,
  `ExpiredToken`, `UnauthorizedOperation`, etc. is logged with the
  `NSF-AUDIT-PERMISSION-ERROR` prefix and tallied in a process-wide
  counter. Scripts exit non-zero if any permission error was observed
  during the run — even if no other "non-compliant" finding was recorded
  — so CI fails rather than producing falsely clean evidence.
- **`nsf1.py` records per-user `AuditErrors`.** When the role can't read
  IAM policies / MFA devices for a user, the record is flagged
  `Compliant=False` with the failing operation captured in the
  `AuditErrors` column, instead of silently treating the user as
  unprivileged (which previously could have hidden privileged-without-MFA
  users behind an `AccessDenied`).
- **CSV outputs neutralize formula-injection** (CWE-1236) so auditors who
  open the report in Excel / Google Sheets can't accidentally execute
  formulas embedded in AWS tag values or resource names.
- **YAML output uses `safe_dump`.** No Python-specific tags will ever be
  emitted — your downstream YAML consumer is safe.
- **`--output-dir` rejects symlinks** at the target. Inside Jenkins
  (`$WORKSPACE`), symlinked intermediate directories are also refused —
  so a workspace-relative tampering can't redirect writes elsewhere on
  the agent.

---

## 16. Required IAM permissions

A minimum-privilege IAM policy + matching trust policy live in
[aws/policy/](aws/policy/). See [aws/policy/README.md](aws/policy/README.md)
for the role setup instructions and a service-by-service breakdown.

The AWS-managed `SecurityAudit` policy is a usable alternative for
NSF1 – NSF11 but may need small additions for NSF12 / NSF13.

---

## 17. Running the test suite

The toolkit ships a pytest suite. **It doesn't touch AWS** — fake IAM
stubs and mocked sessions cover the audit code paths.

```bash
cd aws
pip install -r requirements.txt -r requirements-dev.txt
python3 -m pytest                              # full suite
python3 -m pytest tests/test_aws_common.py     # library only
python3 -m pytest -k 'permission_error'        # one focused area
python3 -m pytest -v                           # verbose
```

Expected output:

```
193 passed in 0.2s
```

If any test fails after you've edited a script, the failure message
points at the file and line number so you can find the regression.

Three test files:

- [tests/test_aws_common.py](aws/tests/test_aws_common.py) — exhaustive
  unit tests for the library (validators, writers, CLI parsers, logging,
  session dispatch, CSV-injection defense, output-dir symlink rejection,
  permission-error classifier).
- [tests/test_audits_smoke.py](aws/tests/test_audits_smoke.py) — every
  `nsfN.py` is imported, its argparse parser is built and `--help`-rendered
  (catches `%` quoting bugs), and the common CLI surface is asserted.
- [tests/test_nsf1_integration.py](aws/tests/test_nsf1_integration.py) —
  end-to-end for nsf1 with a stub IAM client. Verifies the canonical
  evidence-integrity regression guard: a permission error during privilege
  determination must populate `AuditErrors` and produce `Compliant=False`,
  never a silent compliant verdict.

---

## 18. CLI reference (all flags)

Every script accepts these flags. Run any script with `--help` to see its
specific examples.

| Flag | Description |
|---|---|
| `--accounts <id,id,...>` | AWS account IDs (12 digits each). Falls back to `aws/config/accounts.json`. **Required if neither is provided.** |
| `--regions <r,r,...>` | AWS regions. Falls back to `aws/config/regions.json`. **Required for region-scoped audits if neither is provided.** |
| `--role <name>` | IAM role name to assume in each account. Falls back to `$NSF_AUDIT_ROLE`. If neither is set, the script uses `--profile` or default credentials. |
| `--profile <name>` | Named AWS profile (from `~/.aws/credentials` / `~/.aws/config`). Used as the base session before role assumption, or alone if `--role` is not set. |
| `--external-id <value>` | External ID forwarded to `sts:AssumeRole`. Defaults to `$AWS_EXTERNAL_ID`. Required when the audit role's trust policy enforces an `ExternalId` condition (recommended baseline). |
| `--output-dir <path>` | Output directory (default: current directory). Symlinked target paths are rejected. Inside `$WORKSPACE` (Jenkins), symlinked intermediate components are rejected too. |
| `--format <fmts>` | Output format(s), comma-separated. Supported: `csv`, `json`, `yaml`, `text`. Default: `csv`. Multiple formats produce one file each. |
| `-v` / `--verbose` | DEBUG-level logging. Mutually exclusive with `--quiet`. |
| `-q` / `--quiet` | Suppress INFO; only WARNING and above are emitted. |
| `--log-file <path>` | Write logs to this file instead of stderr. |

### Environment variables

| Variable | Equivalent flag |
|---|---|
| `NSF_AUDIT_ROLE` | `--role` |
| `AWS_PROFILE` | `--profile` |
| `AWS_EXTERNAL_ID` | `--external-id` |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN` | Standard boto3 default-credentials chain |

### Examples

```bash
# 1. Simplest: one account, default region, default credentials
python3 audits/nsf1.py --accounts 123456789012

# 2. Multi-account, multi-region, assume role, multi-format
NSF_AUDIT_ROLE=NSF-AuditReadOnly \
AWS_EXTERNAL_ID=long-random-string \
python3 audits/nsf12.py \
    --accounts 123456789012,234567890123 \
    --regions us-east-1,us-west-2 \
    --format csv,json,yaml \
    --output-dir ./reports

# 3. Use a named profile, verbose logging, write logs to a file
python3 audits/nsf9.py \
    --profile prod-readonly \
    --regions us-east-1 \
    --format json \
    --verbose \
    --log-file /tmp/nsf9-debug.log

# 4. Audit every account in config, quiet, save log to file
python3 audits/nsf6.py --quiet --log-file /var/log/nsf_audit/nsf6.log
```

---

## 19. Frequently asked questions

**Q. Do I have to enable every AWS service the scripts read from?**
No. If a service isn't enabled in your account, the script records that
fact as a finding ("GuardDuty not enabled in us-east-1", etc.) and moves
on. Not enabling Inspector v2, for example, is itself a non-compliance
signal for NSF12.

**Q. Will the scripts change anything in my AWS account?**
No. The supplied IAM policy contains only `Get*` / `List*` / `Describe*` /
`BatchGet*` actions. There's no way for the scripts to mutate, create, or
delete AWS resources even by mistake.

**Q. Can I run only one or two controls instead of all 13?**
Yes — each script is independent. Run only the ones you need.

**Q. How long does a run take?**
Single-account, single-region: typically 10–60 seconds. Many accounts and
all 37 regions: 5–15 minutes per script. The toolkit makes only read
calls; AWS rate limits rarely matter.

**Q. The auditor wants evidence that the toolkit itself wasn't tampered
with. What can I tell them?**
- The toolkit is open-source — they can read the code.
- The Python tests ([§17](#17-running-the-test-suite)) prove that the
  evidence-integrity guarantees ([§15](#15-evidence-integrity-guarantees))
  still hold on the version you ran.
- The IAM policy is purely read-only, so even if the code did something
  malicious it couldn't change AWS state.
- The CSV files contain a timestamp in the filename. Pair them with the
  log output for the run (use `--log-file` for unattended runs) — the
  log lines are timestamped per-account so the chain of custody is
  reproducible.

**Q. I'm running on Windows native (no WSL). Does anything change?**
The Python code works fine. The activation step uses backslashes:
`.\venv\Scripts\Activate.ps1`. The Jenkinsfiles assume a POSIX shell on
the agent — if your Jenkins is on Windows, port them to `bat`/`powershell`
steps or run agents on Linux.

**Q. Can the toolkit audit GCP or Azure too?**
Not today. Only AWS is implemented. The structure (one script per
control, library-driven IO) would translate to other clouds, but you'd
need to write the GCP/Azure equivalents of `aws/audits/nsfN.py`.

**Q. Where do I get help / report bugs?**
This repository's issue tracker. For suspected security issues, see the
"Security issues" section of [CONTRIBUTING.md](CONTRIBUTING.md) — please
don't open a public issue for those.

**Q. How do I contribute?**
See [CONTRIBUTING.md](CONTRIBUTING.md) — it walks through dev setup,
project conventions, the PR checklist, and a step-by-step guide for
adding a new audit script.

---

## Project layout

```
nsf-critical-control-set/
├── README.md                                  ← you are here
├── CONTRIBUTING.md                            ← how to develop / submit changes
├── LICENSE                                    ← MIT
└── aws/
    ├── audits/                                ← one script per control
    │   ├── nsf1.py … nsf13.py
    ├── config/                                ← optional defaults
    │   ├── accounts.json
    │   ├── regions.json
    │   └── identity-stores.json
    ├── lib/                                   ← shared library
    │   ├── aws_common.py
    │   └── __init__.py
    ├── pipelines/                             ← Jenkinsfiles
    │   └── nsf1.Jenkinsfile … nsf13.Jenkinsfile
    ├── policy/                                ← IAM policy templates
    │   ├── nsf-audit-policy.json
    │   ├── nsf-audit-trust-policy.json
    │   └── README.md
    ├── tests/                                 ← pytest suite
    │   ├── conftest.py
    │   ├── test_aws_common.py
    │   ├── test_audits_smoke.py
    │   └── test_nsf1_integration.py
    ├── requirements.txt
    └── requirements-dev.txt
```
