# NSF Audit IAM Policy

Minimum-privilege IAM policy required to run every audit script in
[../audits/](../audits/) (NSF1 – NSF13).

Two documents are provided:

- [nsf-audit-policy.json](nsf-audit-policy.json) — the permissions policy
  (what the role can *do*). Attach this to the role created in each
  audited account.
- [nsf-audit-trust-policy.json](nsf-audit-trust-policy.json) — the trust
  policy (who is allowed to assume the role). Replace the three
  placeholders before applying.

## Scope

Read-only describe / list / get calls only. No write actions, no resource
mutation, no data access (e.g. no `s3:GetObject`). Resource scope is `"*"`
because the audit walks every account-level resource.

Coverage by script:

| Script | Services |
|---|---|
| NSF1 (Privileged MFA)          | IAM, STS |
| NSF2 (Remote-access MFA)       | IAM, EC2 (Client VPN), WorkSpaces |
| NSF3 (Limited admin scope)     | IAM |
| NSF4 (Anti-malware)            | GuardDuty, Security Hub, SSM, EC2 |
| NSF5 (EDR)                     | GuardDuty |
| NSF6 (Immutable system backup) | Backup, S3 |
| NSF7 (Immutable research data) | S3 |
| NSF8 (Backup integrity)        | Backup |
| NSF9 (Logging)                 | CloudTrail, EC2 (VPC Flow Logs), CloudWatch Logs, S3 |
| NSF10 (Network segmentation)   | EC2 (VPC, SG, NACL, RT, TGW, VPC Endpoints) |
| NSF11 (CI inventory)           | EC2, IAM, Directory Service, Direct Connect, Route53, SSO/Identity Center |
| NSF12 (Vulnerability mgmt)     | Inspector2, Security Hub, SSM Patch Manager |
| NSF13 (Hardening standards)    | AWS Config, Security Hub, SSM State Manager |

## Trust policy: required placeholders

The template in `nsf-audit-trust-policy.json` is intentionally not valid
until you replace **all three** placeholders. This is the recommended
baseline — narrow principal + external-id condition. Do not relax it
without a documented reason.

| Placeholder | Replace with |
|---|---|
| `REPLACE_AUDIT_PRINCIPAL_ACCOUNT_ID` | The AWS account ID that hosts the audit runner (Jenkins controller / agent / IAM user / EC2). |
| `REPLACE_AUDIT_PRINCIPAL_ROLE_NAME`  | The **specific** IAM role the audit runner uses (e.g. `JenkinsExecutor`). |
| `REPLACE_EXTERNAL_ID`                | A long, random string shared only between the audit runner and this trust policy. Treat it as a secret. Generate one per environment: `python3 -c "import secrets; print(secrets.token_urlsafe(32))"`. |

The audit scripts pass `--external-id <value>` (or read `AWS_EXTERNAL_ID`
from the environment) and forward it to `sts:AssumeRole`. Without a
matching `ExternalId`, the assumption is denied — which is the goal: it
defeats the "[confused deputy](https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html)"
risk if another tenant ever learns your role ARN.

### Discouraged variants — only if you fully understand the trade-off

- **Account-root principal** (`arn:aws:iam::<id>:root`): allows *any*
  principal in that account to assume the role. Acceptable only when the
  auditor account has a tightly controlled set of principals (e.g.
  single-purpose audit account with no human IAM users). Even then, keep
  the `ExternalId` condition.
- **Omitting `ExternalId`**: only safe if both the auditor account and the
  audited account are under the same administrative control AND the
  principal is a specific role ARN (not `:root`).

## Setup

In **each** account the audit must touch:

```bash
# 1. Create the role with the (placeholder-replaced) trust policy
aws iam create-role \
  --role-name NSF-AuditReadOnly \
  --assume-role-policy-document file://nsf-audit-trust-policy.json

# 2. Attach the permissions policy
aws iam put-role-policy \
  --role-name NSF-AuditReadOnly \
  --policy-name NSF-AuditReadOnly \
  --policy-document file://nsf-audit-policy.json
```

Then run any audit script with `--role NSF-AuditReadOnly` (or set
`NSF_AUDIT_ROLE=NSF-AuditReadOnly`), and provide the external ID either
via `--external-id` or `AWS_EXTERNAL_ID`.

## Alternative: AWS-managed policies

If you'd rather not maintain a custom policy, the AWS-managed
[`SecurityAudit`](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/SecurityAudit.html)
policy covers the bulk of what's needed for NSF1 – NSF11. NSF12 / NSF13 may
still require small additions for `inspector2:*` (read), `config:Describe*`,
and `securityhub:Get*` depending on AWS's current managed-policy contents.
The custom policy in this directory is the explicit, audited minimum.
