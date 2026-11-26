---
name: hardening-cloud
description: "Cloud security posture hardening for AWS, Azure and GCP, prioritised by exposure. AWS: Organizations SCPs (deny leaving org, deny StopLogging/DeleteTrail), root user MFA and no access keys, IMDSv2 (HttpTokens required, MetadataNoToken), S3 Block Public Access, organization CloudTrail with log file validation, GuardDuty and Security Hub via delegated admin, IAM Access Analyzer, IAM Identity Center and least privilege. Azure: management groups, Azure Policy (Deny/Audit/DeployIfNotExists), Defender for Cloud and secure score, storage public access, Owner/UAA review. GCP: organization policy constraints, public access prevention, service account keys, audit logs. CSPM tools Prowler, ScoutSuite, Steampipe. Use when asked to \"harden our AWS/Azure/GCP\", \"/harden the cloud account\", triage CSPM findings, or plan guardrails after a cloud incident."
---

# Cloud hardening (AWS, Azure, GCP)

## When to use

- A cloud organisation/tenant/org needs guardrails, or a CSPM report (Security Hub,
  Defender for Cloud, Security Command Center, Prowler) needs a prioritised plan.
- After `ir-cloud-aws` / `ir-azure-entra` / `hunt-cloud-control-plane` showed an
  attack path (leaked access key, public bucket, IMDSv1 SSRF credential theft,
  over-privileged role).

Not for: Entra ID / M365 tenant settings (`hardening-m365-entra`), OS hardening inside
VMs (`hardening-linux`, `hardening-windows-ad`), live incident response (`ir-cloud-aws`).

## Ground rules

- **Read-only first.** Assess with a dedicated read-only role (AWS `SecurityAudit` +
  `ViewOnlyAccess`, Azure `Reader` + `Security Reader`, GCP `roles/iam.securityReviewer`
  + `roles/viewer`). Never assess with an admin key on a laptop.
- **Guardrails are tested in a sandbox OU / management group / folder first.** An SCP,
  Azure Policy `Deny` or org policy can break deployments org-wide; each needs a change
  ticket, an owner, an exemption path and a rollback.
- **Evidence = API output with account/subscription/project ID and timestamp.**
  A CSPM finding is a lead; confirm the resource state before reporting it.
- **Prioritise by exposure, not by count.** One internet-exposed resource with a
  privileged identity beats a thousand untagged volumes.
- **Never delete logs, trails or detectors as part of "cleanup".** Logging changes need
  security sign-off.

## Workflow

1. **Map the estate**: AWS org/OUs/accounts, Azure management groups/subscriptions,
   GCP org/folders/projects; who owns each; which are production.
2. **Logging foundation**: org CloudTrail, Azure Activity Log + Entra logs, GCP audit
   logs to a central, access-restricted log account/project. Without this, nothing
   below can be investigated.
3. **Run CSPM** (native + Prowler/ScoutSuite/Steampipe) read-only; export results.
4. **Rank by exposure** (table below); fix internet-exposed + privileged + sensitive
   data combinations first.
5. **Preventive guardrails** (SCPs/RCPs, Azure Policy Deny, org policies) once the
   current state complies or exemptions exist.
6. **Detective controls**: GuardDuty / Defender for Cloud / SCC on everywhere,
   findings routed to the SOC.
7. **Re-scan and track drift** (scheduled Prowler/Maester-style runs in CI).

## Exposure-based prioritisation

| Priority | Pattern | Example |
|---|---|---|
| P1 | Internet-reachable + exploitable + privileged identity or sensitive data | EC2 with IMDSv1, public web app, instance role with `s3:*` on data buckets |
| P1 | Public data store with sensitive data | S3/Blob/GCS public read; snapshot/AMI/image shared publicly |
| P1 | Long-lived credentials for privileged principals | Root access keys, IAM user admin keys, SA keys with Owner |
| P2 | Missing logging / detection | No org trail, GuardDuty off in a region, Activity Log not exported |
| P2 | Admin ports open to 0.0.0.0/0 | SSH/RDP/DB ports in security groups / NSGs / firewall rules |
| P2 | Cross-account / external trust not understood | Access Analyzer external findings, wildcard principals |
| P3 | Hygiene | Unencrypted volumes (where encryption at rest is a requirement), missing tags, unused roles |

## AWS

### Organization and SCPs

- Use AWS Organizations with OUs (Security, Infrastructure, Workloads/Prod/Non-prod,
  Sandbox, Suspended). Keep workloads out of the management account; SCPs do not
  apply to the management account.
- SCPs restrict maximum permissions; they do not grant. They do not restrict
  service-linked roles. Test with the IAM policy simulator and in a sandbox OU.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Sid": "DenyLeaveOrg", "Effect": "Deny", "Action": "organizations:LeaveOrganization", "Resource": "*" },
    { "Sid": "ProtectSecurityServices", "Effect": "Deny",
      "Action": ["cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail",
                 "cloudtrail:PutEventSelectors", "guardduty:DeleteDetector",
                 "guardduty:DisassociateFromMasterAccount", "config:StopConfigurationRecorder",
                 "config:DeleteConfigurationRecorder", "securityhub:DisableSecurityHub"],
      "Resource": "*",
      "Condition": { "ArnNotLike": { "aws:PrincipalArn": "arn:aws:iam::*:role/SecurityBreakGlass" } } },
    { "Sid": "RequireIMDSv2OnLaunch", "Effect": "Deny", "Action": "ec2:RunInstances",
      "Resource": "arn:aws:ec2:*:*:instance/*",
      "Condition": { "StringNotEquals": { "ec2:MetadataHttpTokens": "required" } } },
    { "Sid": "DenyRootUser", "Effect": "Deny", "Action": "*", "Resource": "*",
      "Condition": { "ArnLike": { "aws:PrincipalArn": "arn:aws:iam::*:root" } } }
  ]
}
```

The role name `SecurityBreakGlass` is a placeholder for your security admin role.
Region-restriction SCPs (`aws:RequestedRegion`) must exempt global services (IAM,
Organizations, STS, CloudFront, Route 53, Support); use the AWS documented example as
the starting point. Resource control policies (RCPs) and declarative policies add
resource-side and service-configuration guardrails; check current availability for
your organisation.

### Root user

- MFA (hardware/passkey) on every account's root user, no root access keys, contact
  details correct. With centralised root access management, remove root credentials
  from member accounts and perform privileged root tasks from the management account.

```bash
aws iam get-account-summary --query 'SummaryMap.{RootKeys:AccountAccessKeysPresent,RootMFA:AccountMFAEnabled}'
aws iam generate-credential-report >/dev/null; aws iam get-credential-report --query Content --output text | base64 -d | cut -d, -f1,4,8,9,10,14 | head
```

### IMDSv2

```bash
# Instances still allowing IMDSv1 (per region)
aws ec2 describe-instances --query "Reservations[].Instances[?MetadataOptions.HttpTokens=='optional'].[InstanceId,Tags[?Key=='Name']|[0].Value]" --output text
# Enforce on one instance (test the app first; check CloudWatch metric MetadataNoToken = 0)
aws ec2 modify-instance-metadata-options --instance-id i-0123456789abcdef0 --http-tokens required --http-endpoint enabled
# Account/region default for new launches
aws ec2 modify-instance-metadata-defaults --http-tokens required
```

Old SDKs/agents that only speak IMDSv1 break; the `MetadataNoToken` metric tells you
before you enforce. Hop limit 1 (or 2 for containers on the instance) limits relay.

### S3 and data exposure

```bash
aws s3control get-public-access-block --account-id 111122223333
aws s3control put-public-access-block --account-id 111122223333 \
  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

- Account-level BPA on in every account; buckets that must be public (static sites)
  go behind CloudFront with origin access control instead.
- Object Ownership `BucketOwnerEnforced` (ACLs disabled). Default encryption is on
  for new objects; use SSE-KMS where key-level access control/audit is required.
- Also check public EBS snapshots, AMIs, RDS snapshots, and resource policies with
  `"Principal": "*"` (Access Analyzer finds these).

### Logging and detection

- **Organization CloudTrail**: multi-region, management events read+write, log file
  validation on (`--enable-log-file-validation`), delivered to a bucket in a separate
  log-archive account with restrictive bucket policy, Object Lock where retention is
  required, KMS encryption. Add selected data events (S3 sensitive buckets, Lambda).
  Alert on `StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors`.
- **GuardDuty**: delegated administrator in the security account, auto-enable for all
  member accounts and all regions in use; enable relevant protection plans (S3,
  EKS/Runtime Monitoring, Malware Protection, RDS, Lambda) per cost/risk.
- **Security Hub**: delegated admin, central configuration, *AWS Foundational
  Security Best Practices* and *CIS AWS Foundations Benchmark* standards; aggregate
  to one region; route findings to the SIEM/ticketing.
- **AWS Config** recorder in all accounts/regions (needed by Security Hub controls).

### IAM and least privilege

- Humans through IAM Identity Center (SSO) with permission sets; no IAM users with
  console passwords or long-lived keys for people.
- Workloads use roles (instance profiles, IRSA/EKS Pod Identity, Lambda roles); no
  access keys in code, AMIs or CI variables (use OIDC federation for CI).
- **IAM Access Analyzer**: organization analyzer for external access, unused-access
  analyzer (paid) for unused roles/keys/permissions, policy validation in CI, policy
  generation from CloudTrail to right-size roles.

```bash
aws accessanalyzer create-analyzer --analyzer-name org-external --type ORGANIZATION
aws accessanalyzer list-findings-v2 --analyzer-arn <arn> --filter '{"status":{"eq":["ACTIVE"]}}'
```

- Permission boundaries for delegated role creation; deny `iam:PassRole` to `*`.
- Security groups: no 0.0.0.0/0 or ::/0 on 22/3389/database ports; use SSM Session
  Manager or EC2 Instance Connect Endpoint instead of open SSH.
- EBS encryption by default per region: `aws ec2 enable-ebs-encryption-by-default`.

## Azure

- **Management groups**: Tenant Root Group -> platform (identity, management,
  connectivity) and landing zones (corp, online) -> sandbox/decommissioned. Assign
  policy and RBAC at management-group scope, not per subscription.
- **Azure Policy**: start `Audit`/`AuditIfNotExists`, move to `Deny` /
  `DeployIfNotExists` / `Modify` after remediation. Examples: storage accounts must
  disallow public blob access, require secure transfer and minimum TLS 1.2; no public
  IPs on NICs in corp landing zones; allowed locations; diagnostic settings deployed
  to the central Log Analytics workspace.
- **Defender for Cloud**: foundational CSPM is free and uses the *Microsoft cloud
  security benchmark*; Defender CSPM adds attack-path analysis. Enable workload plans
  by risk (Servers, Storage, SQL, Containers, Key Vault, Resource Manager, App Service).
  Track secure score per subscription; route alerts to Sentinel/SOC.
- **RBAC**: minimise `Owner` and `User Access Administrator` at subscription/MG scope;
  use PIM for Azure resource roles; review the Global Admin "elevate access" setting
  (`Microsoft.Authorization/elevateAccess/action` in the Activity/Directory audit logs).
- **Logging**: Activity Log diagnostic setting at subscription (or via policy) to Log
  Analytics/Event Hub; resource diagnostic logs for Key Vault, storage, NSG flow logs
  where needed.
- Storage: `allowBlobPublicAccess=false`, consider `allowSharedKeyAccess=false` (forces
  Entra auth; breaks SAS-key based apps), private endpoints for sensitive accounts.
- VMs: no RDP/SSH from Internet; use Bastion or JIT VM access.

```kusto
// Azure Resource Graph: storage accounts allowing public blob access or old TLS
resources
| where type =~ 'microsoft.storage/storageaccounts'
| extend publicBlob = tostring(properties.allowBlobPublicAccess), tls = tostring(properties.minimumTlsVersion)
| where publicBlob =~ 'true' or tls !~ 'TLS1_2'
| project subscriptionId, resourceGroup, name, publicBlob, tls
```

```bash
# NSG rules allowing inbound from any source (Azure CLI; review port and resource)
az network nsg list --query "[].{nsg:name, rg:resourceGroup, rules:securityRules[?direction=='Inbound' && access=='Allow' && (sourceAddressPrefix=='*' || sourceAddressPrefix=='Internet')].[name,destinationPortRange]}" -o json
```

## GCP

- Resource hierarchy: org -> folders -> projects; IAM at folder level for teams.
- **Organization policy constraints** (enforce at org/folder, exempt specific projects):
  - `constraints/iam.allowedPolicyMemberDomains` (domain-restricted sharing)
  - `constraints/iam.disableServiceAccountKeyCreation` and `constraints/iam.disableServiceAccountKeyUpload`
  - `constraints/iam.automaticIamGrantsForDefaultServiceAccounts`
  - `constraints/storage.publicAccessPrevention`, `constraints/storage.uniformBucketLevelAccess`
  - `constraints/compute.vmExternalIpAccess`, `constraints/compute.requireOsLogin`,
    `constraints/compute.skipDefaultNetworkCreation`
  - `constraints/sql.restrictPublicIp`, `constraints/gcp.resourceLocations`
- Newer *managed* constraints exist for some of these; check which form your org uses.

```bash
gcloud org-policies list --organization=ORG_ID
gcloud org-policies describe constraints/iam.disableServiceAccountKeyCreation --organization=ORG_ID
# Who holds basic roles (owner/editor) at project level
gcloud projects get-iam-policy PROJECT_ID --flatten="bindings[].members" \
  --filter="bindings.role:(roles/owner OR roles/editor)" --format="table(bindings.role,bindings.members)"
```

- Remove `allUsers` / `allAuthenticatedUsers` bindings on buckets and services unless
  intentionally public; avoid basic roles (Owner/Editor) for humans and default
  service accounts.
- Admin Activity audit logs are always on; Data Access logs are off by default for
  most services: enable for sensitive services; aggregated org-level log sink to a
  locked project/bucket.
- Security Command Center at org level; route findings to the SOC.

## CSPM tools

| Tool | Example | Notes |
|---|---|---|
| Prowler | `prowler aws --compliance cis_2.0_aws -M html json-ocsf`; `prowler azure --az-cli-auth`; `prowler gcp` | Broad checks incl. CIS/FSBP mappings; compliance framework names vary by version (`prowler aws --list-compliance`) |
| ScoutSuite | `scout aws --profile audit`; `scout azure --cli`; `scout gcp --user-account` | Offline HTML report; check project activity/version before relying on it |
| Steampipe + Powerpipe | SQL over cloud APIs; compliance mods (CIS, FSBP) run as benchmarks | Good for ad-hoc questions ("all SGs open to world") |
| Native | Security Hub, Defender for Cloud, Security Command Center | Source of truth for remediation tracking |

Run tools from a hardened runner with read-only credentials; treat reports as
sensitive (they map your attack surface).

## False positives & benign look-alikes

- Public S3/GCS/Blob flagged for a static website or public dataset that is meant to
  be public: confirm the content and that write is not public; document exception.
- Security group open to 0.0.0.0/0 on 443 for a public load balancer is expected;
  on 22/3389/5432/3306 it is not.
- Access Analyzer "external access" to a known third-party (backup vendor, SIEM
  integration role with external ID) is a trust to document, not a breach.
- CSPM "unencrypted" findings on resources encrypted by default with provider-managed
  keys; read the actual setting.
- Root user "used recently" during an approved billing/support task logged in a ticket.

## Pitfalls

- Region-deny SCP without global-service exemptions: breaks IAM/STS/support.
- Enabling GuardDuty/Security Hub only in the home region; attackers use other regions.
- Org trail logging to a bucket in the same account that admins can delete.
- Deny-by-policy rollout without an exemption process: teams create shadow accounts.
- Enforcing IMDSv2 without checking `MetadataNoToken`, breaking old agents.
- Treating CSPM score as risk: 95% compliant with one public database is still a P1.
- Forgetting non-human identities: CI/CD keys and third-party SaaS roles are the
  usual entry point.

## Output

- Prioritised findings: resource, account/subscription/project, evidence, exposure
  class (P1-P3), fix, owner, ticket, guardrail to prevent recurrence.
- Guardrail pack (SCP/RCP JSON, Azure Policy assignments, org policy list) with test
  results and exemption list.
- Detections for residual risk (e.g. `StopLogging`, `PutBucketPolicy` making public,
  new access keys for privileged users) handed to `detection-engineering` and
  `hunt-cloud-control-plane`; vulnerable images to `vuln-prioritization`.
  Start with `/harden`.

## References

- MITRE ATT&CK (Cloud): T1078.004 Cloud Accounts, T1552.005 Cloud Instance Metadata
  API, T1530 Data from Cloud Storage, T1562.008 Disable or Modify Cloud Logs,
  T1098.001 Additional Cloud Credentials, T1537 Transfer Data to Cloud Account.
- AWS: Security Reference Architecture (AWS SRA); Organizations SCP examples;
  Use IMDSv2; S3 Block Public Access; Creating a trail for an organization;
  GuardDuty and Security Hub multi-account guides; IAM Access Analyzer user guide.
- Microsoft Learn: Cloud Adoption Framework landing zones; Azure Policy effects;
  Microsoft cloud security benchmark; Defender for Cloud documentation.
- Google Cloud: Organization policy constraints list; Security foundations blueprint;
  Cloud Audit Logs overview; Security Command Center.
- CIS AWS / Azure / GCP Foundations Benchmarks.
