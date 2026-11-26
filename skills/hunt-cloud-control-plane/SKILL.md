---
name: hunt-cloud-control-plane
description: "Hypothesis-driven hunt in cloud control-plane audit logs. AWS CloudTrail: unused regions, CreateUser / CreateAccessKey / CreateLoginProfile / UpdateAssumeRolePolicy, StopLogging / DeleteTrail / GuardDuty tampering, GetCallerIdentity recon bursts, S3 policy changes, EC2 user-data, Lambda backdoors, SSM SendCommand. Azure: AzureActivity role assignments, Run Command, Key Vault SecretGet bursts, elevateAccess, Entra app credentials. GCP Admin Activity: SetIamPolicy, CreateServiceAccountKey, setMetadata, sink deletion. Cross-cloud SAML/OIDC trust changes. Athena SQL, Sentinel KQL, Cloud Logging and BigQuery queries. Maps to T1098.001, T1098.003, T1136.003, T1562.008, T1651, T1648, T1535. Use when asked to \"hunt CloudTrail\", \"check AWS/Azure/GCP for persistence\", \"who created access keys\", or after a cloud credential leak."
---

# Hunt: cloud control plane (AWS, Azure, GCP)

## When to use

- Leaked or suspected-compromised cloud credentials (access key in a repo, stolen session token, compromised CI/CD identity).
- Periodic hunt across organisations/subscriptions/projects for persistence and logging tampering.
- After an on-prem incident where the actor reached cloud admin identities (hybrid identity, sync accounts, federation).
- To scope blast radius of a known-bad principal across accounts.

Case handling: `ir-cloud-aws`, `ir-azure-entra`. Kubernetes API-server logs: `hunt-k8s-runtime`. Preventive configuration: `hardening-cloud`.

## Ground rules

- **Attribute every event to a principal chain**: for assumed roles, resolve `sessionIssuer` back to the original identity (and SAML/OIDC subject). A verdict on "role X did it" without the human or workload behind it is incomplete.
- **Errors are evidence.** `AccessDenied` bursts are the actor mapping permissions; do not filter on success only.
- **Coverage statement is mandatory**: which accounts/subscriptions/projects, which trails/diagnostic settings, management vs data events, and retention. Absence of data-plane logs (S3 data events, Key Vault diagnostics, GCP Data Access logs) must be stated, not assumed.
- **Do not alert the actor**: disabling keys, removing role assignments, or applying SCP/deny policies are containment actions with production blast radius - `/contain` with incident-commander approval. Snapshot the current IAM state (policies, trust documents, keys) first.
- **Treat the logging pipeline as a target**: confirm the trail/diagnostic setting still exists and delivered logs for the whole window before trusting "nothing found".

## Workflow

1. **Scope and coverage**: organisation structure, log locations (org trail S3 bucket / CloudTrail Lake, Log Analytics workspace, GCP aggregated sink), gaps, time zone (all UTC).
2. **Logging integrity first**: tamper events and delivery gaps.
3. **Identity persistence**: new users/keys/credentials, trust-policy and federation changes, role grants.
4. **Execution paths**: SSM/Run Command/serial console, user-data/startup scripts, serverless changes, VM extensions.
5. **Recon signatures**: `GetCallerIdentity` and broad List/Describe bursts, denied-call fan-out.
6. **Data access and exposure**: secrets reads, storage policy changes (detail in `hunt-exfiltration`).
7. **Stack** principals, source IPs/ASNs, user-agents and regions against the 90-day baseline.
8. **Verdict, escalate, hand off detections.**

## Hypothesis templates

- "A leaked access key was used from infrastructure we do not own to run reconnaissance (`GetCallerIdentity`, List/Describe fan-out) and create persistence (new user, access key or login profile)."
- "An actor modified a role trust policy or added a SAML/OIDC provider so an external identity can assume privileged roles."
- "An actor disabled or degraded logging (trail stopped, event selectors reduced, diagnostic setting deleted, log sink excluded) before acting."
- "Remote execution on instances was performed through the control plane (SSM SendCommand, Azure Run Command, GCP startup-script metadata) rather than the network."
- "Compute resources were launched in a region the organisation never uses (cryptomining or staging)."
- "A Lambda function, Azure Function or Cloud Function was backdoored or exposed via an unauthenticated URL."

## ATT&CK sub-technique map

| Behaviour | Technique |
|---|---|
| Use of stolen cloud credentials | T1078.004 Valid Accounts: Cloud Accounts |
| New user / service account | T1136.003 Create Account: Cloud Account |
| New access key, login profile, SA key, app secret | T1098.001 Additional Cloud Credentials |
| Role grants, policy attachment | T1098.003 Additional Cloud Roles |
| Trust policy, SAML/OIDC provider, federation changes | T1484.002 Trust Modification; T1556.007 Hybrid Identity |
| Logging tampering | T1562.008 Impair Defenses: Disable or Modify Cloud Logs |
| Recon | T1580 Cloud Infrastructure Discovery, T1526 Cloud Service Discovery, T1087.004 |
| SSM / Run Command / serial console | T1651 Cloud Administration Command |
| User-data / startup scripts / instance changes | T1578.005 Modify Cloud Compute Configurations; T1059.009 Cloud API |
| Serverless backdoor | T1648 Serverless Execution |
| Unused regions | T1535 Unused/Unsupported Cloud Regions |
| Secrets stores (Secrets Manager, Key Vault, Secret Manager) | T1555.006 Cloud Secrets Management Stores |
| Storage exposure / data access | T1530 Data from Cloud Storage; T1537 |

## Data sources required

| Cloud | Source | Notes |
|---|---|---|
| AWS | CloudTrail management events (org trail), queried with Athena or CloudTrail Lake; Sentinel `AWSCloudTrail` | Data events (S3, Lambda invoke) off by default; global-service events (IAM, STS global endpoint) recorded in us-east-1 |
| AWS | GuardDuty findings, Config history | Corroboration, not a substitute |
| Azure | `AzureActivity` (subscription), Entra `AuditLogs`/`SigninLogs`/`AADServicePrincipalSignInLogs`, Key Vault diagnostics (`AzureDiagnostics` or `AZKVAuditLogs`) | Tenant-level operations (e.g. `elevateAccess`) need directory-level activity logs collected |
| GCP | Cloud Audit Logs: Admin Activity (always on), Data Access (off by default except BigQuery), Policy Denied; exported to BigQuery or Sentinel `GCPAuditLogs` | `GenerateAccessToken` (impersonation) is a Data Access event |

## AWS queries (Athena SQL on the CloudTrail table)

Table and column names follow the AWS documentation's CloudTrail table for Athena (`useridentity` struct, `requestparameters` JSON string). Partition names/projection depend on your setup - add partition predicates to control cost.

```sql
-- Logging tampering (T1562.008). Any success here is an escalation trigger.
SELECT eventtime, recipientaccountid, awsregion, eventsource, eventname, useridentity.arn AS actor,
       useridentity.sessioncontext.sessionissuer.arn AS issuer, sourceipaddress, useragent, errorcode, requestparameters
FROM cloudtrail_logs
WHERE eventtime > to_iso8601(current_timestamp - interval '30' day)
  AND eventname IN ('StopLogging','DeleteTrail','UpdateTrail','PutEventSelectors','PutInsightSelectors',
                    'DeleteEventDataStore','StopEventDataStoreIngestion','DeleteFlowLogs',
                    'DeleteDetector','UpdateDetector','DisassociateFromMasterAccount','DisassociateFromAdministratorAccount','DeleteMembers',
                    'StopConfigurationRecorder','DeleteConfigurationRecorder','DeleteDeliveryChannel',
                    'DisableSecurityHub','DeleteLogGroup','DeleteLogStream','PutRetentionPolicy','LeaveOrganization')
ORDER BY eventtime;
```

```sql
-- IAM persistence and privilege changes (T1136.003, T1098.001, T1098.003, T1484.002)
SELECT eventtime, recipientaccountid, eventname, useridentity.arn AS actor, sourceipaddress, useragent, errorcode,
       json_extract_scalar(requestparameters, '$.userName') AS target_user,
       json_extract_scalar(requestparameters, '$.roleName') AS target_role,
       json_extract_scalar(requestparameters, '$.policyArn') AS policy
FROM cloudtrail_logs
WHERE eventsource = 'iam.amazonaws.com'
  AND eventtime > to_iso8601(current_timestamp - interval '30' day)
  AND eventname IN ('CreateUser','CreateAccessKey','CreateLoginProfile','UpdateLoginProfile','AddUserToGroup',
                    'AttachUserPolicy','PutUserPolicy','AttachRolePolicy','PutRolePolicy','AttachGroupPolicy','PutGroupPolicy',
                    'CreateRole','UpdateAssumeRolePolicy','CreatePolicyVersion','SetDefaultPolicyVersion',
                    'DeactivateMFADevice','DeleteVirtualMFADevice','CreateServiceSpecificCredential','UploadSSHPublicKey',
                    'CreateSAMLProvider','UpdateSAMLProvider','CreateOpenIDConnectProvider',
                    'UpdateOpenIDConnectProviderThumbprint','AddClientIDToOpenIDConnectProvider')
ORDER BY eventtime;
```

```sql
-- Access keys / console passwords created for a DIFFERENT user than the caller - classic backdoor pattern.
SELECT eventtime, eventname, useridentity.arn AS actor, useridentity.username AS caller_user,
       json_extract_scalar(requestparameters, '$.userName') AS target_user, sourceipaddress, useragent
FROM cloudtrail_logs
WHERE eventname IN ('CreateAccessKey','CreateLoginProfile','UpdateLoginProfile') AND errorcode IS NULL
  AND json_extract_scalar(requestparameters, '$.userName') IS NOT NULL
  AND (useridentity.username IS NULL OR useridentity.username <> json_extract_scalar(requestparameters, '$.userName'))
  AND eventtime > to_iso8601(current_timestamp - interval '30' day);
```

```sql
-- Recon bursts: GetCallerIdentity plus wide service/API fan-out and denied calls per key per hour. Tune thresholds.
SELECT useridentity.accesskeyid AS key_id, useridentity.arn AS actor, sourceipaddress, useragent,
       date_trunc('hour', from_iso8601_timestamp(eventtime)) AS hr,
       count(*) AS calls, count(DISTINCT eventsource) AS services, count(DISTINCT eventname) AS apis,
       sum(CASE WHEN errorcode LIKE '%AccessDenied%' OR errorcode LIKE '%UnauthorizedOperation%' THEN 1 ELSE 0 END) AS denied,
       max(CASE WHEN eventname = 'GetCallerIdentity' THEN 1 ELSE 0 END) AS whoami
FROM cloudtrail_logs
WHERE eventtime > to_iso8601(current_timestamp - interval '7' day)
GROUP BY 1, 2, 3, 4, 5
HAVING count(DISTINCT eventsource) >= 8 OR sum(CASE WHEN errorcode LIKE '%AccessDenied%' OR errorcode LIKE '%UnauthorizedOperation%' THEN 1 ELSE 0 END) >= 20
ORDER BY denied DESC;
```

```sql
-- Write activity in regions not used by the account in the prior 90 days (T1535). Global services log in us-east-1.
WITH baseline AS (
  SELECT DISTINCT recipientaccountid, awsregion FROM cloudtrail_logs
  WHERE eventtime BETWEEN to_iso8601(current_timestamp - interval '97' day) AND to_iso8601(current_timestamp - interval '7' day))
SELECT r.recipientaccountid, r.awsregion, r.eventname, r.useridentity.arn AS actor, r.sourceipaddress,
       count(*) AS n, min(r.eventtime) AS first_seen
FROM cloudtrail_logs r
LEFT JOIN baseline b ON r.recipientaccountid = b.recipientaccountid AND r.awsregion = b.awsregion
WHERE r.eventtime > to_iso8601(current_timestamp - interval '7' day) AND b.awsregion IS NULL AND r.readonly = 'false'
GROUP BY 1, 2, 3, 4, 5
ORDER BY first_seen;
```

```sql
-- Control-plane execution: SSM, EC2 Instance Connect / serial console, user-data changes, serverless backdoors.
-- Lambda eventNames carry API-version suffixes (e.g. UpdateFunctionCode20150331v2) - hence LIKE.
-- SSM command parameters and EC2 userData are redacted in CloudTrail; pivot to SSM command history / instance logs.
SELECT eventtime, recipientaccountid, awsregion, eventsource, eventname, useridentity.arn AS actor, sourceipaddress,
       json_extract_scalar(requestparameters, '$.documentName') AS ssm_document,
       json_extract_scalar(requestparameters, '$.functionName') AS lambda_fn, requestparameters
FROM cloudtrail_logs
WHERE eventtime > to_iso8601(current_timestamp - interval '30' day) AND errorcode IS NULL
  AND ( eventname IN ('SendCommand','StartSession','CreateAssociation','SendSSHPublicKey','SendSerialConsoleSSHPublicKey')
     OR (eventname = 'ModifyInstanceAttribute' AND requestparameters LIKE '%userData%')
     OR eventname LIKE 'UpdateFunctionCode%' OR eventname LIKE 'UpdateFunctionConfiguration%'
     OR eventname LIKE 'CreateFunction%' OR eventname LIKE 'AddPermission%'
     OR eventname LIKE 'CreateFunctionUrlConfig%' OR eventname LIKE 'UpdateFunctionUrlConfig%'
     OR eventname LIKE 'PublishLayerVersion%' OR eventname LIKE 'CreateEventSourceMapping%')
ORDER BY eventtime;
```

Read the results with these patterns in mind: `StopInstances` -> `ModifyInstanceAttribute` (userData) -> `StartInstances` on the same instance; `AddPermission` granting `*` or an external account; function URL with `AuthType` `NONE`; `SendCommand` with `AWS-RunShellScript`/`AWS-RunPowerShellScript` from a human or unusual role. Secrets reads (`GetSecretValue` on `secretsmanager.amazonaws.com`, `GetParameter`/`GetParameters` with decryption on SSM) in bursts belong in the same review. S3 exposure queries: `hunt-exfiltration`.

### AWS in Sentinel (KQL)

```kql
// Same IAM persistence list against the AWSCloudTrail table. Verify column names in your connector version.
let Persist = dynamic(["CreateUser","CreateAccessKey","CreateLoginProfile","UpdateLoginProfile","AttachUserPolicy","PutUserPolicy",
    "AttachRolePolicy","PutRolePolicy","UpdateAssumeRolePolicy","CreateRole","CreatePolicyVersion","SetDefaultPolicyVersion",
    "CreateSAMLProvider","UpdateSAMLProvider","CreateOpenIDConnectProvider","UpdateOpenIDConnectProviderThumbprint"]);
AWSCloudTrail
| where TimeGenerated > ago(30d) and EventName in (Persist) and isempty(ErrorCode)
| extend Target = coalesce(tostring(parse_json(RequestParameters).userName), tostring(parse_json(RequestParameters).roleName))
| project TimeGenerated, RecipientAccountId, AWSRegion, EventName, UserIdentityArn, UserIdentityType, SourceIpAddress, UserAgent, Target
| order by TimeGenerated asc
```

```kql
// First-seen source IP / ASN per principal in 90 days, for any write call. Pair with geo/ASN enrichment.
let Known = AWSCloudTrail | where TimeGenerated between (ago(90d) .. ago(1d)) | distinct UserIdentityArn, SourceIpAddress;
AWSCloudTrail
| where TimeGenerated > ago(1d) and ReadOnly == false
| join kind=leftanti Known on UserIdentityArn, SourceIpAddress
| summarize Calls = count(), Apis = make_set(EventName, 20) by UserIdentityArn, SourceIpAddress, UserAgent
```

## Azure queries (KQL)

```kql
// Privileged role assignments at any scope. Built-in role IDs: Owner 8e3af657-a8ff-443c-a75c-2fe8c4bcb635,
// Contributor b24988ac-6180-42a0-ab88-20f7382dd24c, User Access Administrator 18d7d88d-d35e-4fb5-a5c3-7773c20a72d9.
AzureActivity
| where TimeGenerated > ago(30d)
| where OperationNameValue =~ "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE" and ActivityStatusValue in~ ("Success","Succeeded")
| extend Body = parse_json(tostring(parse_json(Properties).requestbody))
| extend RoleDefId = tostring(Body.Properties.RoleDefinitionId), PrincipalId = tostring(Body.Properties.PrincipalId),
         PrincipalType = tostring(Body.Properties.PrincipalType)
| where RoleDefId has_any ("8e3af657-a8ff-443c-a75c-2fe8c4bcb635","b24988ac-6180-42a0-ab88-20f7382dd24c","18d7d88d-d35e-4fb5-a5c3-7773c20a72d9")
| project TimeGenerated, Caller, CallerIpAddress, _ResourceId, RoleDefId, PrincipalId, PrincipalType
```

```kql
// Control-plane execution and defence evasion on Azure resources. Tune: automation identities (DevOps, Automation accounts).
AzureActivity
| where TimeGenerated > ago(30d) and ActivityStatusValue in~ ("Success","Succeeded")
| where OperationNameValue in~ (
    "MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION", "MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMANDS/WRITE",
    "MICROSOFT.COMPUTE/VIRTUALMACHINESCALESETS/VIRTUALMACHINES/RUNCOMMAND/ACTION",
    "MICROSOFT.COMPUTE/VIRTUALMACHINES/EXTENSIONS/WRITE",
    "MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE", "MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/WRITE",
    "MICROSOFT.KEYVAULT/VAULTS/WRITE", "MICROSOFT.KEYVAULT/VAULTS/ACCESSPOLICIES/WRITE",
    "MICROSOFT.MANAGEDIDENTITY/USERASSIGNEDIDENTITIES/FEDERATEDIDENTITYCREDENTIALS/WRITE",
    "MICROSOFT.AUTHORIZATION/ELEVATEACCESS/ACTION")
| summarize Count = count(), First = min(TimeGenerated), Resources = make_set(_ResourceId, 10)
    by Caller, CallerIpAddress, OperationNameValue
| order by First desc
```

On the VM, Run Command and Custom Script Extension leave script copies and logs under the Azure agent directories (Windows `C:\Packages\Plugins\`, Linux `/var/lib/waagent/`) - collect them for `windows-forensics` / `linux-forensics`.

```kql
// Key Vault secret/key reads: bursts and new callers (T1555.006). Needs Key Vault diagnostic logs (AuditEvent).
AzureDiagnostics
| where TimeGenerated > ago(7d) and ResourceProvider == "MICROSOFT.KEYVAULT"
| where OperationName in ("SecretGet","SecretList","KeyGet","KeyList","CertificateGet","SecretBackup","KeyBackup")
| summarize Ops = count(), Distinct = dcount(id_s), Vaults = dcount(Resource)
    by Caller = coalesce(identity_claim_upn_s, identity_claim_appid_g), CallerIPAddress, bin(TimeGenerated, 1h)
| where Distinct > 20 or Vaults > 3
```

```kql
// Entra app / service principal credential and federation changes (hybrid identity, OIDC/SAML trust).
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName has_any ("Add service principal credentials","Certificates and secrets management","Add owner to application",
        "Add owner to service principal","Set domain authentication","Set federation settings on domain","Add app role assignment to service principal")
   or (OperationName has "Update application" and tostring(TargetResources) has "FederatedIdentityCredentials")
| project TimeGenerated, OperationName, Actor = coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName)),
          Target = tostring(TargetResources[0].displayName), Result
```

Detailed Entra/M365 hunting and response: `ir-azure-entra`, `hardening-m365-entra`.

## GCP queries

```text
# Cloud Logging query language - Admin Activity: IAM policy changes, SA and key creation, metadata (ssh-keys / startup-script), logging tampering
logName:"cloudaudit.googleapis.com%2Factivity"
protoPayload.methodName:("SetIamPolicy" OR "google.iam.admin.v1.CreateServiceAccountKey" OR "google.iam.admin.v1.CreateServiceAccount"
  OR "v1.compute.instances.setMetadata" OR "v1.compute.projects.setCommonInstanceMetadata"
  OR "google.logging.v2.ConfigServiceV2.DeleteSink" OR "google.logging.v2.ConfigServiceV2.UpdateSink"
  OR "google.logging.v2.ConfigServiceV2.CreateExclusion" OR "WorkloadIdentityPoolProvider")
```

```sql
-- BigQuery over an exported audit-log sink (standard export schema). Owner/editor grants to members outside your domain.
SELECT timestamp,
       protopayload_auditlog.methodName AS method,
       protopayload_auditlog.authenticationInfo.principalEmail AS actor,
       protopayload_auditlog.requestMetadata.callerIp AS ip,
       resource.labels.project_id AS project,
       bd.action, bd.role, bd.member
FROM `my-project.audit_logs.cloudaudit_googleapis_com_activity_*`,
     UNNEST(protopayload_auditlog.servicedata_v1_iam.policyDelta.bindingDeltas) AS bd
WHERE _TABLE_SUFFIX >= FORMAT_DATE('%Y%m%d', DATE_SUB(CURRENT_DATE(), INTERVAL 30 DAY))
  AND protopayload_auditlog.methodName LIKE '%SetIamPolicy%'
  AND bd.action = 'ADD' AND bd.role IN ('roles/owner','roles/editor','roles/iam.serviceAccountTokenCreator','roles/iam.serviceAccountKeyAdmin')
  AND NOT ENDS_WITH(bd.member, '@example.com')     -- replace with your domain(s); also review serviceAccount: members
ORDER BY timestamp;
```

The location of `bindingDeltas` in the exported schema differs by service and export version (e.g. a `servicedata_v1_iam` vs `servicedata_v1_resourcemanager` record, or `metadata` JSON) - check your table schema. Service-account impersonation (`GenerateAccessToken`, `SignJwt` on `iamcredentials.googleapis.com`) is only visible with Data Access logs enabled.

```kql
// GCP in Sentinel (GCPAuditLogs). Verify column names for your connector version.
GCPAuditLogs
| where TimeGenerated > ago(30d)
| where MethodName has_any ("SetIamPolicy","CreateServiceAccountKey","CreateServiceAccount","setMetadata","setCommonInstanceMetadata","DeleteSink","CreateExclusion")
| project TimeGenerated, ProjectId, ServiceName, MethodName, PrincipalEmail, CallerIpAddress = tostring(parse_json(RequestMetadata).callerIp)
```

## Cross-cloud identity

- **Federation into AWS**: new/changed SAML or OIDC providers and role trust policies with `Federated` principals; GitHub Actions OIDC (`token.actions.githubusercontent.com`) roles whose trust condition on `sub` is missing or wildcarded let any repository assume the role. Hunt `AssumeRoleWithWebIdentity`/`AssumeRoleWithSAML` by provider and subject, stacked by role.
- **Azure workload identity federation**: federated identity credentials on app registrations and managed identities (issuer + subject) - an unexpected issuer is a backdoor that needs no secret.
- **GCP workload identity pools/providers**: new providers or relaxed attribute conditions.
- **IdP compromise**: a change at the IdP (Okta/Entra/ADFS) can mint access to every cloud - correlate trust changes with IdP admin logs (`hunt-ad-identity-attacks`, `ir-azure-entra`).
- Inventory all trust relationships quarterly; diff against the last inventory as part of the hunt.

## Baselining and stacking

- **Principal x source IP/ASN x user-agent** over 90 days; first-seen combinations for privileged principals rank high (watch for SDK/CLI user-agents from a human who normally uses the console, or `python-requests`-style agents).
- **Regions per account**, **APIs per principal**, **time-of-day per principal**.
- **IaC identities** (Terraform, CloudFormation, deployment pipelines) produce most IAM writes - baseline them by role/session name and pipeline IP, then hunt writes outside that set.
- **Key age and usage**: long-lived access keys suddenly used from new networks.

## Verdict and escalation

| Verdict | Evidence that moves it there |
|---|---|
| True Positive | Persistence/tamper/execution event by a principal used from unexpected infrastructure or outside change process, or a chain (recon -> persistence -> use) |
| Benign True Positive | IaC pipeline, break-glass use with ticket, cloud-provider service-linked action (`invokedBy` an AWS service) |
| False Positive | Mis-parsed event, provider-internal role, duplicate trail delivery |
| Needs more data | Assumed-role chain unresolved, data events not enabled, region/subscription outside log coverage |

Escalate immediately (`ir-cloud-aws` / `ir-azure-entra`, `/ir`) on: any successful logging tamper; access key/login profile/credential created for another identity; trust-policy or federation change without change record; root/Global Administrator activity outside break-glass; control-plane execution on production by an unexpected principal. Containment (deactivate keys, revoke sessions, deny policies) is approval-gated; preserve IAM state and logs before changes.

## False positives & benign look-alikes

| Look-alike | Why it fires | How to separate |
|---|---|---|
| Terraform / CloudFormation / Bicep / Deployment Manager runs | Mass IAM and resource writes | Pipeline role/identity, known IPs, matches repo commits |
| AWS service-linked actions (Config, Organizations, Control Tower, SSO provisioning) | IAM writes, region activity | `invokedBy`/service principal, control-tower roles |
| Security tooling (CSPM, scanners) | Recon-like List/Describe fan-out, `GetCallerIdentity` | Vendor role and external ID, steady schedule |
| Patch management via SSM / Run Command | SendCommand / Run Command | Maintenance windows, automation document names |
| Key rotation automation | CreateAccessKey / SA key creation | Rotation lambda/identity, old key deleted shortly after |
| New region roll-out | Unused-region activity | Change ticket, IaC identity |
| Break-glass exercises | Root / GA sign-in | Scheduled test with ticket |

## Pitfalls

- IAM and global STS events are logged in us-east-1; a region filter can hide them.
- `useridentity.arn` for assumed roles is the session ARN; join on `sessioncontext.sessionissuer.arn` to group by role.
- CloudTrail delivery lags minutes; Log Analytics/Sentinel ingestion adds more - do not conclude "absent" on the last hour.
- Redacted fields (SSM parameters, userData) push you to host-side evidence.
- Azure `AzureActivity` has both "Start" and "Success" rows per operation - count successes only when quantifying.
- GCP Data Access logs and AWS data events are commonly disabled; say what that means for the hunt.

## Output

Hunt report stub (`cases/<id>/hunts/cloud-control-plane-<date>.md`):

```markdown
# Hunt report - Cloud control plane - <date>
- Hypothesis: <filled template>
- ATT&CK: <T-IDs>
- Coverage: accounts/subscriptions/projects <list>, log sources, management/data events, gaps, window <UTC>
- Method: queries <IDs>, baselines (90-day principal/IP/region), allowlisted automation identities <ref>
- Findings:
  | Time (UTC) | Cloud/account | Principal (resolved chain) | Event(s) | Source IP/ASN/UA | Why suspicious | Verdict |
- Logging integrity: tamper events found / none; delivery gaps
- Escalations and containment requests: <IDs, approvals>
- Detection and hardening opportunities: <hand-offs>
```

Hand-offs: response -> `ir-cloud-aws`, `ir-azure-entra`, `incident-response`, `/contain`; data exposure -> `hunt-exfiltration`; Kubernetes control plane -> `hunt-k8s-runtime`; preventive controls (SCPs, PIM, org policies) -> `hardening-cloud`, `hardening-m365-entra`; rules -> `detection-engineering`, `kql-sentinel-defender`, `sigma-rules`; log gaps -> `logging-coverage`.

## References

- MITRE ATT&CK Cloud matrix (IaaS, Identity Provider); T1098.001 (https://attack.mitre.org/techniques/T1098/001/), T1562.008, T1651, T1648, T1535, T1484.002
- AWS documentation: CloudTrail userIdentity element; Querying AWS CloudTrail logs with Amazon Athena; CloudTrail event reference
- AWS Security Incident Response Guide
- Microsoft Learn: Azure Activity log schema; Azure built-in roles; Key Vault logging; Entra audit log activities
- Google Cloud documentation: Cloud Audit Logs (Admin Activity, Data Access), audit log export to BigQuery, IAM audit logging
- CISA / partner guidance on securing cloud identities and logging (e.g. joint cloud security best-practice sheets)
