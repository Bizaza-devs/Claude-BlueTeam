---
name: ir-cloud-aws
description: AWS incident response for compromised credentials, workloads and data. Covers the CloudTrail eventNames that matter (ConsoleLogin, CreateAccessKey, CreateUser, CreateLoginProfile, AttachUserPolicy, PutUserPolicy, CreatePolicyVersion, AssumeRole, GetSessionToken, GetSecretValue, PutBucketPolicy, DeletePublicAccessBlock, StopLogging, DeleteTrail, PutEventSelectors, DeleteDetector, RunInstances in unused regions, ModifySnapshotAttribute), GuardDuty finding types (InstanceCredentialExfiltration, CloudTrailLoggingDisabled, RootCredentialUsage, BitcoinTool), Athena and CloudTrail Lake SQL, the access-key compromise playbook, containment (AWSDenyAll, revoke role sessions via aws:TokenIssueTime, quarantine security group, snapshot EBS before changes) and evidence preservation. Use for "AWS keys leaked", "GuardDuty alert", "crypto mining in our account", "S3 bucket made public", or "CloudTrail was stopped".
---

# AWS incident response

In AWS the control plane is the crime scene: every attacker action is an API
call with an identity, a source IP, a user agent and a region. Your job is to
find every principal and key the attacker held, and everything they created.

## When to use

- Leaked or suspicious access keys (`AKIA...` long-term, `ASIA...` temporary).
- GuardDuty, Security Hub, Detective or third-party CSPM alerts.
- Unexpected resources (instances in unused regions, new IAM users, Lambda
  functions), cost spikes, public S3 buckets, disabled logging.
- Compromised EC2 instance, container or CI/CD pipeline with AWS credentials.

Run under `incident-response`. For proactive hunting in the control plane,
`hunt-cloud-control-plane`; for hardening afterwards, `hardening-cloud`.

## Ground rules

1. **Preserve CloudTrail and snapshot before you change.** Confirm trails
   still log (and to where), copy relevant log objects to an evidence bucket
   with Object Lock in a separate security account, and snapshot EBS volumes
   of affected instances before stopping, terminating or modifying them.
2. **A finding is not a verdict.** Corroborate a GuardDuty finding with the
   underlying CloudTrail events (identity, IP, user agent, time) before
   containment beyond reversible steps.
3. **Scope every credential, not just the first.** An attacker with IAM
   permissions creates more keys, users, roles and trust relationships.
   Search for every principal they created or modified.
4. **Do not terminate compromised instances** without IC approval; termination
   destroys instance-store data, memory and (by default) the root EBS volume.
5. **Region-blind is blind.** Query all regions; attackers favour unused ones.

## Workflow

1. Identify the principal(s) and key ID(s) involved (`userIdentity.arn`,
   `userIdentity.accessKeyId`).
2. Verify logging: `DescribeTrails`/`GetTrailStatus` across regions and the
   organisation trail; check for `StopLogging`, `DeleteTrail`, `UpdateTrail`,
   `PutEventSelectors`.
3. Preserve: export CloudTrail for the window, snapshot volumes, tag resources.
4. Contain the identity (deny policy, deactivate keys, revoke sessions).
5. Scope: everything the identity did, every principal it created or
   assumed, data accessed (S3 data events, Secrets Manager, SSM, KMS).
6. Contain workloads (quarantine SG, isolate, preserve memory if possible).
7. Eradicate: delete attacker-created resources (after documentation),
   rotate all exposed secrets, fix the leak source.
8. Recover and monitor; report.

## CloudTrail events that matter

| eventName | eventSource | Why it matters | ATT&CK |
|---|---|---|---|
| `ConsoleLogin` | signin.amazonaws.com | Console access; check `additionalEventData.MFAUsed`, `responseElements.ConsoleLogin` | T1078.004 |
| `GetCallerIdentity` | sts | First call after key theft ("whoami") | T1087.004 |
| `CreateAccessKey`, `CreateUser`, `CreateLoginProfile`, `UpdateLoginProfile` | iam | Persistence via new credentials | T1098.001, T1136.003 |
| `AttachUserPolicy`, `AttachRolePolicy`, `PutUserPolicy`, `PutRolePolicy`, `AddUserToGroup` | iam | Privilege escalation | T1098.003 |
| `CreatePolicyVersion`, `SetDefaultPolicyVersion` | iam | Escalation by rewriting a policy | T1098.003 |
| `UpdateAssumeRolePolicy`, `CreateRole` | iam | Backdoor trust for an external account | T1098.003 |
| `AssumeRole`, `AssumeRoleWithWebIdentity`, `GetSessionToken`, `GetFederationToken` | sts | Pivoting / session minting | T1078.004 |
| `GetSecretValue`, `GetParameter(s)` (with decryption), `Decrypt` | secretsmanager, ssm, kms | Credential access | T1555.006 |
| `PutBucketPolicy`, `PutBucketAcl`, `DeletePublicAccessBlock`, `PutPublicAccessBlock` | s3 | Exposure / exfil staging | T1530 |
| `GetObject`, `ListObjects` (data events, only if enabled) | s3 | Data access/exfil | T1530 |
| `StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors` | cloudtrail | Defense evasion | T1562.008 |
| `DeleteDetector`, `UpdateDetector`, `DisassociateFromMasterAccount`, `DeleteFlowLogs` | guardduty, ec2 | Disabling detection | T1562.008 |
| `RunInstances` (esp. GPU types, unused regions), `CreateKeyPair`, `ImportKeyPair` | ec2 | Crypto-mining / foothold | T1496, T1578.002 |
| `AuthorizeSecurityGroupIngress` | ec2 | Opening access | T1562.007 |
| `ModifyInstanceAttribute` (userData), `SendCommand` | ec2, ssm | Code execution on instances | T1059 |
| `CreateSnapshot` + `ModifySnapshotAttribute` / `ModifyImageAttribute` (share to external account) | ec2 | Data theft via snapshot sharing | T1537 |
| `CreateFunction`, `UpdateFunctionCode`, `AddPermission` | lambda | Persistence / execution | T1648 |
| `ScheduleKeyDeletion`, `DisableKey` | kms | Impact / ransom on data | T1485 |
| `LeaveOrganization`, `CreateAccount` | organizations | Account-level persistence/impact | T1098 |

Key fields: `eventTime` (UTC), `eventSource`, `eventName`, `awsRegion`,
`sourceIPAddress`, `userAgent`, `errorCode` (bursts of `AccessDenied` = attacker
probing permissions), `userIdentity.type/arn/accessKeyId/sessionContext`,
`requestParameters`, `responseElements`, `recipientAccountId`.

## GuardDuty findings to prioritise

| Finding type | Meaning |
|---|---|
| `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` | Instance role credentials used from outside AWS |
| `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS` | Instance role credentials used from another AWS account |
| `Stealth:IAMUser/CloudTrailLoggingDisabled` | A trail was disabled |
| `Policy:IAMUser/RootCredentialUsage` | Root user API activity |
| `CryptoCurrency:EC2/BitcoinTool.B` / `.B!DNS` | Instance talking to mining infrastructure |
| `Backdoor:EC2/C&CActivity.B` / `.B!DNS` | Instance contacting known C2 |
| `UnauthorizedAccess:EC2/SSHBruteForce`, `UnauthorizedAccess:EC2/RDPBruteForce` | Brute force (check direction: instance as target or source) |
| `Persistence:IAMUser/AnomalousBehavior`, `PrivilegeEscalation:IAMUser/AnomalousBehavior`, `CredentialAccess:IAMUser/AnomalousBehavior`, `Discovery:IAMUser/AnomalousBehavior` | ML-based anomalous API usage by an identity |
| `Exfiltration:S3/AnomalousBehavior`, `Impact:S3/AnomalousBehavior.Delete` | Unusual S3 reads/deletes (requires S3 Protection) |
| `Policy:S3/BucketBlockPublicAccessDisabled` | Block Public Access removed |
| `PenTest:IAMUser/KaliLinux` (and similar) | API calls from a pentest distribution user agent |

GuardDuty finding types evolve; check the current finding-type list in the
GuardDuty User Guide for anything unfamiliar.

## Queries

### Athena over CloudTrail (S3)

```sql
-- Athena: everything one access key did, all regions. Tune: table name, partitions/date filter.
SELECT eventtime, awsregion, eventsource, eventname, sourceipaddress, useragent, errorcode,
       requestparameters
FROM cloudtrail_logs
WHERE useridentity.accesskeyid = 'AKIAEXAMPLEKEYID'
  AND eventtime BETWEEN '2026-03-01T00:00:00Z' AND '2026-03-08T00:00:00Z'
ORDER BY eventtime;
```

```sql
-- Athena: IAM persistence and logging tampering across the account in 30 days.
SELECT eventtime, useridentity.arn, eventname, awsregion, sourceipaddress, requestparameters
FROM cloudtrail_logs
WHERE eventname IN ('CreateAccessKey','CreateUser','CreateLoginProfile','UpdateLoginProfile',
                    'AttachUserPolicy','AttachRolePolicy','PutUserPolicy','PutRolePolicy',
                    'CreatePolicyVersion','UpdateAssumeRolePolicy','StopLogging','DeleteTrail',
                    'UpdateTrail','PutEventSelectors','DeleteDetector')
  AND eventtime > to_iso8601(current_timestamp - interval '30' day)
ORDER BY eventtime;
```

```sql
-- Athena: RunInstances in regions you do not use. Tune: allowed-regions list.
SELECT eventtime, awsregion, useridentity.arn, sourceipaddress,
       json_extract_scalar(requestparameters, '$.instanceType') AS instance_type
FROM cloudtrail_logs
WHERE eventname = 'RunInstances'
  AND awsregion NOT IN ('eu-west-1','eu-central-1')
ORDER BY eventtime;
```

### CloudTrail Lake

```sql
-- CloudTrail Lake: source IPs and user agents used by a principal. Replace <event-data-store-id>.
SELECT sourceIPAddress, userAgent, count(*) AS calls, min(eventTime) AS first_seen, max(eventTime) AS last_seen
FROM <event-data-store-id>
WHERE userIdentity.arn LIKE '%:user/ci-deploy%'
  AND eventTime > '2026-03-01 00:00:00'
GROUP BY sourceIPAddress, userAgent
ORDER BY first_seen;
```

## Credential compromise playbook

1. **Identify**: key ID, owning principal, where it was used (IPs, user agents,
   regions), first malicious use. Check where it leaked (public repo, CI logs,
   laptop, instance metadata via SSRF).
2. **Contain the key** (IC approval for production principals):
   - Attach the AWS managed policy `AWSDenyAll` to the user/role (explicit deny
     beats allows; reversible).
   - Deactivate, do not delete, the access key: `aws iam update-access-key
     --access-key-id <id> --status Inactive --user-name <user>`.
   - For roles: revoke active sessions (console "Revoke active sessions", which
     adds a deny policy conditioned on `aws:TokenIssueTime`), because
     temporary credentials stay valid until expiry otherwise.
   - Remove console password/login profile if the user should not have one.
3. **Scope**: run the Athena queries above for the key, then for every
   principal the attacker created, assumed (`AssumeRole` responses list the
   session), or modified. Repeat until no new principals appear.
4. **Eradicate**: after documenting, delete attacker-created users, keys,
   roles, policies, trust relationships, Lambda functions, instances, key
   pairs; rotate every secret the principal could read (Secrets Manager, SSM,
   environment variables, user data).
5. **Root user involvement**: treat as SEV1; reset root password and MFA via
   the account's root email (verify that mailbox is not compromised).

## Workload containment and evidence

| Step | Detail | Caution |
|---|---|---|
| Tag the resource | e.g. `IR-Case=<id>`, `IR-Status=Quarantine` | Do not rely on tags as a control |
| Enable termination protection | `aws ec2 modify-instance-attribute --disable-api-termination` | |
| Capture instance metadata | Describe-instances output, attached roles, SGs, ENIs, user data | |
| Snapshot all EBS volumes | `aws ec2 create-snapshot` per volume; share/copy to forensic account | Before stop/terminate or SG change if possible |
| Memory capture | Via SSM Run Command with a Linux tool such as AVML or LiME, or a Windows memory acquisition tool, to the evidence bucket | Requires SSM agent; changes the system slightly; document (`memory-forensics`) |
| Quarantine security group | Replace all SGs with one that has no inbound rules and outbound only to forensic tooling | Existing tracked connections may persist after SG changes; add a network ACL deny for full cut-off |
| Detach / restrict instance role | Remove or replace the instance profile; revoke role sessions | Breaks the workload |
| Deregister from load balancers / ASG | Prevent replacement or traffic | ASG may terminate an unhealthy instance; suspend processes first |
| Do not stop/terminate | Unless IC accepts loss of memory and instance-store data | |

## Evidence preservation

- CloudTrail: confirm an organisation trail (all regions, management events)
  exists; copy logs for the window to an Object Lock bucket in a separate
  security/forensics account. Note CloudTrail Event history covers only 90
  days of management events.
- Data events (S3 object-level, Lambda) exist only if enabled beforehand.
- VPC Flow Logs, Route 53 Resolver query logs, S3 server access logs, ELB/ALB
  logs, WAF logs, EKS audit logs: export what exists.
- Record hashes and acquisition details in the evidence log (`evidence-handling`).

## False positives & benign look-alikes

- `AccessDenied` bursts from misconfigured automation or new deployments.
- Console logins from new IPs by travelling engineers or new VPN egress.
- Infrastructure-as-code pipelines creating keys, roles and instances in
  new regions during a migration; check the pipeline role and commit history.
- Security tooling (CSPM, scanners) making read-only enumeration calls with
  distinctive user agents.
- AWS service-linked activity (`userIdentity.type = AWSService`).

## Pitfalls

- Deleting the key immediately (loses the ability to correlate cleanly; deactivate first).
- Forgetting temporary credentials already issued (role sessions keep working).
- Checking only the home region.
- Changing security groups and assuming established connections dropped.
- Terminating the instance before snapshotting.
- Missing persistence in other accounts of the organisation, cross-account trust
  policies, or identity center (IAM Identity Center) assignments.
- Assuming S3 data access can be ruled out when data events were not enabled
  (report as a gap, `defender-mindset`).

## Output

- Principal and key inventory: compromised, created, assumed; status of each.
- API activity timeline (UTC) per principal; data accessed (with gaps noted).
- Containment record; snapshot and log evidence IDs.
- Hand-offs: `hunt-cloud-control-plane`, `memory-forensics`, `linux-forensics`,
  `hardening-cloud`, `detection-engineering`, `incident-response`, `ir-report-writing`.

## References

- AWS Security Incident Response Guide (AWS whitepaper).
- AWS CloudTrail User Guide: CloudTrail record contents; CloudTrail Lake.
- Amazon GuardDuty User Guide: Finding types.
- AWS IAM User Guide: Revoking IAM role temporary security credentials; AWSDenyAll managed policy.
- Amazon EC2 User Guide: Security group connection tracking.
- MITRE ATT&CK Cloud (IaaS) matrix: T1078.004, T1098.001, T1136.003, T1530,
  T1537, T1562.008, T1496 - https://attack.mitre.org/techniques/T1078/004/
