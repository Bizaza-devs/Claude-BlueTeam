---
name: logging-coverage
description: Telemetry baseline a SOC needs and how to enable it. Covers Windows Advanced Audit Policy subcategories and key event IDs (4624, 4625, 4648, 4672, 4688 with command line, 4698, 4720, 4728, 4732, 4768, 4769, 4771, 5140, 5145, 7045, 1102), PowerShell 4104 script block logging, Sysmon (SwiftOnSecurity sysmon-config, olafhartong sysmon-modular) and Sysmon IDs 1-29, Linux auditd rules, Microsoft 365 Unified Audit Log and mailbox auditing, Entra ID logs, AWS CloudTrail data events, VPC Flow Logs, GuardDuty, GCP audit logs, Kubernetes audit policy, retention guidance and a data-source to ATT&CK coverage table. Use when asked "what logs do we need", "enable auditing", "Sysmon config", "auditd rules", "is the UAL on", "CloudTrail data events", "log retention", or for a coverage gap analysis.
---

# Logging coverage

You cannot detect, hunt or reconstruct what was never recorded. This skill is
the logging baseline: what to collect, how to switch it on, how long to keep it,
and how to prove it is actually arriving.

## When to use

- Onboarding a new estate, tenant or cloud account to the SOC.
- A detection or hunt needs a field that is not there (`detection-engineering`).
- Post-incident: "we could not tell what happened because..." (`post-incident-review`).
- ATT&CK coverage gap analysis (`/coverage`).
- Before an incident: verifying that the logs an investigation would need exist.

## Ground rules

- **"Enabled" is not "collected".** A source counts only when events from it are
  in the SIEM, parsed, for the expected number of hosts/accounts, verified by a
  query with counts (per host, last 24 h). Policy screenshots are not evidence.
- **Generate a test event for every source** you enable (create a scheduled
  task, run an encoded PowerShell echo, add a test user to a test group, list an
  S3 object) and confirm it arrives end-to-end with the fields you need.
- **Record gaps explicitly.** Every investigation report states which sources
  were missing or retained too briefly; never imply absence of activity from
  absence of logs.
- **Changing audit policy, agent config or cloud logging is a change**: go
  through change approval, size storage and licence cost first, and roll out in
  rings (pilot -> broad).
- **Protect the logs themselves:** forward off-host quickly, restrict who can
  disable logging, and alert on logging being disabled (1102, `StopLogging`,
  `DeleteTrail`, Sysmon service stopped).

## Workflow

1. **List what you must detect** (top ATT&CK techniques for your threat model,
   `threat-intel-ioc`, `defender-mindset`) and what an IR needs (identity,
   process, network, cloud control plane, email).
2. **Map techniques to data sources** using the coverage table below.
3. **Inventory current state per source:** enabled? collected? parsed? which
   hosts/accounts? retention?
4. **Prioritise gaps** by detection value per cost: process creation with command
   line, authentication, PowerShell, cloud control plane and identity logs first.
5. **Enable** with the configs below, through change control.
6. **Verify** end-to-end with test events; build a "source health" query per
   source (events per host per day) and alert on silence.
7. **Set retention** and archive tiers; document it.
8. **Re-assess** quarterly and after every incident.

## Windows: Advanced Audit Policy

Configure via GPO: Computer Configuration > Policies > Windows Settings >
Security Settings > Advanced Audit Policy Configuration. Also enable
"Audit: Force audit policy subcategory settings to override audit policy
category settings" so legacy category settings do not overwrite them.

| Category > Subcategory | Setting | Key events |
|---|---|---|
| Account Logon > Credential Validation | Success, Failure | 4776 (NTLM validation, on DCs) |
| Account Logon > Kerberos Authentication Service | Success, Failure (DCs) | 4768 (TGT requested), 4771 (pre-auth failed) |
| Account Logon > Kerberos Service Ticket Operations | Success, Failure (DCs) | 4769 (service ticket - Kerberoasting) |
| Account Management > User Account Management | Success, Failure | 4720 (user created), 4722, 4724 (password reset), 4738, 4740 (locked out) |
| Account Management > Security Group Management | Success | 4728 / 4732 / 4756 (member added to global / local / universal group) |
| Detailed Tracking > Process Creation | Success | 4688 (+ command line, see below) |
| DS Access > Directory Service Changes | Success (DCs) | 5136 (object modified - GPO, ACL, SPN changes); needs SACLs |
| Logon/Logoff > Logon | Success, Failure | 4624, 4625, 4648 (explicit credentials) |
| Logon/Logoff > Special Logon | Success | 4672 (privileged logon) |
| Logon/Logoff > Account Lockout | Failure | 4625 with lockout status |
| Object Access > File Share | Success, Failure | 5140 (share accessed) |
| Object Access > Detailed File Share | Failure (Success is very noisy; enable on high-value servers/DCs) | 5145 (share object access check, e.g. ADMIN$, SYSVOL) |
| Object Access > Other Object Access Events | Success, Failure | 4698 (scheduled task created), 4699-4702 |
| Policy Change > Audit Policy Change | Success | 4719 (audit policy changed) |
| System > Security System Extension | Success | 4697 (service installed - Security log) |

Always-on or other logs:
- **1102** - Security log cleared (Security log; generated regardless of policy).
- **System 7045** - new service installed (Service Control Manager); **System 104** - a log was cleared.
- **4688 command line:** GPO Administrative Templates > System > Audit Process
  Creation > "Include command line in process creation events" = Enabled.
- **PowerShell:** Administrative Templates > Windows Components > Windows
  PowerShell > "Turn on PowerShell Script Block Logging" (event **4104** in
  Microsoft-Windows-PowerShell/Operational) and "Turn on Module Logging" (4103).
  Transcription to a protected share is optional extra depth. Script block logs
  can contain secrets - restrict access.
- **Log size:** the Security log default size is small for a busy server or DC;
  raise it substantially via GPO (Event Log settings) and forward in near-real-time.
- Other useful channels: Microsoft-Windows-TaskScheduler/Operational,
  Microsoft-Windows-WMI-Activity/Operational, Microsoft-Windows-TerminalServices-*,
  Microsoft-Windows-Windows Defender/Operational, Microsoft-Windows-Bits-Client/Operational,
  Directory Service and DNS Server logs on DCs.

```powershell
# Verify effective audit policy on a host (run elevated)
auditpol /get /category:*
# Example: enable one subcategory locally (use GPO for fleet-wide settings)
auditpol /set /subcategory:"Process Creation" /success:enable
# Check the command-line policy registry value (1 = enabled)
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name ProcessCreationIncludeCmdLine_Enabled
```

## Sysmon

Install with a maintained community config and tune it, rather than writing
from scratch: **SwiftOnSecurity sysmon-config** (single, well-commented baseline)
or **olafhartong sysmon-modular** (modular, ATT&CK-mapped, several prebuilt
variants including a more verbose one for EDR-less environments).

```powershell
# Install / update config (elevated). Keep the config in version control.
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
.\Sysmon64.exe -c sysmonconfig.xml        # apply a new config
.\Sysmon64.exe -c                         # print current config
```

| ID | Event | ID | Event |
|---|---|---|---|
| 1 | Process creation (command line, hashes, parent) | 16 | Sysmon config state changed |
| 2 | File creation time changed (timestomping) | 17 | Pipe created |
| 3 | Network connection | 18 | Pipe connected |
| 4 | Sysmon service state changed | 19 | WMI event filter activity |
| 5 | Process terminated | 20 | WMI event consumer activity |
| 6 | Driver loaded | 21 | WMI consumer-to-filter binding |
| 7 | Image (DLL) loaded | 22 | DNS query |
| 8 | CreateRemoteThread | 23 | File delete (archived) |
| 9 | RawAccessRead (raw disk read) | 24 | Clipboard change |
| 10 | Process access (e.g. LSASS) | 25 | Process tampering (hollowing, herpaderping) |
| 11 | File create | 26 | File delete detected (logged, not archived) |
| 12 | Registry key/value create or delete | 27 | File block executable |
| 13 | Registry value set | 28 | File block shredding |
| 14 | Registry key/value rename | 29 | File executable detected |
| 15 | File stream created (ADS, Zone.Identifier) | 255 | Sysmon error |

Tuning notes: ID 7 and ID 3 are high volume - include-filter them to
interesting images/paths; ID 10 should target `lsass.exe` with dump-capable
access masks; ID 23 needs an archive directory with ACLs and disk-space limits;
IDs 27-29 are protective/blocking features (newer Sysmon versions) - roll out
carefully. Alert on Sysmon 4 and 16 and on the service being stopped.
If you run an EDR (e.g. MDE), compare its telemetry first; Sysmon then fills
specific gaps rather than duplicating everything.

## Linux: auditd and system logs

```bash
# /etc/audit/rules.d/50-blueteam.rules - baseline; load with: augenrules --load
# Tune: execve on busy servers is high volume - exclude noisy service accounts with -F auid!=... or -F exe!=...
-D
-b 8192
-f 1
# Process execution (both ABIs)
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=unset -k exec_user
-a always,exit -F arch=b32 -S execve -F auid>=1000 -F auid!=unset -k exec_user
-a always,exit -F arch=b64 -S execve -F euid=0 -k exec_root
# Identity and privilege files
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k priv_esc
-w /etc/sudoers.d/ -p wa -k priv_esc
# SSH and persistence locations
-w /etc/ssh/sshd_config -p wa -k sshd
-w /root/.ssh/ -p wa -k ssh_keys
-w /etc/cron.d/ -p wa -k cron
-w /etc/crontab -p wa -k cron
-w /var/spool/cron/ -p wa -k cron
-w /etc/systemd/system/ -p wa -k systemd
-w /etc/ld.so.preload -p wa -k preload
# Kernel modules and ptrace (rootkits, injection)
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules
-a always,exit -F arch=b64 -S ptrace -k ptrace
# Audit config tampering
-w /etc/audit/ -p wa -k audit_config
# Make rules immutable until reboot (last line; changes then require a reboot)
-e 2
```

- Query locally: `ausearch -k exec_user -i --start today`, `aureport -x --summary`.
- Forward with the SIEM agent or audisp/syslog; tools like Laurel convert auditd
  records into JSON lines that are easier to parse.
- Also collect: `/var/log/auth.log` or `/var/log/secure` (sshd, sudo), journald,
  web server access/error logs, shell history is not a security log (easily wiped).
- Community baselines: Florian Roth's (Neo23x0) auditd rules; CIS Benchmarks audit sections.

## Microsoft 365 and Entra ID

```powershell
# Exchange Online PowerShell: is the Unified Audit Log ingesting?
Get-AdminAuditLogConfig | Format-List UnifiedAuditLogIngestionEnabled
# Enable if False (change-controlled)
Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
# Mailbox auditing on by default at org level? (AuditDisabled should be False)
Get-OrganizationConfig | Format-List AuditDisabled
# Per-mailbox check, including whether MailItemsAccessed is audited
Get-Mailbox -Identity user@corp.example | Format-List AuditEnabled, AuditOwner, AuditDelegate, AuditAdmin
```

- **UAL** covers Exchange, SharePoint/OneDrive, Teams, Entra and more; search
  via Purview Audit or `Search-UnifiedAuditLog`; stream to the SIEM (Sentinel
  Microsoft 365 connector / Defender XDR `CloudAppEvents`, or the Office 365
  Management Activity API for other SIEMs).
- **MailItemsAccessed** is the key BEC/exfil record; its availability broadened
  beyond the Premium tier in recent years - verify it is in the mailbox's audit
  action lists in your tenant.
- Audit retention depends on licensing (Audit Standard vs Premium, plus
  retention policies/add-ons) - check current Microsoft Purview documentation
  and export to the SIEM for anything you need longer.
- **Entra ID:** send via Diagnostic settings to Log Analytics / Event Hub / storage:
  `SignInLogs`, `NonInteractiveUserSignInLogs`, `ServicePrincipalSignInLogs`,
  `ManagedIdentitySignInLogs`, `AuditLogs`, `RiskyUsers`, `UserRiskEvents`,
  `MicrosoftGraphActivityLogs`. Portal-only retention is short - always export.
  Hand-offs: `ir-bec-m365`, `ir-azure-entra`, `hardening-m365-entra`.

## AWS

```bash
# Organization-wide, multi-region trail with log file validation (run in the management account)
aws cloudtrail create-trail --name org-trail --s3-bucket-name <log-archive-bucket> \
  --is-multi-region-trail --is-organization-trail --enable-log-file-validation \
  --kms-key-id <kms-key-arn>
aws cloudtrail start-logging --name org-trail

# Add S3 object-level data events (cost! scope to sensitive buckets where possible)
aws cloudtrail put-event-selectors --trail-name org-trail --advanced-event-selectors '[
  {"Name":"Management events","FieldSelectors":[{"Field":"eventCategory","Equals":["Management"]}]},
  {"Name":"S3 data events","FieldSelectors":[
    {"Field":"eventCategory","Equals":["Data"]},
    {"Field":"resources.type","Equals":["AWS::S3::Object"]}]}]'

# Verify
aws cloudtrail get-trail-status --name org-trail
aws cloudtrail get-event-selectors --trail-name org-trail
```

- **CloudTrail management events** (control plane: `CreateUser`, `CreateAccessKey`,
  `AssumeRole`, `PutBucketPolicy`, `StopLogging`, `DeleteTrail`) - non-negotiable;
  Event history alone keeps only 90 days and is per-region.
- **Data events** (S3 `GetObject`/`PutObject`, Lambda `Invoke`, DynamoDB items,
  others) are off by default and billed - required to investigate data theft.
- Log archive in a separate account, bucket with versioning / Object Lock,
  restricted delete; alert on `StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors`.
- **VPC Flow Logs** (VPC or subnet level, to S3/CloudWatch) - consider a custom
  format adding fields such as `pkt-srcaddr`, `pkt-dstaddr`, `tcp-flags`, `flow-direction`.
- **Route 53 Resolver query logs** for DNS visibility.
- **GuardDuty** in every account and region via delegated admin; foundational
  sources are CloudTrail management events, VPC Flow Logs and DNS logs, with
  optional protection plans (S3, EKS, runtime monitoring, malware protection, RDS, Lambda).
- Also: Config (resource history), Security Hub findings, ELB/CloudFront/WAF access logs.
  Hand-offs: `ir-cloud-aws`, `hunt-cloud-control-plane`, `hardening-cloud`.

## GCP

- **Admin Activity** audit logs: always on, cannot be disabled.
- **Data Access** audit logs: off by default for most services (BigQuery is an
  exception) - enable per service in the IAM audit config (`DATA_READ`,
  `DATA_WRITE`, `ADMIN_READ`) at organisation or folder level; they can be high volume.
- **System Event** and **Policy Denied** logs also exist.
- Default storage: the `_Required` bucket (Admin Activity, System Event) keeps
  400 days; the `_Default` bucket keeps 30 days unless changed - create an
  **aggregated organisation sink** to BigQuery / Cloud Storage / Pub/Sub for the SIEM.
- Also: VPC Flow Logs (per subnet), Cloud DNS query logging, firewall rule logging,
  Security Command Center findings.

## Kubernetes audit policy

```yaml
# audit-policy.yaml - API server: --audit-policy-file, --audit-log-path (or webhook), --audit-log-maxage
# Tune: keep Secrets at Metadata (never log secret bodies); drop high-volume read-only system traffic
apiVersion: audit.k8s.io/v1
kind: Policy
omitStages: ["RequestReceived"]
rules:
  - level: None
    users: ["system:kube-proxy"]
    verbs: ["watch"]
  - level: None
    nonResourceURLs: ["/healthz*", "/readyz*", "/livez*", "/version"]
  - level: Metadata
    resources:
      - group: ""
        resources: ["secrets", "configmaps", "serviceaccounts/token"]
  - level: Request
    verbs: ["create"]
    resources:
      - group: ""
        resources: ["pods/exec", "pods/attach", "pods/portforward"]
  - level: RequestResponse
    resources:
      - group: "rbac.authorization.k8s.io"
        resources: ["roles", "rolebindings", "clusterroles", "clusterrolebindings"]
  - level: Request
    verbs: ["create", "update", "patch", "delete"]
    resources:
      - group: ""
        resources: ["pods", "services"]
      - group: "apps"
        resources: ["deployments", "daemonsets", "statefulsets"]
      - group: "batch"
        resources: ["jobs", "cronjobs"]
  - level: Metadata
```

Managed clusters: EKS control-plane logging (enable `audit` and `authenticator`
log types), AKS diagnostic settings (`kube-audit` or `kube-audit-admin`), GKE
Cloud Audit Logs for the Kubernetes API (Data Access for reads). Add runtime
telemetry (Falco, EDR on nodes) - audit logs do not show what ran inside a
container (`hunt-k8s-runtime`).

## Retention guidance

| Tier | Suggested minimum | Why |
|---|---|---|
| Hot, searchable in SIEM | 90 days | Most detections, triage and hunts |
| Total (hot + cheap archive) | 12 months or more | Dwell times of months are common in intrusions; IR needs the start of the story |
| Identity, cloud control plane, DC security logs | Longest you can afford | Highest investigative value per byte |

Benchmarks to cite: US OMB M-21-31 (federal agencies: 12 months active plus 18
months cold storage for covered log types), PCI DSS v4.0 Requirement 10.5.1 (12
months, with the most recent three months immediately available). Check legal
and privacy constraints (works councils, GDPR) before extending retention of
user-activity data, and document the decision.

## Data source -> ATT&CK coverage

| Data source | Key techniques it enables detection of |
|---|---|
| Process creation + command line (4688/Sysmon 1/EDR) | T1059.*, T1218.* (LOLBins), T1003.001 (dump commands), T1047, T1053.005, T1569.002, T1105, T1027 |
| PowerShell 4104 | T1059.001, T1027, T1140, T1105, T1003 (in-memory tools) |
| Logon events 4624/4625/4648/4672 | T1078, T1110.*, T1021.001/.002/.006, T1550.002 |
| Kerberos 4768/4769/4771 (DCs) | T1558.003 (Kerberoasting), T1558.004 (AS-REP roasting), T1110, T1558.001 |
| Account/group management 4720/4728/4732/4756 | T1136.002, T1098, T1078.002 |
| Service/task creation 7045/4697/4698 | T1543.003, T1053.005, T1569.002 |
| Share access 5140/5145 | T1021.002, T1039, T1570 |
| Directory Service Changes 5136 | T1484.001 (GPO modification), T1098, T1222.001 |
| Sysmon 10 (process access) | T1003.001, T1055 |
| Sysmon 8 / 25 | T1055.*, T1055.012 |
| Sysmon 12/13 (registry) | T1547.001, T1112, T1546.* , T1562.001 |
| Sysmon 19-21 (WMI) | T1546.003 |
| Sysmon 22 / DNS logs / Zeek dns.log | T1071.004, T1568.002 (DGA), T1048 |
| Sysmon 3 / EDR network / Zeek conn.log / VPC Flow | T1071, T1571, T1041, T1048, T1021, T1046 |
| Log clearing 1102/104, Sysmon 4/16 | T1070.001, T1562.002, T1562.001 |
| Linux auditd execve + file watches | T1059.004, T1053.003, T1543.002, T1098.004, T1574.006, T1547.006 |
| Entra sign-in logs | T1078.004, T1110.003, T1621, T1556, T1550.001 |
| Entra / M365 audit (UAL) | T1098.*, T1528, T1564.008, T1114.002/.003, T1137 |
| CloudTrail management | T1078.004, T1098.001, T1136.003, T1562.008, T1530 (with data events), T1580 |
| Kubernetes audit | T1609, T1610, T1611 (with runtime data), T1098 (RBAC), T1552.007 |

Use ATT&CK Navigator layers generated from this table plus deployed rules to
show coverage; tools such as DeTT&CT help score data-source quality and
visibility. Recent ATT&CK releases restructure detection guidance (data sources
-> detection strategies/analytics) - align your mapping to the version you report against.

## False positives & benign look-alikes

Coverage work has its own "false positives":

| Looks like | Reality | Check |
|---|---|---|
| Policy enabled in GPO | Overridden by legacy category settings or local policy | `auditpol /get` on sample hosts; force-subcategory setting |
| Source in SIEM | Only a subset of hosts forwarding | Distinct hosts per day vs asset inventory |
| Events present | Key field empty (no command line, no OriginalFileName) | Sample events, field fill rate |
| Trail exists | Single-region, or management events only, or stopped | `get-trail-status`, selectors, region coverage |
| UAL "on" | Ingestion disabled earlier, or licence lacks needed records | `UnifiedAuditLogIngestionEnabled`, test search for a known action |

## Pitfalls

- Turning on everything at once: Detailed File Share success, Filtering Platform
  Connection (5156) and Sysmon 7 without filters can flood the SIEM and the budget.
- Small local log sizes on DCs/servers - events roll over before forwarding catches up.
- No health monitoring: a source silently stops after an agent update.
- Clock skew across sources makes timelines wrong; enforce NTP everywhere.
- Logging secrets: script blocks, request bodies, Kubernetes Secrets at
  `RequestResponse` - restrict access or lower the level.
- Cloud logging configured in one region/account only; new accounts not auto-enrolled.
- Retention shorter than typical dwell time.

## Output

- Coverage matrix: source x status (enabled / collected / parsed / hosts / retention)
  with gaps ranked by detection value per cost.
- Change-ready configs (GPO settings list, Sysmon config choice, auditd rules,
  CLI commands) with rollout plan and test events.
- Source-health queries and alerts.
- Hand-offs: `detection-engineering` and `/coverage` (ATT&CK gaps),
  `hardening-windows-ad`, `hardening-linux`, `hardening-m365-entra`,
  `hardening-cloud`, `purple-team-validation` to verify telemetry with emulation.

## References

- Microsoft Learn: Advanced security audit policy settings; Audit Process Creation; PowerShell logging (about_Logging_Windows)
- Microsoft Sysinternals: Sysmon documentation; SwiftOnSecurity sysmon-config; olafhartong sysmon-modular
- Linux Audit documentation (auditctl, audit.rules, ausearch); CIS Benchmarks
- Microsoft Purview: Audit (Standard/Premium), mailbox auditing; Microsoft Entra diagnostic settings
- AWS: CloudTrail User Guide (data events, organization trails), VPC Flow Logs, Amazon GuardDuty User Guide
- Google Cloud: Cloud Audit Logs; Kubernetes documentation: Auditing
- OMB M-21-31; PCI DSS v4.0 Requirement 10; NIST SP 800-92 (log management)
- MITRE ATT&CK: https://attack.mitre.org/ ; ATT&CK Navigator; DeTT&CT
