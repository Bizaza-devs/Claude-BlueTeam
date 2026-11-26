---
name: kql-sentinel-defender
description: KQL for Microsoft Sentinel and Defender XDR advanced hunting - hunting queries, scheduled/NRT analytics rules and Defender custom detections. Covers core operators (where, summarize, join kinds, make-series, mv-expand, has vs contains), the tables DeviceProcessEvents, DeviceNetworkEvents, DeviceLogonEvents, DeviceFileEvents, DeviceRegistryEvents, IdentityLogonEvents, EmailEvents, CloudAppEvents, SigninLogs, AuditLogs, SecurityEvent, Syslog, CommonSecurityLog, time-window joins, series_decompose_anomalies, watchlists, entity mapping, and 10+ ready hunts (encoded PowerShell, LSASS dump, password spray, MFA fatigue, inbox rules, OAuth consent, brute force). Use when asked to "write a KQL query", "hunt in Sentinel/Defender", "build an analytics rule", "custom detection", or to tune a noisy KQL rule.
---

# KQL for Sentinel and Defender XDR

KQL is read top to bottom as a pipeline: filter early, narrow columns, then
aggregate. Most slow or wrong queries violate that order.

## When to use

- Hunting in Defender XDR advanced hunting or a Sentinel / Log Analytics workspace.
- Building a Sentinel scheduled or NRT analytics rule, or a Defender XDR custom detection.
- Converting a Sigma rule to KQL and fixing the output (`sigma-rules`).
- Investigating an entity during `alert-triage` or `incident-response`.

## Ground rules

- **State the time range and the table you queried with every result.** "No
  hits in `DeviceProcessEvents`, last 30d, 1,240 devices reporting" - an empty
  result without coverage numbers is not evidence of absence.
- **Confirm the data is there first:** `TableName | where TimeGenerated > ago(1d) | count`
  (or `Timestamp` in Defender) and distinct device/user counts.
- **No TP verdict from one query hit alone.** Corroborate with a second table or
  source (process + network, sign-in + audit, email + click).
- **Rules ship only after a TP test and a 30-day baseline** (`detection-engineering`).
  Defender advanced hunting keeps 30 days; for longer baselines use Sentinel /
  Log Analytics retention.

## Workflow

1. Pick the table that records the behaviour; check its schema (`TableName | getschema`).
2. Filter on time first, then on indexed/high-selectivity columns (`ActionType`,
   `EventID`, `FileName`), using `has` / `in~` before `contains` / regex.
3. `project` only the columns you need; `extend` derived fields.
4. Aggregate (`summarize`) to cluster results by entity; review the top clusters.
5. Join to a second table for corroboration within a time window.
6. For rules: add entity columns (AccountUpn, DeviceName, IPAddress, FileHash),
   tune exclusions into a `let` list or watchlist, then baseline.

## Core operators

| Operator | Use | Note |
|---|---|---|
| `where` | filter | `==` is case-sensitive, `=~` case-insensitive, `!~` |
| `has`, `has_any`, `has_all` | whole-term match | uses the term index - fast; `has "enc"` will not match `-encodedcommand` |
| `contains`, `startswith`, `endswith` | substring | case-insensitive by default; `_cs` variants are faster |
| `in`, `in~`, `!in~` | list membership | `in~` case-insensitive |
| `matches regex` | RE2 regex | slow; filter with `has` first |
| `project`, `project-away`, `extend` | shape columns | |
| `summarize ... by` | aggregate | `count()`, `dcount()`, `make_set()`, `arg_max()`, `min()`, `max()` |
| `bin(TimeGenerated, 1h)` | bucket time | for counting over time |
| `join kind=...` | correlate | default `innerunique` dedupes the left side - say the kind explicitly |
| `union` | stack tables | `union isfuzzy=true` tolerates missing tables |
| `mv-expand` | explode arrays | dynamic columns like `TargetResources` |
| `parse`, `extract()`, `parse_json()` | field extraction | |
| `let` | variables, lists, sub-queries | `materialize()` to reuse a costly sub-result |
| `make-series` | regular time series | for anomaly functions |
| `top`, `take` | limit | `take` is arbitrary rows, not "latest" |

Join kinds that matter: `inner` (all matches), `leftouter` (keep left rows),
`leftanti` (left rows with no match - "never seen before"), `leftsemi`.
Put the smaller table on the left.

## Table quick reference

| Table | Platform | Key columns |
|---|---|---|
| `DeviceProcessEvents` | XDR / Sentinel | `FileName`, `FolderPath`, `ProcessCommandLine`, `InitiatingProcessFileName`, `InitiatingProcessCommandLine`, `AccountName`, `SHA256`, `ProcessVersionInfoOriginalFileName` |
| `DeviceNetworkEvents` | XDR / Sentinel | `ActionType` (`ConnectionSuccess`...), `RemoteIP`, `RemotePort`, `RemoteUrl`, `InitiatingProcessFileName` |
| `DeviceLogonEvents` | XDR / Sentinel | `ActionType` (`LogonSuccess`/`LogonFailed`), `LogonType` (string, e.g. `Network`, `RemoteInteractive`), `AccountName`, `RemoteIP` |
| `DeviceFileEvents` | XDR / Sentinel | `ActionType` (`FileCreated`, `FileModified`, `FileRenamed`, `FileDeleted`), `FolderPath`, `FileName`, `SHA256` |
| `DeviceRegistryEvents` | XDR / Sentinel | `ActionType` (`RegistryValueSet`...), `RegistryKey`, `RegistryValueName`, `RegistryValueData` |
| `IdentityLogonEvents` | XDR (Defender for Identity / cloud) | `ActionType`, `Protocol`, `LogonType`, `AccountUpn`, `IPAddress`, `DeviceName`, `FailureReason` |
| `EmailEvents` | XDR (Defender for Office 365) | `NetworkMessageId`, `SenderFromAddress`, `RecipientEmailAddress`, `Subject`, `DeliveryAction`, `ThreatTypes`, `EmailDirection` |
| `CloudAppEvents` | XDR (Defender for Cloud Apps) | `Application`, `ActionType`, `AccountObjectId`, `AccountDisplayName`, `IPAddress`, `RawEventData` |
| `SigninLogs` | Sentinel (Entra ID) | `UserPrincipalName`, `ResultType` (string, `"0"` = success), `IPAddress`, `AppDisplayName`, `LocationDetails`, `ConditionalAccessStatus`, `AuthenticationRequirement`, `UserAgent` |
| `AuditLogs` | Sentinel (Entra ID) | `OperationName`, `InitiatedBy`, `TargetResources`, `Result`, `Category` |
| `SecurityEvent` | Sentinel (Windows via AMA) | `EventID`, `Computer`, `Account`, `TargetUserName`, `LogonType` (int), `IpAddress`, `CommandLine`, `NewProcessName` |
| `Syslog` | Sentinel (Linux via AMA) | `Computer`, `Facility`, `SeverityLevel`, `ProcessName`, `SyslogMessage` |
| `CommonSecurityLog` | Sentinel (CEF appliances) | `DeviceVendor`, `DeviceProduct`, `SourceIP`, `DestinationIP`, `DestinationPort`, `DeviceAction`, `RequestURL` |

Time column: Defender advanced hunting uses `Timestamp`; Sentinel/Log Analytics
tables use `TimeGenerated` (XDR tables streamed to Sentinel carry both). The
queries below use `Timestamp` for XDR tables and `TimeGenerated` for Sentinel-only
tables - swap as needed. Non-interactive sign-ins are in `AADNonInteractiveUserSignInLogs`
(same schema family) - include them for spray and token hunts.

## Time-window correlation pattern

```kql
// XDR: process launched from Office, followed within 5 min by an outbound connection from the same process
// Tune: parent list, exclude known add-ins, window size
let lookback = 7d;
let spawns = DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe","outlook.exe")
    | where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe")
    | project DeviceId, DeviceName, SpawnTime = Timestamp, FileName, ProcessCommandLine, ProcessId;
let conns = DeviceNetworkEvents
    | where Timestamp > ago(lookback)
    | where RemoteIPType == "Public"
    | project DeviceId, NetTime = Timestamp, InitiatingProcessId, InitiatingProcessFileName, RemoteIP, RemoteUrl, RemotePort;
spawns
| join kind=inner (conns) on $left.DeviceId == $right.DeviceId, $left.ProcessId == $right.InitiatingProcessId
| where NetTime between (SpawnTime .. SpawnTime + 5m)
| project SpawnTime, DeviceName, FileName, ProcessCommandLine, RemoteIP, RemoteUrl, RemotePort
```

Process IDs are reused; the time window prevents false joins. In Defender, prefer
joining on `InitiatingProcessCreationTime` as well when available.

## Anomaly detection with make-series

```kql
// Sentinel: hourly failed sign-ins per user, flag statistical spikes (14d)
// Tune: threshold 3 (higher = fewer anomalies), minimum count filter, exclude service accounts
let start = ago(14d); let end = now();
SigninLogs
| where TimeGenerated between (start .. end)
| where ResultType != "0"
| make-series Failures = count() default = 0 on TimeGenerated from start to end step 1h by UserPrincipalName
| extend (Anomaly, Score, Baseline) = series_decompose_anomalies(Failures, 3, -1, "linefit")
| mv-expand TimeGenerated to typeof(datetime), Failures to typeof(long), Anomaly to typeof(int), Score to typeof(double), Baseline to typeof(double)
| where Anomaly == 1 and Failures > 20
| project TimeGenerated, UserPrincipalName, Failures, Baseline = round(Baseline, 1), Score = round(Score, 1)
```

`series_decompose_anomalies(series, threshold, seasonality, trend)`: `-1` lets
it detect seasonality; returns flags (+1 spike, -1 dip), scores and baseline.

## Watchlists and allowlists

```kql
// Sentinel: exclude known admin jump hosts kept in a watchlist with alias "AdminHosts" (SearchKey = host name)
let adminHosts = _GetWatchlist("AdminHosts") | project SearchKey;
SecurityEvent
| where TimeGenerated > ago(1d) and EventID == 4624 and LogonType == 10
| where Computer !in~ (adminHosts)
| summarize Logons = count(), Sources = make_set(IpAddress, 20) by Computer, TargetUserName
```

Keep exclusions in watchlists (or a `let` datatable in the repo) with owner and
review date - not inline magic strings scattered across rules.

## Analytics rule vs custom detection

| Setting | Sentinel scheduled analytics rule | Sentinel NRT rule | Defender XDR custom detection |
|---|---|---|---|
| Runs | Every 5 min to 14 days | About every minute | Fixed choices (e.g. every 1, 3, 12, 24 h) and a near-real-time option for supported tables |
| Lookback | Up to 14 days | Since last run | Tied to frequency (check current docs) |
| Required output | Any; map entities in the rule | Same | Must return `Timestamp` and the identifiers for the impacted entity (e.g. `DeviceId`, `ReportId`) |
| Entities | Entity mapping (Account, Host, IP, File, URL...) | Same | Impacted entities chosen in the wizard |
| Grouping | Alert grouping + incident grouping by entities | Same | Alerts grouped into incidents by XDR correlation |
| Response | Automation rules / playbooks (Logic Apps) | Same | Built-in actions: isolate device, collect investigation package, run AV scan, restrict app execution, quarantine file, disable user, etc. |
| Suppression | Stop running query for N hours after alert | n/a | Dedup by entity/time handled by platform |

Rule settings checklist: lookback >= frequency + ingestion delay (Log Analytics
ingestion can lag several minutes), entity mapping complete, custom details
carry the command line / IP for the analyst, severity justified, ATT&CK tactics
and techniques set, automated response actions approved (isolation and account
disable affect users - require IR lead / change approval).

## Ready hunting queries

```kql
// 1. XDR: encoded PowerShell, rare across fleet (T1059.001, T1027)
// Tune: exclude management agents by InitiatingProcessFolderPath; raise rarity threshold for large estates
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe","pwsh.exe") or ProcessVersionInfoOriginalFileName =~ "PowerShell.EXE"
| where ProcessCommandLine matches regex @"(?i)\s[-/](e|ec|en|enc[a-z]*)\s"
| summarize Devices = dcount(DeviceId), Example = take_any(ProcessCommandLine), Parents = make_set(InitiatingProcessFileName, 10) by CmdHash = hash_sha256(ProcessCommandLine)
| where Devices <= 3
```

```kql
// 2. XDR: LSASS dump via comsvcs MiniDump or procdump (T1003.001)
// Tune: none expected; any hit is high severity - verify parent and user
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName =~ "rundll32.exe" and ProcessCommandLine contains "comsvcs" and (ProcessCommandLine contains "minidump" or ProcessCommandLine contains "#24"))
     or (ProcessCommandLine has_any ("procdump","procdump64") and ProcessCommandLine has "lsass")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

```kql
// 3. XDR: Run-key persistence by non-installer processes (T1547.001)
// Tune: allowlist signed updaters by InitiatingProcessFolderPath
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where ActionType == "RegistryValueSet"
| where RegistryKey contains @"\CurrentVersion\Run"          // also matches RunOnce
| where InitiatingProcessFolderPath !startswith @"c:\program files"
| where RegistryValueData matches regex @"(?i)(\\AppData\\|\\Temp\\|\\Users\\Public\\|powershell|mshta|rundll32|https?://)"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
```

```kql
// 4. XDR: executable dropped in user-writable path then executed within 10 min (T1204, T1105)
// Tune: exclude browsers' update folders, developer machines
let drops = DeviceFileEvents
    | where Timestamp > ago(3d) and ActionType == "FileCreated"
    | where FileName endswith ".exe" or FileName endswith ".dll" or FileName endswith ".scr"
    | where FolderPath contains @"\AppData\Local\Temp\" or FolderPath contains @"\Downloads\" or FolderPath contains @"\Users\Public\"
    | project DeviceId, DropTime = Timestamp, SHA256, DropPath = FolderPath, Dropper = InitiatingProcessFileName;
DeviceProcessEvents
| where Timestamp > ago(3d)
| join kind=inner (drops) on DeviceId, SHA256
| where Timestamp between (DropTime .. DropTime + 10m)
| project Timestamp, DeviceName, DropPath, Dropper, FileName, ProcessCommandLine, SHA256
```

```kql
// 5. Sentinel: password spray - one IP, many users, few attempts each (T1110.003)
// Tune: thresholds; exclude known NAT/egress IPs of your org; include AADNonInteractiveUserSignInLogs
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(1d)
| where ResultType in ("50126","50053","50057")   // invalid creds, locked, disabled
| summarize Users = dcount(UserPrincipalName), Attempts = count(), Apps = make_set(AppDisplayName, 10), UAs = make_set(UserAgent, 5) by IPAddress, bin(TimeGenerated, 1h)
| where Users >= 15 and Attempts / Users < 4
```

```kql
// 6. Sentinel: MFA fatigue - repeated MFA denials/timeouts followed by success (T1621)
// Tune: failure count; result codes vary by MFA method - validate in your tenant
let window = 1h;
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType in ("500121","0")
| summarize Fails = countif(ResultType != "0"), FirstSuccess = minif(TimeGenerated, ResultType == "0"), FirstFail = minif(TimeGenerated, ResultType != "0"), IPs = make_set(IPAddress, 10)
    by UserPrincipalName, bin(TimeGenerated, window)
| where Fails >= 5 and isnotempty(FirstSuccess) and FirstSuccess > FirstFail
```

```kql
// 7. Sentinel: OAuth consent and new credentials on apps/service principals (T1528, T1098.001)
// Tune: exclude change-managed automation accounts by InitiatedBy
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName in ("Consent to application", "Add service principal credentials", "Add app role assignment to service principal")
     or OperationName has "Certificates and secrets management"
| extend Actor = coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
| mv-expand Target = TargetResources
| project TimeGenerated, OperationName, Actor, TargetName = tostring(Target.displayName), TargetId = tostring(Target.id), Result
```

```kql
// 8. XDR: suspicious inbox rules - forward, delete or move to obscure folders (T1564.008, T1114.003)
// Tune: Exchange operation names; parse RawEventData parameters per your data
CloudAppEvents
| where Timestamp > ago(30d)
| where Application == "Microsoft Exchange Online"
| where ActionType in ("New-InboxRule","Set-InboxRule","UpdateInboxRules")
| extend Params = tostring(RawEventData.Parameters)
| where Params has_any ("ForwardTo","RedirectTo","ForwardAsAttachmentTo","DeleteMessage","MoveToFolder","RSS Subscriptions","Conversation History")
| project Timestamp, AccountDisplayName, IPAddress, ActionType, Params
```

```kql
// 9. XDR: delivered email from first-seen external sender domain with attachment (T1566.001)
// Tune: lookback for "first seen"; exclude newsletters; join EmailAttachmentInfo for file types
let known = EmailEvents
    | where Timestamp between (ago(30d) .. ago(1d)) and EmailDirection == "Inbound"
    | distinct SenderFromDomain;
EmailEvents
| where Timestamp > ago(1d) and EmailDirection == "Inbound" and DeliveryAction == "Delivered" and AttachmentCount > 0
| where SenderFromDomain !in (known)
| project Timestamp, NetworkMessageId, SenderFromAddress, RecipientEmailAddress, Subject, AttachmentCount, ThreatTypes
```

```kql
// 10. XDR: Kerberos/NTLM failures across many accounts from one device (T1110, T1558)
// Tune: requires Defender for Identity; threshold per environment
IdentityLogonEvents
| where Timestamp > ago(1d)
| where ActionType == "LogonFailed" and Protocol in~ ("Kerberos","Ntlm")
| summarize Accounts = dcount(AccountUpn), Failures = count(), Reasons = make_set(FailureReason, 10) by DeviceName, IPAddress, bin(Timestamp, 30m)
| where Accounts >= 10
```

```kql
// 11. Sentinel: Windows brute force followed by success from the same IP (T1110.001)
// Tune: LogonType filter; exclude vulnerability scanners
SecurityEvent
| where TimeGenerated > ago(1d) and EventID in (4625, 4624)
| summarize Failed = countif(EventID == 4625), Success = countif(EventID == 4624), Accounts = make_set(TargetUserName, 20), LastSuccess = maxif(TimeGenerated, EventID == 4624)
    by IpAddress, Computer
| where Failed >= 20 and Success > 0
```

```kql
// 12. Sentinel: Security log cleared or audit policy changed (T1070.001, T1562.002)
// Tune: none - always review
SecurityEvent
| where TimeGenerated > ago(30d) and EventID in (1102, 4719)
| project TimeGenerated, Computer, EventID, Account, Activity
```

```kql
// 13. Sentinel: SSH brute force on Linux (T1110)
// Tune: message format varies by distro and sshd version
Syslog
| where TimeGenerated > ago(1d)
| where ProcessName == "sshd" and SyslogMessage has "Failed password"
| extend SrcIP = extract(@"from\s+(\d{1,3}(?:\.\d{1,3}){3})", 1, SyslogMessage), User = extract(@"for (invalid user )?(\S+)", 2, SyslogMessage)
| summarize Attempts = count(), Users = dcount(User) by Computer, SrcIP
| where Attempts > 30
```

```kql
// 14. Sentinel: firewall - internal host allowed to rare external port (T1571)
// Tune: DeviceAction values differ per vendor; common-port list; baseline window
CommonSecurityLog
| where TimeGenerated > ago(1d)
| where DeviceAction in~ ("allow","accept","permit")
| where ipv4_is_private(SourceIP) and not(ipv4_is_private(DestinationIP))
| where DestinationPort !in (80, 443, 53, 123, 25, 587, 993, 22)
| summarize Conns = count(), Dests = dcount(DestinationIP) by DestinationPort, DeviceVendor
| where Conns < 50
| order by Conns asc
```

## False positives & benign look-alikes

| Query | Benign source | Distinguish by |
|---|---|---|
| Encoded PowerShell | Intune/SCCM, vendor agents | Parent is the agent service from Program Files, same command on many devices |
| Run keys | Software installers/updaters | Signed binary in Program Files, matches install event |
| Password spray | Corporate egress NAT, misconfigured service with expired password | Single user repeated vs many users; app = legacy protocol client |
| MFA fatigue | User genuinely struggling with a new phone | Same IP/device as usual, user confirms via out-of-band call |
| OAuth consent | Admin-approved enterprise apps | Publisher verified, change ticket, consent by admin role |
| Inbox rules | User organising mail | Rule targets newsletters; created from usual IP/device |

Verdict table:

| Verdict | Evidence |
|---|---|
| True Positive | Hit + corroboration in a second table (network/sign-in/audit) and no owner explanation |
| Benign True Positive | Behaviour real, sanctioned (admin, pentest with engagement ID) |
| False Positive | Logic matched unrelated data (e.g. `contains` hit in a URL) - fix the query |
| Needs more data | Device not onboarded, table missing, retention too short - say so |

## Pitfalls

- `ResultType` in `SigninLogs` is a **string**; `ResultType == 0` silently fails.
- `has` matches terms: `has "enc"` misses `-encodedcommand`; use `has_any` with full terms or `contains`/regex after a cheap pre-filter.
- Default `join` is `innerunique` - it drops duplicate left keys; specify `kind=`.
- Joins without a time-window predicate explode on reused PIDs and long lookbacks.
- `take 10` is not "the latest 10" - use `top 10 by Timestamp desc`.
- Defender advanced hunting results are capped (row count and query resource limits); aggregate rather than dumping raw rows.
- Dynamic columns (`InitiatedBy`, `LocationDetails`, `RawEventData`) need `tostring()` before comparison.
- Rule lookback shorter than frequency + ingestion delay leaves blind gaps.

## Output

- Query (labelled with platform, time range, tuning notes) plus a results summary
  with counts and the coverage statement.
- For rules: analytics-rule/custom-detection settings table, entity mapping,
  baseline numbers, ADS link (`detection-engineering`).
- Hand-offs: `alert-triage` / `/investigate` for hits, `hunt-dispatch` for
  broader hunts, `ir-bec-m365` and `ir-azure-entra` for identity/mail findings,
  `sigma-rules` to make the rule portable.

## References

- Microsoft Learn: Kusto Query Language overview; `series_decompose_anomalies()`; join flavors
- Microsoft Learn: Advanced hunting schema reference (Device*, Identity*, Email*, CloudAppEvents tables)
- Microsoft Learn: SigninLogs, AuditLogs, SecurityEvent, Syslog, CommonSecurityLog table references
- Microsoft Learn: Create custom detection rules (Defender XDR); Create scheduled analytics rules and NRT rules (Sentinel); Watchlists
- Microsoft Entra authentication and authorization error codes (AADSTS codes such as 50126, 500121)
- Azure-Sentinel GitHub repository (hunting queries, analytics rules)
- MITRE ATT&CK: https://attack.mitre.org/techniques/T1110/003/, https://attack.mitre.org/techniques/T1621/
