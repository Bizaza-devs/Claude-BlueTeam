---
name: hunt-lateral-movement
description: Threat hunt for Windows lateral movement (TA0008): PsExec/PAExec and Impacket-style remote services (7045, named pipes), WMI remote execution (WmiPrvSE children, wmiexec output), WinRM (wsmprovhost, WinRM 91), RDP (4624 type 10, TerminalServices 1149, LSM 21/22/25, tscon hijack), SMB admin shares (5140/5145), DCOM (MMC20, Excel), remote scheduled tasks (atexec), pass-the-hash/ticket logon patterns (4624 type 3 NTLM, type 9 seclogo, 4648), OpenSSH on Windows, and graph analysis of first-seen source-destination pairs. KQL, SPL and Sigma per behaviour. Use when asked to "hunt lateral movement", "who logged on where", "PsExec in the estate", "T1021", "T1550.002", "pass the hash", "RDP from workstations" or "new admin connections".
---

# Hunt: lateral movement

Lateral movement needs three things: a credential, a network path and a remote
execution primitive. Hunt the execution primitive on the destination (it leaves
the best artefacts), confirm with the logon on the destination and the
connection from the source, then graph who-talks-to-whom for paths that have
never existed before.

## When to use

- Intel or an incident says the actor moves with PsExec, WMI, WinRM, RDP, DCOM,
  remote tasks or stolen hashes/tickets.
- After credential theft is suspected (`hunt-credential-access`): where did the
  credential go next?
- A workstation shows admin-share writes, remote service creation or inbound
  RDP/WinRM that IT does not recognise.
- Building the "normal admin paths" baseline for a tiering project.

## Ground rules

1. **Two ends or it did not happen.** A lateral-movement finding names the
   source host, destination host, account, primitive and time, and is
   supported by evidence from at least two of: destination execution,
   destination logon (4624/LSM), source process/connection, network flow.
2. **Logon type and auth package before conclusions.** Do not call
   "pass-the-hash" on a 4624 without logon type, authentication package,
   logon process, source IP/workstation and the account's normal pattern.
3. **Admin tools are dual-use.** PsExec, WinRM and RDP are legitimate; the
   verdict depends on source host, account, time and change record, never on
   the tool name alone.
4. **No account disables or host isolation from a hunt.** Hand confirmed TPs
   to `incident-response`; containment goes through `/contain` with approval.

## Workflow

1. Hypothesis and scope via `hunt-dispatch` (e.g. "workstation-to-workstation
   admin logons in the last 30 days are only from IT jump hosts").
2. Data check: 4624/4625/4648, 5140/5145, 7045, TerminalServices logs,
   WinRM/Operational, Sysmon or MDE process + network on destinations.
3. Destination-first: remote execution artefacts (sections 1-4).
4. Logon patterns: RDP, NTLM/Kerberos anomalies, PtH/PtT (sections 5-6).
5. Graph: first-seen source -> destination -> account triples (section 7).
6. Pivot each lead to the source host (what ran there just before?) and to
   credentials (`hunt-credential-access`).
7. Conclude, report, convert stable patterns into detections.

## ATT&CK sub-technique map

| Primitive | ATT&CK | Destination evidence | Source evidence |
|---|---|---|---|
| RDP | T1021.001 | 4624 type 10 (7 on reconnect), RemoteConnectionManager 1149, LSM 21/22/25 | mstsc.exe, `Terminal Server Client\Servers` key, RDPClient/Operational 1024/1102 |
| SMB / admin shares | T1021.002 | 5140/5145 ADMIN$, C$, IPC$; files dropped | `net use`, `copy \\host\c$` |
| DCOM | T1021.003 | mmc.exe / excel.exe `-Embedding` spawning shells | PowerShell `GetTypeFromProgID` / `[Activator]` |
| SSH | T1021.004 | OpenSSH/Operational "Accepted ...", sshd children | ssh.exe outbound |
| WinRM | T1021.006 | wsmprovhost.exe / winrshost.exe children, WinRM 91 | WinRM 6, `Invoke-Command`, `Enter-PSSession`, winrs |
| WMI | T1047 | WmiPrvSE.exe children, 4624 type 3 | `wmic /node:`, `Invoke-WmiMethod -ComputerName` |
| Remote service (PsExec, Impacket) | T1569.002, T1543.003 | 7045/4697, pipes, ADMIN$ binary | psexec.exe, `sc \\host create` |
| Remote scheduled task | T1053.005 | 4698 + 4699 short-lived task, Tasks folder | `schtasks /s`, atexec |
| Pass the hash / ticket | T1550.002 / T1550.003 | 4624 type 3 NTLM local admin; Kerberos from unusual host | 4624 type 9 seclogo, 4648, LSASS access |
| RDP session hijack | T1563.002 | tscon.exe run as SYSTEM | - |
| Tool transfer | T1570 | 5145 write of .exe/.dll/.ps1 to admin share | SMB copy |

## Data sources required

| Source | Use | Note |
|---|---|---|
| Security 4624/4625/4634/4648/4672 | Logons, explicit creds, admin logons | "Audit Logon", "Audit Special Logon" |
| Security 5140/5145 | Share access, file-level share access | 5145 needs "Audit Detailed File Share" (high volume, scope to servers/DCs if needed) |
| System 7045, Security 4697/4698/4699 | Remote services/tasks | See `hunt-windows-persistence` |
| TerminalServices-RemoteConnectionManager/Operational, TerminalServices-LocalSessionManager/Operational | RDP | Collect from servers and workstations |
| Microsoft-Windows-WinRM/Operational, PowerShell/Operational 4103/4104 | WinRM | On destination |
| Sysmon 1/3/17/18 or MDE DeviceProcessEvents/DeviceNetworkEvents/DeviceLogonEvents | Process, network, pipes | Required on destinations |
| MDI IdentityLogonEvents / DC 4768/4769/4776 | Auth path, NTLM/Kerberos | DC logs are the cheapest wide view |
| Zeek/NetFlow (smb_mapping, dce_rpc, rdp, conn) | Network confirmation | Internal east-west visibility is often missing |

## Behaviours and queries

### 1. Remote service execution (PsExec, PAExec, Impacket psexec/smbexec)

```kql
// MDE: services installed whose binary/command points at admin-share drops, COMSPEC or PsExec-style names.
DeviceEvents
| where Timestamp > ago(30d) and ActionType == "ServiceInstalled"
| extend AF = parse_json(AdditionalFields)
| extend ServiceName = tostring(AF.ServiceName)
| where ServiceName in~ ("PSEXESVC", "RemComSvc", "csexecsvc") or ServiceName startswith "PAExec"
    or (FolderPath matches regex @"(?i)^c:\\windows\\[A-Za-z]{8}\.exe$")   // Impacket-style random binary in ADMIN$; verify FolderPath holds the image path
    or tostring(AF) has_any ("%COMSPEC%", @"\\127.0.0.1\", "cmd.exe /Q /c")
| project Timestamp, DeviceName, ServiceName, FolderPath, FileName, AdditionalFields, InitiatingProcessAccountName
```

```spl
index=wineventlog source="XmlWinEventLog:System" EventCode=7045
  (ServiceName IN ("PSEXESVC","RemComSvc","csexecsvc") OR ServiceName="PAExec*" OR ImagePath="*%COMSPEC%*" OR ImagePath="*\\\\127.0.0.1\\*" OR ImagePath="*ADMIN$*")
| table _time host ServiceName ImagePath AccountName
```

```yaml
title: PsExec-Style Named Pipe Created On Destination
status: experimental
logsource: {product: windows, category: pipe_created}
detection:
  selection:
    PipeName|startswith: ['\PSEXESVC', '\PAExec', '\RemCom_communicaton', '\csexecsvc']
  condition: selection
falsepositives: [IT operations using PsExec/PAExec from jump hosts - allowlist by source host via the matching 4624]
level: medium
tags: [attack.lateral_movement, attack.execution, attack.t1569.002, attack.t1021.002]
```

Impacket `psexec` uses randomised service and binary names (dropped to
`ADMIN$`), `smbexec` uses a service whose ImagePath runs `%COMSPEC%` with an
`echo ... ^> \\127.0.0.1\...` style redirection; PsExec's own service can be
renamed with `-r`. Stack 7045 by ImagePath shape rather than by name.

### 2. WMI, WinRM and DCOM remote execution

```kql
// MDE: children of remote-execution hosts on servers/workstations. Tune: monitoring agents that use WMI/WinRM.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("wmiprvse.exe", "wsmprovhost.exe", "winrshost.exe")
    or (InitiatingProcessFileName in~ ("mmc.exe", "excel.exe", "outlook.exe") and InitiatingProcessCommandLine has "-Embedding")
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe")
| extend WmiExecOutput = ProcessCommandLine matches regex @"(?i)1>\s*\\\\127\.0\.0\.1\\ADMIN\$\\__\d+"
| summarize Count = count(), Hosts = dcount(DeviceId), Sample = any(ProcessCommandLine), WmiExec = max(toint(WmiExecOutput))
    by InitiatingProcessFileName, FileName, AccountName
| order by Hosts asc
```

```spl
index=sysmon source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  (ParentImage IN ("*\\WmiPrvSE.exe","*\\wsmprovhost.exe","*\\winrshost.exe") OR (ParentImage IN ("*\\mmc.exe","*\\excel.exe") ParentCommandLine="*-Embedding*"))
  Image IN ("*\\cmd.exe","*\\powershell.exe","*\\pwsh.exe","*\\rundll32.exe","*\\mshta.exe")
| eval wmiexec=if(match(CommandLine,"127\.0\.0\.1.ADMIN\$.__"),1,0)
| stats count dc(host) as hosts values(CommandLine) as cmds by ParentImage Image User wmiexec
```

```yaml
title: Shell Spawned By WMI Or WinRM Provider Host
status: experimental
logsource: {product: windows, category: process_creation}
detection:
  parent:
    ParentImage|endswith: ['\WmiPrvSE.exe', '\wsmprovhost.exe', '\winrshost.exe']
  child:
    Image|endswith: ['\cmd.exe', '\powershell.exe', '\pwsh.exe', '\rundll32.exe', '\mshta.exe', '\regsvr32.exe']
  condition: parent and child
falsepositives: [SCCM/monitoring agents executing via WMI, admins using Invoke-Command - allowlist by account and source]
level: medium
tags: [attack.lateral_movement, attack.execution, attack.t1047, attack.t1021.006, attack.t1021.003]
```

Corroborate on the destination: WinRM/Operational 91 (shell created) and
PowerShell 4104 script blocks under `wsmprovhost.exe`; a 4624 type 3 for the
same account seconds earlier; inbound 5985/5986 (WinRM) or 135 + dynamic RPC
(WMI/DCOM) from the source.

### 3. Remote scheduled tasks (schtasks /s, atexec)

```kql
// Sentinel SecurityEvent: task created and deleted within 5 minutes on the same host (create-run-delete).
SecurityEvent
| where TimeGenerated > ago(30d) and EventID in (4698, 4699)
| extend TaskName = extract(@"<Data Name=""TaskName"">([^<]+)<", 1, EventData)
| summarize Created = minif(TimeGenerated, EventID == 4698), Deleted = maxif(TimeGenerated, EventID == 4699),
    Content = take_anyif(EventData, EventID == 4698), Account = any(SubjectUserName) by Computer, TaskName
| where isnotempty(Created) and isnotempty(Deleted) and Deleted between (Created .. Created + 5m)
```

SPL - same create/delete pairing; tune `maxspan`:

```spl
index=wineventlog source="XmlWinEventLog:Security" EventCode IN (4698,4699)
| transaction host TaskName startswith=(EventCode=4698) endswith=(EventCode=4699) maxspan=5m
| table _time host TaskName SubjectUserName TaskContent duration
```

```yaml
title: Scheduled Task Action Redirects Output To Windows Temp (atexec pattern)
status: experimental
logsource: {product: windows, service: security}
detection:
  selection:
    EventID: 4698
    TaskContent|contains|all: ['cmd.exe', '/C', '\Temp\', '.tmp']
  condition: selection
falsepositives: [Admin scripts that log to Windows\Temp]
level: high
tags: [attack.lateral_movement, attack.execution, attack.t1053.005]
```

The `TaskContent` XML is entity-encoded in the event (the `> file 2>&1`
redirection appears as `&gt;` / `&amp;`); check how your pipeline renders it
before adding the redirection to the match.

### 4. Admin shares and tool transfer (5140/5145)

```kql
// Sentinel: executable/script writes to admin shares, stacked by source IP. Requires Audit Detailed File Share.
SecurityEvent
| where TimeGenerated > ago(30d) and EventID == 5145
| extend ShareName = extract(@"<Data Name=""ShareName"">([^<]+)<", 1, EventData),
         RelativeTargetName = extract(@"<Data Name=""RelativeTargetName"">([^<]+)<", 1, EventData)
| where ShareName has_any (@"\ADMIN$", @"\C$") and EventData has_any ("WriteData", "%%4417")
| where RelativeTargetName matches regex @"(?i)\.(exe|dll|ps1|bat|vbs|sys)$"
| summarize Files = make_set(RelativeTargetName, 20), Targets = dcount(Computer) by IpAddress, SubjectUserName
| order by Targets desc
```

```spl
index=wineventlog source="XmlWinEventLog:Security" EventCode=5145 ShareName IN ("\\\\*\\ADMIN$","\\\\*\\C$")
  RelativeTargetName IN ("*.exe","*.dll","*.ps1","*.bat","*.sys") AccessList="*%%4417*"
| stats dc(host) as targets values(RelativeTargetName) as files by IpAddress SubjectUserName
| sort - targets
```

```yaml
title: Executable Written To Admin Share
status: experimental
logsource: {product: windows, service: security}
detection:
  selection:
    EventID: 5145
    ShareName|endswith: ['\ADMIN$', '\C$']
    RelativeTargetName|endswith: ['.exe', '.dll', '.ps1', '.bat', '.sys']
    AccessList|contains: '%%4417'
  condition: selection
falsepositives: [Software deployment (SCCM client push), backup agents - allowlist by source host]
level: medium
tags: [attack.lateral_movement, attack.t1021.002, attack.t1570]
```

`%%4417` is the WriteData access string; whether it renders as the code or as
"WriteData (or AddFile)" depends on the collector - verify locally.

### 5. RDP

```kql
// MDE: RemoteInteractive logons; flag workstation-to-workstation, non-IT accounts, off-hours. Tune IT jump host list.
let JumpHosts = dynamic(["10.0.10.5", "10.0.10.6"]);   // replace with your PAW/jump host IPs
DeviceLogonEvents
| where Timestamp > ago(30d) and ActionType == "LogonSuccess" and LogonType == "RemoteInteractive"
| where RemoteIP !in (JumpHosts) and RemoteIPType != "Loopback"
| summarize Sessions = count(), Destinations = make_set(DeviceName, 20), First = min(Timestamp) by AccountName, RemoteIP
| order by array_length(Destinations) desc
```

```spl
index=wineventlog source="XmlWinEventLog:Security" EventCode=4624 LogonType=10
| stats count dc(host) as dests values(host) as hosts min(_time) as first by TargetUserName IpAddress
| sort - dests
```

```yaml
title: RDP Session Hijack Via Tscon As SYSTEM
status: experimental
logsource: {product: windows, category: process_creation}
detection:
  selection:
    Image|endswith: '\tscon.exe'
    User|contains: ['SYSTEM', 'AUTHORI', 'AUTORI']
  condition: selection
falsepositives: [Rare; some session-management tooling]
level: high
tags: [attack.lateral_movement, attack.t1563.002]
```

Read RDP events together: RemoteConnectionManager 1149 records that
authentication succeeded at the network level (it is not proof of a full
session); LSM 21 (session logon), 22 (shell start), 24/25 (disconnect/
reconnect) and Security 4624 type 10 (or type 7 on reconnect/unlock),
4778/4779 complete the story. RDP with Restricted Admin mode shows in the
4624 `RestrictedAdminMode` field and is itself pass-the-hash capable.

### 6. Pass-the-hash / pass-the-ticket logon patterns

```kql
// MDE/Sentinel: NTLM network logons by local accounts or between workstations; PtH from the source side (type 9 seclogo).
DeviceLogonEvents
| where Timestamp > ago(30d) and ActionType == "LogonSuccess"
| extend HostShort = tostring(split(DeviceName, ".")[0])   // DeviceName is often an FQDN; local accounts carry the NetBIOS host name
| where (LogonType == "Network" and Protocol == "NTLM" and (AccountDomain =~ HostShort or IsLocalAdmin == true))
     or LogonType == "NewCredentials"
| summarize Count = count(), Targets = dcount(DeviceName), Sample = any(DeviceName) by AccountName, AccountDomain, LogonType, Protocol, RemoteIP
| order by Targets desc
```

```spl
index=wineventlog source="XmlWinEventLog:Security" EventCode=4624
  ((LogonType=3 AuthenticationPackageName=NTLM NOT TargetUserName="ANONYMOUS LOGON" NOT TargetUserName="*$")
   OR (LogonType=9 LogonProcessName="seclogo*"))
| stats count dc(host) as targets values(host) as hosts by TargetUserName TargetDomainName LogonType IpAddress WorkstationName
| sort - targets
```

```yaml
title: Logon With NewCredentials Via Seclogo (PtH Source Side Or runas /netonly)
status: experimental
logsource: {product: windows, service: security}
detection:
  selection:
    EventID: 4624
    LogonType: 9
    LogonProcessName: 'seclogo'
    AuthenticationPackageName: 'Negotiate'
  condition: selection
falsepositives: [Admins using runas /netonly - same signature; confirm with user and process tree]
level: medium
tags: [attack.lateral_movement, attack.defense_evasion, attack.t1550.002]
```

Pass-the-ticket / overpass-the-hash signals: a 4768 using RC4 (`0x17`) for a
user whose tickets are normally AES; Kerberos service logons on a host for an
account that never authenticates from that source; 4769 from an IP that never
obtained a 4768 for that account (needs all DC logs). Pair with LSASS access
on the source (`hunt-credential-access`) and ticket forgery checks
(`hunt-ad-identity-attacks`).

### 7. Graph: first-seen source -> destination pairs

```kql
// MDE: admin-capable network/RDP logons whose (src, dst, account) triple is new vs. a 30-day baseline.
let Baseline = DeviceLogonEvents
| where Timestamp between (ago(31d) .. ago(1d)) and ActionType == "LogonSuccess" and LogonType in ("Network", "RemoteInteractive")
| distinct RemoteIP, DeviceName, AccountName;
DeviceLogonEvents
| where Timestamp > ago(1d) and ActionType == "LogonSuccess" and LogonType in ("Network", "RemoteInteractive") and isnotempty(RemoteIP)
| join kind=leftanti Baseline on RemoteIP, DeviceName, AccountName
| summarize NewDests = dcount(DeviceName), Dests = make_set(DeviceName, 25), Accounts = make_set(AccountName, 10) by RemoteIP
| where NewDests >= 3     // fan-out threshold; tune per environment
| order by NewDests desc
```

```spl
index=wineventlog source="XmlWinEventLog:Security" EventCode=4624 LogonType IN (3,10) earliest=-31d
  NOT TargetUserName="*$" NOT IpAddress IN ("-","::1","127.0.0.1")
| stats min(_time) as first_seen by IpAddress host TargetUserName
| where first_seen > relative_time(now(), "-1d")
| stats dc(host) as new_dests values(host) as dests values(TargetUserName) as accounts by IpAddress
| where new_dests >= 3
```

Graph views: (a) fan-out - one source reaching many new destinations fast;
(b) chains - A->B then B->C within minutes; (c) tier violations - a tier-0
account authenticating on a lower-tier host. Exclude scanners and backup
servers only after listing them. This stateful logic fits a scheduled SIEM
analytic (via `detection-engineering`), not a Sigma rule.

### 8. OpenSSH on Windows

Windows 10 1809+/Server 2019+ ship `ssh.exe` and an optional `sshd`. Hunt
"Accepted password/publickey for <user> from <ip>" in `OpenSSH/Operational`,
sshd-spawned shells, and `ssh.exe -L/-R/-D` tunnels (T1572). The 4624 logon
type for sshd logons varies by auth method and build - verify before using it.

```kql
// MDE: ssh.exe tunnels and sshd-spawned shells on Windows.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName =~ "ssh.exe" and ProcessCommandLine matches regex @"\s-(R|L|D)\s")
     or (InitiatingProcessFileName in~ ("sshd.exe", "sshd-session.exe") and FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe"))
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

## Baselining and stacking

- Stack destination execution by (parent, child, account) and by normalised
  command line; WMI/WinRM children on servers should come from a short list
  of monitoring/admin accounts.
- Stack logons by (account, source, logon type, auth package) per destination
  tier. Least-frequent pairs and accounts with sudden fan-out are leads.
- Baseline admin paths: list legitimate jump hosts/PAWs and service accounts;
  anything else using RDP/WinRM/PsExec to servers is a lead.
- For 5145, stack written file names across shares; a binary written to 30
  hosts' `ADMIN$` within an hour by one non-deployment account is a lead.

## False positives & benign look-alikes

| Look-alike | Resembles | How to tell |
|---|---|---|
| SCCM client push, software deployment | Admin share writes, service install | Source = site server, service names `ccmsetup`, change window |
| Monitoring (SCOM, Zabbix agents, vuln scanners) | WMI/WinRM, NTLM network logons | Fixed service accounts and source IPs, periodic timing |
| Helpdesk RDP / remote assistance | RDP to workstations | Helpdesk accounts from helpdesk subnet, ticket reference |
| `runas /netonly` by admins | 4624 type 9 seclogo | User confirms, interactive admin workstation |
| Backup servers | Admin share access everywhere | Backup service account, nightly schedule |
| Ansible/DSC over WinRM | wsmprovhost children | Automation account, change record, consistent command shape |

## Pitfalls

- Hunting only destination logs: workstation logs are often not collected; DC
  authentication logs (4768/4769/4776) and MDI are the estate-wide fallback.
- Mistaking 1149 for a successful session; it fires before session creation.
- Ignoring IPv6 and NAT: `RemoteIP`/`IpAddress` may be `::1`, a proxy, a VPN
  concentrator or `-`; use `WorkstationName` and DNS/DHCP history to resolve.
- Assuming NTLM = PtH. NTLM is still common (IP-based access, legacy apps); the
  signal is local accounts, workstation-to-workstation, and new fan-out.
- Filtering out machine accounts too early: `computer$` logons can be relayed
  or abused (RBCD, see `hunt-ad-identity-attacks`).

## Escalation criteria

- Remote execution (service, WMI, WinRM, DCOM, task) on any host from a source
  that is not a sanctioned admin host, with no change record.
- Local administrator (RID 500 or LAPS-managed) NTLM logons from one source to
  multiple hosts, or any tier-0 account logon on a lower-tier host.
- New fan-out >= the tuned threshold from a user workstation, or a chain
  A->B->C within an hour.
- tscon as SYSTEM, wmiexec/atexec/smbexec output patterns.

| Verdict | Evidence that moves it |
|---|---|
| True Positive | Unsanctioned source + remote execution + credential-theft or C2 evidence on source |
| Benign True Positive | Admin activity confirmed by owner, ticket, jump host, expected account |
| False Positive | Field misparse (IP `-`, NAT), wrong logon type mapping |
| Needs more data | Source host logs missing; pull EDR/live response from source |

## Output

```markdown
## Hunt report - lateral movement - <HUNT-ID>
- Hypothesis / status: <supported | refuted | inconclusive>
- Scope & window: <tiers/subnets>, <UTC range>; destination log coverage <n>%, source coverage <n>%
- Primitives covered: <RDP, SMB, WMI, WinRM, DCOM, services, tasks, PtH/PtT, SSH> (ATT&CK IDs)
- Graph summary: <n> new src->dst pairs, <n> fan-out sources, <n> tier violations
- Findings: | Time (UTC) | Source | Destination | Account | Primitive | Evidence (2+) | Verdict |
- Sanctioned admin paths documented: <jump hosts, service accounts>
- Detections proposed: <titles -> detection-engineering>; gaps: <missing 5145, no workstation logs, ...>
```

Hand-offs: confirmed movement to `incident-response` (scope map), credential
source to `hunt-credential-access`, AD-level abuse to `hunt-ad-identity-attacks`,
host artefacts to `windows-forensics`, timeline to `timeline-analysis`,
detections to `detection-engineering`, tiering gaps to `hardening-windows-ad`.

## References

- MITRE ATT&CK TA0008 Lateral Movement; T1021.001-.006, T1047, T1550.002,
  T1550.003, T1563.002, T1569.002, T1570: https://attack.mitre.org/tactics/TA0008/
- JPCERT/CC, "Detecting Lateral Movement through Tracking Event Logs".
- Microsoft Learn: 4624(S) An account was successfully logged on (logon types, fields).
- Microsoft Learn: 5145(S, F) A network share object was checked to see whether client can be granted desired access.
- Microsoft Learn: Advanced hunting schema - DeviceLogonEvents, DeviceProcessEvents.
- SANS DFIR "Hunt Evil" poster (lateral movement artefacts).
