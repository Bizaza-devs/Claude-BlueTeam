---
name: hunt-windows-persistence
description: Threat hunt for Windows persistence (TA0003): Run/RunOnce keys, services (7045, 4697), scheduled tasks (4698/4702, TaskScheduler 106/140/141, TaskCache and hidden tasks), WMI event subscriptions (Sysmon 19/20/21, WMI-Activity 5861), startup folders, Winlogon Userinit/Shell, IFEO Debugger and SilentProcessExit, AppInit/AppCert DLLs, COM hijacking (HKCU CLSID InprocServer32), BITS jobs, accessibility backdoors (sethc, utilman), Office add-ins, Active Setup, and Autoruns (autorunsc) baseline diffing. KQL, SPL and Sigma per behaviour, stacking and escalation criteria. Use when asked to "hunt for persistence", "check autoruns", "new services or scheduled tasks", "WMI persistence", "T1547.001", "T1053.005", "T1546.003" or "how is it surviving reboot".
---

# Hunt: Windows persistence

Persistence is the most forgiving thing to hunt: it must be written somewhere
durable and it must be executed again later. Hunt both the write (registry,
file, task, service, WMI) and the later execution (process launched by
services.exe, svchost Schedule, WmiPrvSE, winlogon, explorer at logon).

## When to use

- A hypothesis or intel report says an actor persists via Run keys, tasks,
  services, WMI, COM hijack, IFEO, BITS or Office add-ins.
- After any confirmed intrusion: "what will bring them back after we clean up?"
  (sweep before eradication so nothing is missed).
- Periodic estate hygiene: Autoruns baseline vs. today's diff on servers and
  tier-0 assets.
- An anomaly: a process starting at every boot or logon that nobody owns.

## Ground rules

1. **An autostart entry is not a verdict.** A rare entry needs the binary it
   points to (hash, signer, path, first-seen) and its creator (process, user,
   time) before it is called malicious. Two sources: the write event plus the
   on-disk/registry artefact or an execution event.
2. **Collect before you clean.** Never delete a task, service or key from a
   hunt. Export the artefact (task XML, reg export, WMI MOF / `Get-CimInstance`
   output, binary + hash) through `evidence-handling`; removal is an
   eradication step under `incident-response` with change approval.
3. **Diff against a baseline, not against memory.** "Looks normal" is not
   evidence; a golden-image or 30-day Autoruns/telemetry baseline is.
4. **No "clean" without coverage.** Registry auditing (Sysmon 12/13/14 or MDE),
   4698 and 7045 must be shown present for the scope before a null result.

## Workflow

1. Hypothesis and scope via `hunt-dispatch`; pick mechanisms from the ATT&CK map.
2. Data check (table below). Note which hosts lack Sysmon/MDE.
3. Run the narrow known-bad queries per mechanism (user-writable paths,
   script hosts, encoded commands, LOLBins as payloads).
4. Run the broad queries and stack by normalised payload path and signer.
5. For each rare entry: resolve the payload, hash, signature, creator process
   tree and first-seen across the estate; check it executes (child processes).
6. Where telemetry is thin, collect Autoruns from scoped hosts and diff.
7. Conclude, write the hunt report, convert stable patterns to detections via
   `detection-engineering`.

## ATT&CK sub-technique map

| Mechanism | ATT&CK | Primary evidence |
|---|---|---|
| Run/RunOnce/RunOnceEx, Policies\Explorer\Run, startup folder | T1547.001 | Sysmon 13 / DeviceRegistryEvents; Sysmon 11 / DeviceFileEvents |
| Winlogon Userinit / Shell / Notify | T1547.004 | Registry value set under `...\Winlogon` |
| Active Setup StubPath | T1547.014 | `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\<GUID>\StubPath` |
| LSA auth packages / SSP | T1547.002 / T1547.005 | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` values |
| Windows service | T1543.003 | 7045, 4697, `HKLM\SYSTEM\CurrentControlSet\Services\<name>` |
| Scheduled task | T1053.005 | 4698/4702, TaskScheduler 106/140, TaskCache, `C:\Windows\System32\Tasks` |
| WMI event subscription | T1546.003 | Sysmon 19/20/21, WMI-Activity/Operational 5861 |
| IFEO Debugger / SilentProcessExit | T1546.012 | IFEO `Debugger`, `GlobalFlag` 0x200, `SilentProcessExit\<exe>\MonitorProcess` |
| AppInit DLLs / AppCert DLLs | T1546.010 / T1546.009 | `...\Windows NT\CurrentVersion\Windows\AppInit_DLLs`; `...\Session Manager\AppCertDlls` |
| COM hijacking | T1546.015 | HKCU `Software\Classes\CLSID\{...}\InprocServer32` / `LocalServer32` |
| Accessibility features | T1546.008 | IFEO on sethc/utilman/osk/magnify/narrator/displayswitch/atbroker, or replaced binary |
| BITS jobs | T1197 | Bits-Client/Operational 3/59/60, bitsadmin `/SetNotifyCmdLine` |
| Office add-ins / templates / Office Test key | T1137.006 / T1137.001 / T1137.002 | Word/Excel startup dirs, Normal.dotm, `HKCU\Software\Microsoft\Office test\Special\Perf` |

## Data sources required

| Source | Needed for | Enable / check |
|---|---|---|
| Sysmon 1, 11, 12/13/14, 19/20/21 or MDE (DeviceProcessEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceEvents) | Registry, file, WMI, execution | Sysmon config must include autorun keys and WMI events |
| Security 4697, 4698, 4699, 4702 | Services, tasks | "Audit Security System Extension", "Audit Other Object Access Events" |
| System 7045 (Service Control Manager) | Services | On by default |
| Microsoft-Windows-TaskScheduler/Operational 106/140/141/200/201 | Tasks | Disabled by default on some builds; enable |
| Microsoft-Windows-WMI-Activity/Operational 5861 | WMI permanent consumers | On by default (Win10+/2016+) |
| Microsoft-Windows-Bits-Client/Operational 3/59/60 | BITS | On by default |
| Autoruns (autorunsc) / Velociraptor `Windows.Sysinternals.Autoruns` | Gap-filling, baselines | Live collection, read-only |

Sentinel note: Sysmon usually lands in `Event` (parse with your Sysmon
function/ASIM parser); Security events in `SecurityEvent`. Queries below that
use `EventData has` are written to survive parser differences.

## Behaviours and queries

### 1. Registry autostart writes (Run, Winlogon, IFEO, AppInit/AppCert, Active Setup, LSA, Office Test, COM)

```kql
// MDE: autostart registry writes; tune the allowlist of initiating processes (installers, GPO, SCCM).
let AutostartKeys = dynamic([@"\CurrentVersion\Run", @"\CurrentVersion\Policies\Explorer\Run",
  @"\Windows NT\CurrentVersion\Winlogon", @"\Image File Execution Options\", @"\SilentProcessExit\",
  @"\Windows NT\CurrentVersion\Windows", @"\Session Manager\AppCertDlls", @"\Active Setup\Installed Components",
  @"\Control\Lsa", @"\Office test\Special\Perf", @"\Classes\CLSID\"]);
DeviceRegistryEvents
| where Timestamp > ago(30d) and ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| where RegistryKey has_any (AutostartKeys)
| where not(RegistryKey has @"\Classes\CLSID\")
    or (RegistryKey startswith "HKEY_CURRENT_USER" and RegistryKey has_any ("InprocServer32", "LocalServer32", "TreatAs"))
| where RegistryValueName in~ ("", "Userinit", "Shell", "Debugger", "MonitorProcess", "GlobalFlag", "AppInit_DLLs",
    "LoadAppInit_DLLs", "StubPath", "Authentication Packages", "Security Packages") or RegistryKey has @"\Run"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, PreviousRegistryValueData,
    InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
```

SPL - same keys from Sysmon 13; tune `index` and the process allowlist:

```spl
index=sysmon source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode IN (12,13)
  (TargetObject="*\\CurrentVersion\\Run*" OR TargetObject="*\\Winlogon\\Userinit" OR TargetObject="*\\Winlogon\\Shell"
   OR TargetObject="*\\Image File Execution Options\\*\\Debugger" OR TargetObject="*\\SilentProcessExit\\*"
   OR TargetObject="*\\AppInit_DLLs" OR TargetObject="*\\AppCertDlls\\*" OR TargetObject="*\\Active Setup\\Installed Components\\*\\StubPath"
   OR TargetObject="*\\Office test\\Special\\Perf*" OR (TargetObject="HKU\\*\\Classes\\CLSID\\*" TargetObject="*Server32*"))
| stats count min(_time) as first max(_time) as last values(Image) as writer by host TargetObject Details
| sort count
```

```yaml
title: Autostart Registry Value Pointing To User-Writable Path Or Script Host
status: experimental
logsource: {product: windows, category: registry_set}
detection:
  keys:
    TargetObject|contains: ['\CurrentVersion\Run', '\Winlogon\Userinit', '\Winlogon\Shell', '\Image File Execution Options\',
                            '\SilentProcessExit\', '\AppInit_DLLs', '\Active Setup\Installed Components\', '\Office test\Special\Perf']
  payload:
    Details|contains: ['\AppData\', '\Temp\', '\Users\Public\', '\ProgramData\', 'powershell', 'mshta', 'wscript', 'cscript', 'rundll32', 'regsvr32', 'http']
  condition: keys and payload
falsepositives: [Per-user installers (Teams, Zoom, OneDrive) writing Run keys under AppData - allowlist by signer]
level: medium
tags: [attack.persistence, attack.t1547.001, attack.t1547.004, attack.t1546.012]
```

Expected-value checks: `Userinit` should be `C:\Windows\system32\userinit.exe,`
and `Shell` `explorer.exe`; any appended entry is high-signal. `LoadAppInit_DLLs`
= 1 with a non-empty `AppInit_DLLs` is rare on modern estates. `GlobalFlag`
0x200 under IFEO plus `SilentProcessExit\<exe>\MonitorProcess` runs a program
whenever `<exe>` exits.

### 2. New services (7045 / 4697)

```kql
// MDE: new services; stack on normalised binary path. Verify AdditionalFields keys on your tenant.
DeviceEvents
| where Timestamp > ago(30d) and ActionType == "ServiceInstalled"
| extend AF = parse_json(AdditionalFields)
| extend ServiceName = tostring(AF.ServiceName), StartType = tostring(AF.ServiceStartType), Account = tostring(AF.ServiceAccount)
| extend PathNorm = tolower(replace_regex(FolderPath, @"\\users\\[^\\]+", @"\users\<user>"))
| summarize Hosts = dcount(DeviceId), FirstSeen = min(Timestamp), Names = make_set(ServiceName, 10) by PathNorm, FileName
| where Hosts <= 3
// Sentinel: Event | where Source == "Service Control Manager" and EventID == 7045 | where EventData has_any ("\\AppData\\","%COMSPEC%","powershell","\\\\127.0.0.1\\ADMIN$")
```

```spl
index=wineventlog source="XmlWinEventLog:System" EventCode=7045
| eval suspicious=if(match(lower(ImagePath),"appdata|\\btemp\\b|users.public|%comspec%|cmd\.exe /c|powershell|-enc|127\.0\.0\.1|admin\$"),1,0)
| stats count dc(host) as hosts values(host) as host_list min(_time) as first by ServiceName ImagePath AccountName suspicious
| where hosts<=3 OR suspicious=1
```

```yaml
title: Service Installed With Suspicious Image Path
status: experimental
logsource: {product: windows, service: system}
detection:
  selection:
    Provider_Name: 'Service Control Manager'
    EventID: 7045
  suspicious:
    ImagePath|contains: ['\AppData\', '\Temp\', '\Users\Public\', '%COMSPEC%', 'cmd.exe /c', 'powershell', ' -enc', '\\127.0.0.1\', 'mshta', 'rundll32']
  condition: selection and suspicious
falsepositives: [Software installers using Temp during setup, RMM agents]
level: high
tags: [attack.persistence, attack.t1543.003, attack.execution, attack.t1569.002]
```

Also review `svchost` services added via a `ServiceDll` value under
`Services\<name>\Parameters` (registry query, not 7045) and services whose
binary is unsigned or newly written.

### 3. Scheduled tasks (4698/4702, TaskCache, hidden tasks)

```kql
// MDE: created/updated tasks whose action runs from user-writable paths or script hosts.
DeviceEvents
| where Timestamp > ago(30d) and ActionType in ("ScheduledTaskCreated", "ScheduledTaskUpdated")
| extend AF = parse_json(AdditionalFields)
| extend TaskName = tostring(AF.TaskName), TaskContent = tostring(AF.TaskContent)
| where TaskContent has_any (@"\AppData\", @"\Temp\", @"\Users\Public\", "powershell", "mshta", "wscript", "cscript",
    "rundll32", "regsvr32", "cmd.exe /c", "-enc", "http")
| project Timestamp, DeviceName, ActionType, TaskName, TaskContent, InitiatingProcessFileName, InitiatingProcessAccountName
```

```kql
// MDE: hidden tasks - SD value deleted under TaskCache\Tree (Tarrask-style). Requires SYSTEM-level writer.
DeviceRegistryEvents
| where ActionType == "RegistryValueDeleted" and RegistryKey has @"\Schedule\TaskCache\Tree\" and RegistryValueName == "SD"
| project Timestamp, DeviceName, RegistryKey, InitiatingProcessFileName, InitiatingProcessCommandLine
```

```spl
index=wineventlog source="XmlWinEventLog:Security" EventCode IN (4698,4702)
| rex field=TaskContent "(?s)<Command>(?<cmd>[^<]+)</Command>(\s*<Arguments>(?<args>[^<]*)</Arguments>)?"
| eval cmdnorm=replace(lower(cmd),"users.[^\\\\]+","users/<user>")
| stats count dc(host) as hosts values(TaskName) as tasks values(args) as args values(SubjectUserName) as by_user by cmdnorm
| where hosts<=3
```

```yaml
title: Scheduled Task Created With Suspicious Action
status: experimental
logsource: {product: windows, service: security}
detection:
  selection:
    EventID: [4698, 4702]
    TaskContent|contains: ['\AppData\', '\Temp\', '\Users\Public\', 'powershell', 'mshta', 'wscript', 'cscript', 'regsvr32', 'rundll32', '-enc', 'http://', 'https://']
  condition: selection
falsepositives: [Software updaters (browsers, Teams) registering per-user tasks from AppData]
level: medium
tags: [attack.persistence, attack.execution, attack.t1053.005]
```

Cross-checks: a task in `TaskCache\Tree` with no XML file in
`C:\Windows\System32\Tasks` (or vice versa), tasks missing from `schtasks /query`
but present in the registry, and TaskScheduler 106 (registered) / 141 (deleted)
in a short window (create-run-delete pattern used for remote execution, see
`hunt-lateral-movement`).

### 4. WMI event subscriptions

```kql
// MDE: filter-to-consumer bindings. Verify ActionType name on your tenant; Sysmon 19/20/21 equivalent in Sentinel Event table.
DeviceEvents
| where Timestamp > ago(90d) and ActionType == "WmiBindEventFilterToConsumer"
| project Timestamp, DeviceName, AdditionalFields, InitiatingProcessFileName, InitiatingProcessCommandLine
```

```spl
index=sysmon source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode IN (19,20,21)
| eval consumer_payload=coalesce(Destination, Consumer, Query)
| stats values(EventType) as types values(consumer_payload) as payload values(User) as users min(_time) as first by host Name
| search NOT Name IN ("SCM Event Log Consumer","SCM Event Log Filter","BVTFilter","BVTConsumer")
```

```yaml
title: WMI Permanent Event Consumer With Script Or Command Line
status: experimental
logsource: {product: windows, category: wmi_event}
detection:
  selection:
    EventID: 20
    Type: ['Command Line', 'Script']
  condition: selection
falsepositives: [Vendor management agents (OEM hardware tools, some backup/monitoring agents) - verify by consumer name and payload]
level: high
tags: [attack.persistence, attack.privilege_escalation, attack.t1546.003]
```

Live check (read-only): `Get-CimInstance -Namespace root\subscription -ClassName __EventFilter`,
`__EventConsumer` (CommandLineEventConsumer, ActiveScriptEventConsumer) and
`__FilterToConsumerBinding`. WMI-Activity/Operational 5861 records new
permanent consumer registrations even without Sysmon.

### 5. Startup folders and Office add-in locations

```kql
// MDE: files dropped where they auto-execute at logon or Office start. Tune for vendor add-ins.
DeviceFileEvents
| where Timestamp > ago(30d) and ActionType in ("FileCreated", "FileRenamed", "FileModified")
| where FolderPath has_any (@"\Start Menu\Programs\Startup\", @"\Microsoft\Word\STARTUP\", @"\Microsoft\Excel\XLSTART\",
    @"\Microsoft\AddIns\", @"\Microsoft\Templates\Normal.dotm")
| summarize Hosts = dcount(DeviceId), Paths = make_set(FolderPath, 5) by FileName, SHA256, InitiatingProcessFileName
| where Hosts <= 3
```

```spl
index=sysmon source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
  (TargetFilename="*\\Start Menu\\Programs\\Startup\\*" OR TargetFilename="*\\Word\\STARTUP\\*" OR TargetFilename="*\\Excel\\XLSTART\\*" OR TargetFilename="*\\Templates\\Normal.dotm")
| stats count dc(host) as hosts values(Image) as writer by TargetFilename
```

```yaml
title: File Written To Startup Folder By Script Host Or Office
status: experimental
logsource: {product: windows, category: file_event}
detection:
  path:
    TargetFilename|contains: '\Start Menu\Programs\Startup\'
  writer:
    Image|endswith: ['\powershell.exe', '\pwsh.exe', '\wscript.exe', '\cscript.exe', '\mshta.exe', '\cmd.exe', '\winword.exe', '\excel.exe', '\rundll32.exe']
  condition: path and writer
falsepositives: [Login scripts copying shortcuts - allowlist by GPO script path]
level: high
tags: [attack.persistence, attack.t1547.001, attack.t1137.006]
```

Also check `HKCU\Software\Microsoft\Office\<ver>\Excel\Options` values named
`OPEN*` (XLL add-ins) and `...\<App>\Addins\*` with `LoadBehavior` 3.

### 6. BITS jobs and accessibility-feature backdoors

```kql
// MDE: bitsadmin persistence/notify commands; and shells spawned by accessibility binaries or winlogon.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName =~ "bitsadmin.exe" and ProcessCommandLine has_any ("/SetNotifyCmdLine", "/addfile", "/transfer", "/create"))
   or (InitiatingProcessFileName in~ ("sethc.exe","utilman.exe","osk.exe","magnify.exe","narrator.exe","displayswitch.exe","atbroker.exe","winlogon.exe")
       and FileName in~ ("cmd.exe","powershell.exe","pwsh.exe"))
   // replaced binary; confirm OriginalFileName values on a known-good host of the same build
   or (FileName in~ ("sethc.exe","utilman.exe","osk.exe") and ProcessVersionInfoOriginalFileName in~ ("cmd.exe","powershell.exe","explorer.exe"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, ProcessVersionInfoOriginalFileName, InitiatingProcessFileName
```

```spl
index=sysmon source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  ((Image="*\\bitsadmin.exe" CommandLine IN ("*SetNotifyCmdLine*","*/addfile*","*/transfer*"))
   OR (ParentImage IN ("*\\sethc.exe","*\\utilman.exe","*\\osk.exe","*\\Magnify.exe","*\\Narrator.exe","*\\DisplaySwitch.exe","*\\AtBroker.exe") Image IN ("*\\cmd.exe","*\\powershell.exe")))
| table _time host User ParentImage Image CommandLine
```

```yaml
title: Shell Spawned By Accessibility Feature Binary
status: experimental
logsource: {product: windows, category: process_creation}
detection:
  parent:
    ParentImage|endswith: ['\sethc.exe', '\utilman.exe', '\osk.exe', '\Magnify.exe', '\Narrator.exe', '\DisplaySwitch.exe', '\AtBroker.exe']
  child:
    Image|endswith: ['\cmd.exe', '\powershell.exe', '\pwsh.exe']
  condition: parent and child
falsepositives: [Very unlikely; accessibility tools do not launch shells]
level: high
tags: [attack.persistence, attack.privilege_escalation, attack.t1546.008]
```

BITS live check: `bitsadmin /list /allusers /verbose` or `Get-BitsTransfer -AllUsers`
(admin). Jobs survive reboots; a job with a notify command line is persistence.

## Autoruns collection and diffing

```powershell
# Read-only collection: all entry types, CSV, hashes, signature verification, all user profiles. Do not use -vt (uploads to VirusTotal) without approval.
.\autorunsc64.exe -accepteula -nobanner -a * -c -h -s '*' | Out-File -Encoding utf8 "$env:COMPUTERNAME-autoruns.csv"
```

```powershell
# Diff today's collection against a baseline from the same build/role. Key on location + entry + image path + hash.
$base = Import-Csv .\baseline-autoruns.csv; $now = Import-Csv .\HOST-autoruns.csv
$key = { "$($_.'Entry Location')|$($_.Entry)|$($_.'Image Path')|$($_.'SHA-256')" }
Compare-Object ($base | ForEach-Object $key) ($now | ForEach-Object $key) | Where-Object SideIndicator -eq '=>'
```

At scale, use Velociraptor `Windows.Sysinternals.Autoruns` or your EDR's live
response, collect per role (DC, file server, workstation build) and stack
entries across hosts: an entry on 1 of 400 identical workstations is a lead.
Column names vary slightly by Autoruns version; check the header first.

## Baselining and stacking

- **Key:** normalised payload path (user names, GUIDs, version digits
  replaced) + signer + mechanism. Count `dcount(host)` and first-seen.
- **Tail:** entries on <= 3 hosts, first seen in the window, unsigned or signed
  by an unexpected publisher, payload in a user-writable path, payload is a
  LOLBin with arguments (`rundll32`, `mshta`, `regsvr32`, `powershell -enc`).
- **Creator stacking:** for services/tasks, stack by creating process and
  account; tasks created by `cmd.exe`/`powershell.exe` under a user account on
  servers stand out against SCCM/GPO-created ones.
- **Execution confirm:** join the payload to process starts under
  `services.exe`, `svchost.exe -k netsvcs -p -s Schedule`, `WmiPrvSE.exe`,
  `winlogon.exe`/`userinit.exe` and `explorer.exe` at logon.

## False positives & benign look-alikes

| Look-alike | Mechanism | How to tell |
|---|---|---|
| Per-user apps (Teams, OneDrive, Zoom, Slack, Spotify) | HKCU Run, tasks from `%LOCALAPPDATA%` | Signed by vendor, consistent path across many users |
| Browser/updater tasks (Google, Edge, Adobe) | Scheduled tasks | Vendor signer, task name pattern, present on most hosts |
| SCCM/Intune/GPO | Services, tasks, Run keys at scale | Creator is `CcmExec`, IME, `gpsvc`; burst across fleet in change window |
| Default WMI consumer "SCM Event Log Consumer" / BVT | WMI | Built-in NTEventLogEventConsumer names, no command line |
| OEM tools (Dell, HP, Lenovo) | WMI, services, tasks | Vendor signer, image path under Program Files |
| Security/EDR/backup agents | Services, IFEO, AppInit-like hooks | Owned by security team; verify signer and install record |
| Application compatibility / debugging | IFEO `Debugger` (e.g. vsjitdebugger), `GlobalFlag` | Developer workstations, known debugger paths |
| Shell extensions and Office COM add-ins | HKLM CLSID registrations | HKLM writes by installers are normal; HKCU overrides of existing CLSIDs are not |

## Pitfalls

- Hunting only `HKLM\...\Run`: miss `HKCU`, `RunOnceEx`, `Wow6432Node`,
  `Policies\Explorer\Run` and user hives of users not logged on (Autoruns
  `'*'` loads all profiles; telemetry does not see offline hives).
- Trusting `schtasks /query` - hidden tasks (SD removed) do not appear; read
  the TaskCache registry and the Tasks folder.
- 7045 alone: services can be created by direct registry writes (`Services\<name>`)
  and appear only after reboot; hunt the registry too.
- Treating a signed payload as benign: signed LOLBins (`rundll32`, `msiexec`,
  `regsvr32`) are payloads of choice; inspect the arguments.
- Removing persistence before scoping it: the actor often has more than one
  mechanism; sweep the whole map first.

## Escalation criteria

Escalate to `alert-triage` / `incident-response` when any of:
- Autostart payload in a user-writable path that is unsigned and seen on <= 3 hosts,
  with no owner after one business-day enquiry.
- WMI CommandLine/ActiveScript consumer, IFEO `Debugger` on an accessibility
  binary, appended `Userinit`, `Office test\Special\Perf` value, or a hidden task.
- Persistence on a DC, ADCS, Entra Connect server or other tier-0 asset that is
  not in the change record.
- Payload executes and makes outbound connections (`hunt-c2-beaconing`).

| Verdict | Evidence that moves it |
|---|---|
| True Positive | Unowned entry + malicious/unknown payload + execution or C2 evidence |
| Benign True Positive | Owner confirms (ticket, admin), payload signed by expected vendor |
| False Positive | Query logic matched a benign pattern; fix and add allowlist |
| Needs more data | Payload missing on disk, telemetry gap; collect via live response |

## Output

Hunt report stub (attach to the `hunt-dispatch` hunt log):

```markdown
## Hunt report - Windows persistence - <HUNT-ID>
- Hypothesis / status: <supported | refuted | inconclusive>
- Scope & window: <hosts/roles>, <UTC range>; coverage: Sysmon/MDE on <n>% of scope
- Mechanisms covered: <Run keys, services, tasks, WMI, ...> (ATT&CK IDs)
- Results: <n> entries reviewed, <n> rare, <n> explained, <n> escalated
- Findings: | Host | Mechanism | Key/Task/Service | Payload + SHA256 | Creator | First seen | Verdict |
- Exclusions added: <list with owner>
- Detections proposed: <Sigma titles -> detection-engineering>
- Gaps: <hosts without registry telemetry, TaskScheduler log disabled, ...>
```

Hand-offs: confirmed persistence to `incident-response` (eradication list),
binaries to `malware-triage`, artefact timeline to `windows-forensics` /
`timeline-analysis`, detections to `detection-engineering` / `sigma-rules`,
recurring gaps to `logging-coverage`, related payloads to `hunt-lolbins`.

## References

- MITRE ATT&CK TA0003 Persistence; T1547.001, T1543.003, T1053.005, T1546.003,
  T1546.012, T1546.015, T1197, T1137: https://attack.mitre.org/tactics/TA0003/
- Microsoft Sysinternals: Autoruns for Windows (autorunsc usage).
- Microsoft Learn: Advanced hunting schema - DeviceRegistryEvents, DeviceEvents, DeviceFileEvents.
- Microsoft Threat Intelligence blog: Tarrask malware and hidden scheduled tasks (2022).
- SigmaHQ rule repository (registry_set, process_creation, wmi_event categories).
- Microsoft Learn: Audit Other Object Access Events; Audit Security System Extension.
