---
name: windows-forensics
description: Artifact-driven Windows host forensics and triage. Covers order of volatility, KAPE and Velociraptor collection targets, evidence of execution (Prefetch, Amcache.hve, ShimCache/AppCompatCache, BAM/DAM, UserAssist, SRUM, Windows 11 PCA), file and folder access (LNK, Jump Lists, ShellBags, RecentDocs), NTFS ($MFT, $UsnJrnl:$J, $LogFile, $I30), key EVTX logs and event IDs (4624, 4688, 7045, 4104, 1149), registry hives and key paths, browser history, Eric Zimmerman tools (PECmd, AmcacheParser, AppCompatCacheParser, MFTECmd, EvtxECmd, RECmd, Timeline Explorer) and Chainsaw/Hayabusa EVTX hunting. Use when asked "did this binary run", "what did the attacker touch", "triage this host/image", "parse prefetch/amcache/shimcache", "check for timestomping", or when running /forensics on a Windows system.
---

# Windows forensics

## When to use

- A Windows endpoint or server is suspected compromised and you need to prove
  what executed, when, by whom, and what was accessed or staged.
- You received a KAPE/Velociraptor triage package, a disk image (E01/raw/VHDX)
  or a live host and must answer specific investigative questions.
- You need to corroborate an EDR/SIEM alert with on-disk artifacts, or the EDR
  telemetry is missing for the time window.
- Before writing the technical section of a report (`ir-report-writing`).

Memory belongs to `memory-forensics`; super-timelines to `timeline-analysis`;
suspicious files found here go to `malware-triage`; acquisition and custody to
`evidence-handling`.

## Ground rules

1. **Hash + acquisition time + who before any analysis.** Every image, triage
   zip or exported hive gets a SHA-256 and an evidence-log row
   (`evidence-handling`) before you open it. Work on copies, never the original.
2. **One artifact is an indicator, two independent artifacts are a finding.**
   "Executed" needs at least two of: Prefetch, Amcache, BAM, UserAssist, SRUM,
   PCA, 4688/Sysmon 1, EDR telemetry. ShimCache or Amcache alone is *presence*,
   not execution.
3. **All times in UTC** in notes and timelines. Record the host's configured
   time zone (registry `TimeZoneInformation`) and any observed clock skew.
4. **State the artifact's semantics next to its timestamp** ("Prefetch last run",
   "$SI modified", "ShimCache file last-modified") - a timestamp without its
   meaning is not evidence.
5. **No live-host analysis that destroys volatile data.** Memory first, then
   triage collection, then deeper work. Running tools on a live box changes
   Prefetch, Amcache and $MFT - note every tool you ran and when.
6. **Absence of evidence is not evidence of absence.** Prefetch disabled,
   logs rolled or cleared, ShimCache not yet flushed - check the artifact
   actually exists and covers the window before concluding "did not run".

## Workflow

1. **Scope the questions.** Write down 3-6 concrete questions (initial access
   vector? first execution of X? lateral movement source? data staged?). Every
   artifact you parse should answer one of them.
2. **Preserve in order of volatility** (RFC 3227): memory -> network state /
   running processes (if live) -> triage collection of locked files -> full disk
   image if justified. Isolate the host via EDR network containment rather than
   pulling the cable or powering off (approval per `incident-response`).
3. **Collect** with KAPE or Velociraptor (targets below). Include Volume Shadow
   Copies when time window predates the latest VSS.
4. **Parse** with EZ tools into CSV, one folder per artifact class. Run
   Hayabusa/Chainsaw over EVTX for a fast detection pass.
5. **Anchor.** Find the anchor event (alert time, first malicious logon,
   malicious file creation) and pivot +/- a window across artifacts
   (`timeline-analysis`).
6. **Corroborate** each claim with a second artifact class (ground rule 2).
7. **Record** findings in the incident timeline CSV and evidence log; hand
   suspicious binaries to `malware-triage`, IOCs to `threat-intel-ioc`.

## Collection

### KAPE

```powershell
# Triage collection from live C: into a VHDX, including Volume Shadow Copies
.\kape.exe --tsource C: --tdest E:\case\%m --target KapeTriage --vss --vhdx %m
# Process the collected files with the EZ tools compound module
.\kape.exe --msource E:\case\HOST01\C --mdest E:\case\HOST01\parsed --module !EZParser
```

- `KapeTriage` (compound) covers registry hives + transaction logs, EVTX,
  Prefetch, Amcache, $MFT, $J, $LogFile, LNK/Jump Lists, SRUM, browser
  history, scheduled tasks, WMI repository and more.
- Target/module names and flags change between releases - check
  `kape.exe --help` and the `Targets\` folder of your copy. Keep the
  KAPE console log with the evidence (it records copied files and hashes).

### Velociraptor

- `Windows.KapeFiles.Targets` collects the same KAPE target definitions; in
  newer releases it is superseded by `Windows.Triage.Targets` (version-
  dependent - check the artifact list on your server).
- Offline collector (`velociraptor.exe` with an embedded collection config)
  for hosts without an agent; output is a zip with an upload manifest.
- Useful parsing artifacts on a live fleet: `Windows.Forensics.Prefetch`,
  `Windows.Forensics.SRUM`, `Windows.EventLogs.EvtxHunter`,
  `Windows.Registry.UserAssist` (names may vary by version).

## Evidence of execution

| Artifact | Location | What it proves | Caveats |
|---|---|---|---|
| Prefetch | `C:\Windows\Prefetch\<EXE>-<hash>.pf` | Executed; run count; last run times (up to 8 on Win8+); files/dirs referenced in first ~10 s | Disabled by default on Windows Server; may be disabled by policy; 1024 file cap (Win8+); Win10+ files are MAM-compressed (PECmd handles it) |
| Amcache.hve | `C:\Windows\AppCompat\Programs\Amcache.hve` | Presence of a PE + SHA-1 (`FileId`, computed over only the first 30 MiB / 31,457,280 bytes); install/inventory metadata | Not proof of execution on Win10+; populated by inventory tasks too; key layout changed across builds |
| ShimCache / AppCompatCache | `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\AppCompatCache` | File path existed and was seen by the shim engine; ordered most recent first | Timestamp is the file's **last-modified time**, not execution time; written to the hive only at shutdown/reboot (read from memory for live data); no reliable execution flag on Win10+ |
| BAM / DAM | `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>` (1809+; earlier `bam\UserSettings\<SID>`), `dam\...` | Per-user last execution time of a binary | Win10 1709+ only; entries for older executions are pruned (reported ~7 days); not for every process type |
| UserAssist | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count` | GUI launches by that user (ROT13 names), run count, focus time, last run | GUID `{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}` = executables, `{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}` = shortcuts; only Explorer-launched programs |
| SRUM | `C:\Windows\System32\sru\SRUDB.dat` (ESE) | Per-app, per-user CPU, bytes sent/received per network interface, ~30-60 days | Data flushed roughly hourly, so last hour may be in memory only; needs `SOFTWARE` hive to resolve names |
| PCA (Win11 22H2+) | `C:\Windows\appcompat\pca\PcaAppLaunchDic.txt`, `PcaGeneralDb0.txt`, `PcaGeneralDb1.txt` | Path + last launch time (UTC) of programs launched via Explorer (PcaAppLaunchDic) | Win11 22H2+ only; not populated for every launch method (e.g. command line); plain text - verify format per build |
| Process creation logs | Security 4688, Sysmon 1, EDR | Full command line, parent, user, time | 4688 needs "Audit Process Creation" + "Include command line" GPO |
| Scheduled tasks / services | `C:\Windows\System32\Tasks\`, `SYSTEM\...\Services`, 7045/4697/4698 | Persistence that executes | Cross-check with `hunt-windows-persistence` |

```powershell
# Prefetch: all files, CSV + JSON
PECmd.exe -d C:\case\C\Windows\Prefetch --csv C:\case\parsed\prefetch
# Amcache: include unassociated file entries
AmcacheParser.exe -f C:\case\C\Windows\AppCompat\Programs\Amcache.hve -i --csv C:\case\parsed\amcache
# ShimCache from an offline SYSTEM hive (replay .LOG1/.LOG2 if the hive is dirty)
AppCompatCacheParser.exe -f C:\case\C\Windows\System32\config\SYSTEM --csv C:\case\parsed\shimcache
# SRUM (needs SOFTWARE hive)
SrumECmd.exe -f C:\case\C\Windows\System32\sru\SRUDB.dat -r C:\case\C\Windows\System32\config\SOFTWARE --csv C:\case\parsed\srum
```

## File and folder access

| Artifact | Location | Answers |
|---|---|---|
| LNK files | `%APPDATA%\Microsoft\Windows\Recent\*.lnk`, Office `Recent` folders | User opened a file; target path, size, MAC times of target, volume serial, NetBIOS name / MAC of origin host |
| Jump Lists | `%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\*.automaticDestinations-ms`, `CustomDestinations\*.customDestinations-ms` | Files opened per application (AppID in filename) incl. remote paths |
| ShellBags | `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` (primary on Win7+), `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` | Folders browsed in Explorer, incl. removable media, network shares, ZIP contents, deleted folders |
| RecentDocs | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` | Recently opened files by extension (MRU order) |
| Open/Save dialogs | `...\Explorer\ComDlg32\OpenSavePidlMRU`, `LastVisitedPidlMRU` | Files opened/saved via common dialogs and the executable that used them |
| Typed paths / Run | `...\Explorer\TypedPaths`, `...\Explorer\RunMRU`, `...\Explorer\WordWheelQuery` | Paths typed into Explorer, Win+R commands, Explorer search terms |

```powershell
LECmd.exe  -d C:\case\C\Users --csv C:\case\parsed\lnk
JLECmd.exe -d C:\case\C\Users --csv C:\case\parsed\jumplists
SBECmd.exe -d C:\case\C\Users --csv C:\case\parsed\shellbags
```

## NTFS file system

| Artifact | Path | Use |
|---|---|---|
| `$MFT` | `C:\$MFT` | Every file record: `$STANDARD_INFORMATION` (SI) and `$FILE_NAME` (FN) MACB times, size, parent, resident data for small files, deleted-but-not-reused records |
| `$UsnJrnl:$J` | `C:\$Extend\$UsnJrnl:$J` (alternate data stream) | Change journal: create, rename, delete, data overwrite per file reference with timestamp; typically days to weeks |
| `$LogFile` | `C:\$LogFile` | Transaction log of metadata changes; short window (often hours) |
| `$I30` | Directory index attribute | Slack entries can reveal files that were deleted from a directory |

```powershell
MFTECmd.exe -f 'C:\case\C\$MFT' --csv C:\case\parsed\mft
# Resolve parent paths in the journal using the MFT (supported in current MFTECmd builds)
MFTECmd.exe -f 'C:\case\C\$Extend\$J' -m 'C:\case\C\$MFT' --csv C:\case\parsed\usnjrnl
# Bodyfile output for mactime / timeline-analysis
MFTECmd.exe -f 'C:\case\C\$MFT' --body C:\case\parsed\body --bdl C
```

`$LogFile` is not parsed by MFTECmd; use a dedicated parser (for example
LogFileParser or NTFS Log Tracker) if you need it.

**Timestomping (T1070.006) checks:** SI created earlier than FN created;
SI times with zero sub-second precision (`.0000000`) while neighbours have
full precision; SI times earlier than the file's USN `FileCreate` record or
than the parent directory's creation; Prefetch/Amcache first-seen later than
the claimed creation.

## Event logs (`C:\Windows\System32\winevt\Logs\`)

| Log | Event IDs | Meaning |
|---|---|---|
| Security | 4624 / 4625 / 4634 / 4647 | Logon success (check Logon Type 2, 3, 7, 10, 11) / failure / logoff |
| Security | 4648 | Logon with explicit credentials (runas, lateral movement source) |
| Security | 4672 | Special privileges assigned to new logon (admin-equivalent) |
| Security | 4688 / 4689 | Process created / exited |
| Security | 4697, 4698, 4702 | Service installed, scheduled task created / updated |
| Security | 4720, 4722, 4724, 4728, 4732, 4756, 4738 | Account created, enabled, password reset, added to global/local/universal group, changed |
| Security (DC) | 4768, 4769, 4771, 4776 | Kerberos TGT, service ticket, pre-auth failure, NTLM validation (`hunt-ad-identity-attacks`) |
| Security | 1102 | Security log cleared (T1070.001) |
| System | 7045, 7036, 7040 | Service installed, state change, start type change |
| System | 104 | Log cleared |
| PowerShell/Operational | 4103, 4104 | Module logging, Script Block logging (decoded script text) |
| Windows PowerShell | 400, 403, 800 | Engine start/stop (HostApplication shows command line), pipeline |
| TerminalServices-RemoteConnectionManager/Operational | 1149 | RDP network authentication succeeded (source IP) |
| TerminalServices-LocalSessionManager/Operational | 21, 22, 24, 25 | RDP session logon, shell start, disconnect, reconnect |
| TerminalServices-RDPClient/Operational | 1024, 1102 | Outbound RDP from this host (destination) |
| TaskScheduler/Operational | 106, 140, 141, 200, 201 | Task registered, updated, deleted, action started, completed |
| WMI-Activity/Operational | 5857, 5860, 5861 | Provider load, temporary / permanent event consumer |
| WinRM/Operational | 6, 91 | WSMan session created (client), shell request (server) |
| Windows Defender/Operational | 1116, 1117, 5001, 5007 | Detection, action taken, real-time protection disabled, config changed |
| Sysmon/Operational | 1, 3, 7, 8, 10, 11, 12-14, 22 | Process, network, image load, remote thread, process access, file create, registry, DNS |

```powershell
# Parse all EVTX to CSV using the community maps
EvtxECmd.exe -d C:\case\C\Windows\System32\winevt\Logs --csv C:\case\parsed\evtx
```

### Chainsaw and Hayabusa (fast detection pass)

```bash
# Chainsaw: Sigma + built-in rules over a folder of EVTX, CSV per rule group
chainsaw hunt ./evtx/ -s ./sigma/ --mapping ./mappings/sigma-event-logs-all.yml -r ./rules/ --csv --output ./chainsaw_out/
# Chainsaw: keyword search
chainsaw search "mimikatz" -i ./evtx/
# Hayabusa: detection timeline in UTC (flags and wizard behaviour vary by version; see `hayabusa help`)
hayabusa csv-timeline -d ./evtx/ -o hayabusa_timeline.csv -U
```

Treat both as triage. Every hit is re-verified against the raw event
(`EvtxECmd` output or Event Viewer of a copy), and severity labels are the
rule author's, not your verdict.

## Registry

Hives: `C:\Windows\System32\config\{SYSTEM,SOFTWARE,SAM,SECURITY}`,
`C:\Users\<u>\NTUSER.DAT`, `C:\Users\<u>\AppData\Local\Microsoft\Windows\UsrClass.dat`,
`Amcache.hve`. Always collect the `.LOG1`/`.LOG2` transaction logs; a dirty hive
without them is missing recent writes. Resolve `CurrentControlSet` via
`SYSTEM\Select\Current` on offline hives.

| Question | Key |
|---|---|
| Host name, time zone | `SYSTEM\...\Control\ComputerName\ComputerName`, `SYSTEM\...\Control\TimeZoneInformation` |
| Network history | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles`, `SYSTEM\...\Services\Tcpip\Parameters\Interfaces` |
| USB devices | `SYSTEM\...\Enum\USBSTOR`, `SYSTEM\...\Enum\USB`, `SYSTEM\MountedDevices`, `SOFTWARE\Microsoft\Windows Portable Devices\Devices` |
| Autoruns | `Software\Microsoft\Windows\CurrentVersion\Run`/`RunOnce` (HKLM + HKCU), `SYSTEM\...\Services`, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` |
| Local accounts | `SAM\SAM\Domains\Account\Users` |
| Installed software | `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` |
| RDP outbound targets | `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers` |

```powershell
# Batch-parse all hives with a curated batch file (ships with RECmd)
RECmd.exe -d C:\case\C --bn .\BatchExamples\Kroll_Batch.reb --csv C:\case\parsed\registry
```

Registry Explorer is the GUI equivalent; key "last write" time applies to the
key, not to an individual value.

## Browser history

| Browser | File | Time format |
|---|---|---|
| Chrome | `%LOCALAPPDATA%\Google\Chrome\User Data\<Profile>\History` (SQLite) | WebKit: microseconds since 1601-01-01 UTC |
| Edge (Chromium) | `%LOCALAPPDATA%\Microsoft\Edge\User Data\<Profile>\History` | WebKit |
| Firefox | `%APPDATA%\Mozilla\Firefox\Profiles\<profile>\places.sqlite` | PRTime: microseconds since 1970-01-01 UTC |

Also collect `Downloads` (Chromium `History` table `downloads`, Firefox
`places.sqlite` annotations), `Web Data`, `Login Data` metadata (not
contents), and the `-wal` files. Tools: Hindsight (Chromium), plaso parsers,
or a SQLite browser on a copy.

## What answers which question

| Question | Primary artifacts | Corroborate with |
|---|---|---|
| Did X execute? When? | Prefetch, BAM, 4688/Sysmon 1, PCA | Amcache (SHA-1), UserAssist, SRUM, EDR |
| Did X exist on disk? | $MFT, Amcache, ShimCache | $J FileCreate, Defender 1116 |
| Who ran it? | 4688 SubjectUserSid, BAM SID, UserAssist (per NTUSER) | 4624 for that LogonId |
| How did the actor log on? | 4624 type + source IP, 1149, 21/22 | 4648 on the source host, VPN/IdP logs |
| Where did they move next? | 4648, RDPClient 1024, `Terminal Server Client\Servers`, Jump Lists for `mstsc` | Destination 4624 type 3/10 (`hunt-lateral-movement`) |
| What files did the user open? | LNK, Jump Lists, RecentDocs, OpenSavePidlMRU | $MFT access/USN, ShellBags for folders |
| Was data staged/exfiltrated? | $J (archive creation), Prefetch of 7z/rar/rclone, SRUM bytes sent | Proxy/firewall logs (`hunt-exfiltration`) |
| Was USB used? | USBSTOR, MountedDevices, LNK volume serial | ShellBags, Partition/Diagnostic log 1006 (if present) |
| Persistence? | Run keys, Services, Tasks, WMI | 7045/4697/4698, `hunt-windows-persistence` |
| Anti-forensics? | 1102, 104, $J mass deletes, timestomp checks | Gaps in EVTX record IDs, missing Prefetch |

## Verdict table

| Verdict | Evidence that moves it |
|---|---|
| True Positive | Two independent execution artifacts + malicious context (unexpected path, known-bad hash, followed by persistence or credential access) |
| Benign True Positive | Execution confirmed but tied to an approved admin task, change ticket, or sanctioned tool (verify the ticket, not the user's word) |
| False Positive | Artifact is presence-only (ShimCache/Amcache) and execution artifacts that would exist are absent, or detection misparsed a benign path |
| Needs more data | Single artifact only; key artifact disabled/rolled; time window predates log retention - collect VSS, memory, EDR, network logs |

## False positives & benign look-alikes

- Amcache/ShimCache entries for files that were only browsed, copied, or
  extracted by an installer.
- Prefetch for `RUNDLL32.EXE`, `SVCHOST.EXE`, `DLLHOST.EXE` with multiple hashes:
  the hash includes the path/command line for hosting processes.
- 4624 type 3 from domain controllers, backup and vulnerability scanners.
- Event 7045 for legitimate driver/agent updates (EDR, VPN, printer drivers).
- SI/FN mismatch caused by legitimate copy/extract tools that preserve source
  timestamps (archivers, robocopy `/COPY:T`), not only by timestomping.
- PowerShell 4104 warnings from management tooling (SCCM/Intune scripts).

## Pitfalls

- Reading ShimCache timestamps as execution times.
- Analysing a dirty hive without replaying transaction logs.
- Forgetting UsrClass.dat (ShellBags) and the `.LOG` files in collection.
- Live-response tools creating their own Prefetch/Amcache entries that later
  look like attacker activity - log your own tool use with UTC times.
- Event Viewer shows local time; EvtxECmd/Hayabusa CSVs are UTC (check
  options) - never mix.
- Assuming log clearing removed everything: check other logs, forwarded
  SIEM copies, VSS, and EVTX slack via carving.
- Prefetch absent on servers by default - absence there means nothing.
- Over-trusting tool versions: Win11 builds change artifact formats; record
  tool name and version in the evidence notes.

## Output

- Parsed artifact CSVs per class under the case folder, with tool versions.
- Findings added to the incident timeline CSV (`timeline-analysis` format:
  `timestamp_utc, host, source, event, detail, analyst, confidence`).
- Evidence-log rows for every exported artifact (`evidence-handling`).
- A short answer per scoped question with the artifacts that support it.
- Hand-offs: binaries -> `malware-triage`; IOCs -> `threat-intel-ioc` / `/ioc`;
  memory -> `memory-forensics`; report -> `ir-report-writing` / `/report`.
  Command entry point: `/forensics`; agent: forensic-analyst.

## References

- MITRE ATT&CK: T1070.001 Clear Windows Event Logs, T1070.006 Timestomp,
  T1070.004 File Deletion, T1547.001 Registry Run Keys, T1543.003 Windows
  Service, T1053.005 Scheduled Task, T1021.001 RDP, T1059.001 PowerShell,
  T1562.002 Disable Windows Event Logging.
- RFC 3227 Guidelines for Evidence Collection and Archiving.
- NIST SP 800-86 Guide to Integrating Forensic Techniques into Incident Response.
- Eric Zimmerman's tools documentation (PECmd, AmcacheParser, AppCompatCacheParser,
  MFTECmd, EvtxECmd, RECmd, LECmd, JLECmd, SBECmd, SrumECmd, Timeline Explorer).
- KAPE and Velociraptor documentation; Chainsaw (WithSecure Labs) and Hayabusa
  (Yamato Security) READMEs.
- Microsoft Learn: Audit events reference (Security auditing event IDs).
- SANS "Windows Forensic Analysis" poster (artifact categories).
