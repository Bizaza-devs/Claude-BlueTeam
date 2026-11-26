---
name: hunt-credential-access
description: Threat hunt for credential access on Windows and Entra ID (TA0006): LSASS access (Sysmon 10 GrantedAccess masks 0x1010/0x1410/0x1438/0x143a/0x1fffff, CallTrace, Defender OpenProcessApiCall), comsvcs MiniDump and procdump dumps, SAM/SYSTEM/SECURITY hive saves, NTDS.dit via ntdsutil IFM and shadow copies, DPAPI and Credential Manager, browser credential stores, credential files and GPP cpassword, keylogging, password spraying (4625 sub-status, 4771 0x18, 4776, Entra 50126/50053/50076) and Kerberos brute force or user enumeration (4768 0x6). KQL, SPL and Sigma per behaviour. Use when asked to "hunt credential dumping", "LSASS access", "mimikatz", "T1003.001", "NTDS.dit", "password spray", "brute force", "T1110.003" or "were credentials stolen".
---

# Hunt: credential access

Credential theft is the pivot point of most intrusions: once it succeeds, the
attacker looks like a user. Hunt the read of the secret store (LSASS, hives,
NTDS, DPAPI blobs, browser stores) and the guessing of secrets (spraying,
brute force). Kerberos ticket attacks (Kerberoasting, AS-REP roasting, DCSync,
forged tickets) live in `hunt-ad-identity-attacks`.

## When to use

- Intel or an incident mentions Mimikatz, nanodump, comsvcs MiniDump,
  procdump, secretsdump, LaZagne, browser stealers or password spraying.
- After lateral movement is found: how did the actor get the credential?
- Unexplained account lockouts, Entra smart-lockout events or MFA prompts
  users did not trigger.
- Validating that ASR/Credential Guard/RunAsPPL actually protect LSASS.

## Ground rules

1. **Access is not theft.** Many signed tools open LSASS. A credential-access
   finding needs the source process identity (path, signer, hash, parent), the
   access mask or API, and a second artefact (dump file, outbound transfer,
   follow-on logon with the credential) before it is a TP.
2. **Assume stolen once proven.** A confirmed dump means every credential
   cached on that host is compromised; scope affected accounts (logon sessions
   present on the host in the window) before anyone resets anything.
3. **Resets are containment, not hunting.** Password resets, krbtgt rotation
   and token revocation go through `incident-response` / `/contain` with
   approval; resetting early tips off the actor and loses scope.
4. **Spray verdicts need the denominator.** Report attempts, distinct users,
   distinct sources and successes; a spray claim without the success check
   (correct-password results) is incomplete.

## Workflow

1. Hypothesis and scope via `hunt-dispatch`; decide host-side (LSASS, hives,
   NTDS, DPAPI) vs. authentication-side (spray, brute force) or both.
2. Data check: Sysmon 10 with an LSASS-targeted config, or MDE; 4625/4771/4776
   on DCs; SigninLogs + AADNonInteractiveUserSignInLogs; command-line logging.
3. High-signal first: dump command lines, `.dmp` files, hive saves, NTDS copies.
4. Broad: all LSASS opens with read rights, stacked by source image + signer + mask.
5. Authentication: spray/brute-force shapes, then check for successes.
6. Pivot: on a hit, list accounts with sessions on the host, then look for
   their use elsewhere (`hunt-lateral-movement`).
7. Conclude, report, convert detections; protection gaps to `hardening-windows-ad`.

## ATT&CK sub-technique map

| Behaviour | ATT&CK | Primary evidence |
|---|---|---|
| LSASS memory read / dump | T1003.001 | Sysmon 10, OpenProcessApiCall, `.dmp` creation, comsvcs/procdump command lines |
| SAM / SYSTEM / SECURITY hives | T1003.002, T1003.004 (LSA secrets), T1003.005 (cached creds) | `reg save`, shadow-copy reads, 4656/4663 with SACL |
| NTDS.dit | T1003.003 | ntdsutil IFM, vssadmin/diskshadow, ESENT events, file copies on DCs |
| DCSync | T1003.006 | See `hunt-ad-identity-attacks` |
| Credential Manager / DPAPI | T1555.004 | `vaultcmd`, access to `Microsoft\Credentials`, `Protect` master keys |
| Browser stores | T1555.003 | Non-browser access to `Login Data`, `Local State`, `logins.json`, `key4.db` |
| Credential files / GPP | T1552.001, T1552.006 | `findstr /si password`, `Groups.xml` cpassword reads |
| Registry credentials | T1552.002 | `reg query ... /f password /s` |
| Keylogging | T1056.001 | Hooking APIs (EDR), unknown binaries in startup with input capture |
| Password spraying / brute force / stuffing | T1110.003 / T1110.001 / T1110.004 | 4625, 4771, 4776, SigninLogs |

## Data sources required

| Source | Needed for | Note |
|---|---|---|
| Sysmon 10 (ProcessAccess) targeted at lsass.exe | LSASS access | Config must include TargetImage lsass.exe; capture CallTrace |
| MDE DeviceEvents (OpenProcessApiCall), DeviceProcessEvents, DeviceFileEvents | LSASS, dumps, tools | OpenProcessApiCall coverage is selective; do not treat absence as proof |
| Process creation with command line (4688 + policy, Sysmon 1) | Dump tools, reg save, ntdsutil | Required |
| Sysmon 11 / DeviceFileEvents | `.dmp`, hive and ntds copies | |
| Security 4656/4663 with SACLs | Browser stores, DPAPI, hives read | Not on by default; scope SACLs tightly |
| DC: 4625, 4771, 4776, 4768, 4740 | Spray, brute force, lockouts | "Audit Kerberos Authentication Service", "Audit Credential Validation" (failures) |
| Entra SigninLogs + AADNonInteractiveUserSignInLogs | Cloud spray | Non-interactive logs are where much legacy-protocol spraying shows |
| Application log ESENT 216/325/326/327 | NTDS copies via ntdsutil | On DCs |

## Behaviours and queries

### 1. LSASS process access

Access-right bits (hex): `0x10` PROCESS_VM_READ, `0x400` QUERY_INFORMATION,
`0x1000` QUERY_LIMITED_INFORMATION, `0x8` VM_OPERATION, `0x20` VM_WRITE,
`0x2` CREATE_THREAD, `0x40` DUP_HANDLE, `0x1fffff` PROCESS_ALL_ACCESS.
Common credential-theft masks: `0x1010` (QLI + VM_READ), `0x1410`, `0x1438`,
`0x143a`, `0x1fffff`, and `0x40` (handle duplication to dump via a cloned
handle). The core signal is any VM_READ (`0x10`) from an unexpected process.
`0x1000`/`0x1400` alone are widespread and mostly benign.

```kql
// MDE: LSASS opens by non-system processes; stack by source + signer. Verify DesiredAccess key in AdditionalFields.
DeviceEvents
| where Timestamp > ago(30d) and ActionType == "OpenProcessApiCall" and FileName =~ "lsass.exe"
| extend Access = tolong(parse_json(AdditionalFields).DesiredAccess)
| where binary_and(Access, 0x10) != 0 or Access == 0x40
| join kind=leftouter (DeviceFileCertificateInfo | summarize Signer = any(Signer) by SHA1) on $left.InitiatingProcessSHA1 == $right.SHA1
| summarize Hosts = dcount(DeviceId), Masks = make_set(Access, 10), First = min(Timestamp)
    by InitiatingProcessFolderPath, InitiatingProcessFileName, Signer
| order by Hosts asc
```

SPL - Sysmon 10 with read rights; tune the allowlist of EDR/AV/backup images:

```spl
index=sysmon source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10 TargetImage="*\\lsass.exe"
  GrantedAccess IN ("0x1010","0x1410","0x1438","0x143a","0x1fffff","0x40","0x1418","0x147a")
  NOT SourceImage IN ("C:\\Windows\\System32\\wininit.exe","C:\\Windows\\System32\\csrss.exe","C:\\Windows\\System32\\svchost.exe")
| eval dbghelp=if(match(CallTrace,"(?i)dbghelp|dbgcore"),1,0), unknown_region=if(match(CallTrace,"UNKNOWN"),1,0)
| stats count dc(host) as hosts values(GrantedAccess) as masks max(dbghelp) as dbghelp max(unknown_region) as unknown by SourceImage
| sort hosts
```

```yaml
title: LSASS Access With Read Rights From Unusual Location Or With Dump Call Trace
status: experimental
logsource: {product: windows, category: process_access}
detection:
  target:
    TargetImage|endswith: '\lsass.exe'
  rights:
    GrantedAccess: ['0x1010', '0x1410', '0x1438', '0x143a', '0x1fffff', '0x40']
  path:
    SourceImage|contains: ['\Temp\', '\Users\Public\', '\AppData\', '\ProgramData\', '\Downloads\']
  trace:
    CallTrace|contains: ['dbghelp.dll', 'dbgcore.dll', 'UNKNOWN']
  condition: target and rights and (path or trace)
falsepositives: [EDR/AV, backup and crash-dump tools - allowlist by signed path]
level: high
tags: [attack.credential_access, attack.t1003.001]
```

`UNKNOWN` in CallTrace means the call came from memory not backed by a module
on disk (shellcode / reflective loading) and is high-signal.

### 2. LSASS dump tooling and dump files

```kql
// MDE: known dump command lines and .dmp files written by unexpected processes.
union
(DeviceProcessEvents
 | where Timestamp > ago(30d)
 | where (ProcessCommandLine has "comsvcs" and ProcessCommandLine has_any ("MiniDump", "#24", "#+24"))
      or (ProcessVersionInfoOriginalFileName =~ "procdump" and ProcessCommandLine has_any ("lsass", "-ma"))
      or (ProcessCommandLine has_any ("sekurlsa::", "lsadump::", "privilege::debug"))
      or (FileName =~ "rdrleakdiag.exe" and ProcessCommandLine has "/fullmemdmp")
 | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName),
(DeviceFileEvents
 | where Timestamp > ago(30d) and ActionType == "FileCreated" and FileName endswith ".dmp"
 | where FileName has "lsass" or InitiatingProcessFileName in~ ("rundll32.exe", "powershell.exe", "cmd.exe", "taskmgr.exe")
 | project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName, FileName = FolderPath, ProcessCommandLine = InitiatingProcessCommandLine, InitiatingProcessFileName)
```

```spl
index=sysmon source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
  ((EventCode=1 (CommandLine="*comsvcs*MiniDump*" OR CommandLine="*comsvcs*#24*" OR (OriginalFileName="procdump" CommandLine="*lsass*") OR CommandLine="*sekurlsa::*"))
   OR (EventCode=11 TargetFilename="*.dmp" (TargetFilename="*lsass*" OR Image IN ("*\\rundll32.exe","*\\powershell.exe","*\\taskmgr.exe"))))
| table _time host User Image CommandLine TargetFilename
```

```yaml
title: LSASS Dump Via Comsvcs MiniDump
status: experimental
logsource: {product: windows, category: process_creation}
detection:
  selection:
    Image|endswith: '\rundll32.exe'
    CommandLine|contains: 'comsvcs'
  dump:
    CommandLine|contains: ['MiniDump', '#24', '#+24', '#-4294967272']
  condition: selection and dump
falsepositives: [None expected outside support-led crash diagnostics]
level: critical
tags: [attack.credential_access, attack.t1003.001, attack.defense_evasion, attack.t1218.011]
```

Task Manager "Create dump file" on lsass writes `lsass.DMP` under the user's
`%TEMP%`; legitimate only in a documented support case. Attackers also obfuscate
the ordinal (`#+24`, negative/large forms) and rename `comsvcs.dll`; stack
rundll32 command lines ending in `full` with a PID-like number.

### 3. SAM/SYSTEM/SECURITY hives and NTDS.dit

```kql
// MDE: hive saves, IFM creation, shadow copy creation/paths used to copy locked files.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName =~ "reg.exe" and ProcessCommandLine has_any ("save", "export") and ProcessCommandLine has_any (@"hklm\sam", @"hklm\system", @"hklm\security", "HKEY_LOCAL_MACHINE\\SAM"))
     or (FileName =~ "ntdsutil.exe" and ProcessCommandLine has_any ("ifm", "create full"))
     or (FileName in~ ("vssadmin.exe", "wmic.exe", "diskshadow.exe") and ProcessCommandLine has_any ("create shadow", "shadowcopy call create", "/s "))
     or ProcessCommandLine has_any (@"GLOBALROOT\Device\HarddiskVolumeShadowCopy", @"\NTDS\ntds.dit", @"config\SAM")
     or (FileName =~ "esentutl.exe" and ProcessCommandLine has_any ("/vss", "ntds.dit"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
```

```spl
index=sysmon source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  ((Image="*\\reg.exe" CommandLine="*save*" (CommandLine="*hklm\\sam*" OR CommandLine="*hklm\\system*" OR CommandLine="*hklm\\security*"))
   OR (Image="*\\ntdsutil.exe" CommandLine="*ifm*") OR CommandLine="*HarddiskVolumeShadowCopy*" OR CommandLine="*ntds.dit*"
   OR (Image="*\\vssadmin.exe" CommandLine="*create shadow*"))
| table _time host User ParentImage Image CommandLine
```

```yaml
title: Registry Hive Saved For Offline Credential Extraction
status: experimental
logsource: {product: windows, category: process_creation}
detection:
  selection:
    Image|endswith: '\reg.exe'
    CommandLine|contains: [' save ', ' export ']
  hive:
    CommandLine|contains: ['hklm\sam', 'hklm\system', 'hklm\security', 'HKEY_LOCAL_MACHINE\SAM', 'HKEY_LOCAL_MACHINE\SECURITY']
  condition: selection and hive
falsepositives: [Backup or imaging scripts - rare; verify owner]
level: high
tags: [attack.credential_access, attack.t1003.002, attack.t1003.004]
```

On DCs, `ntdsutil "ac i ntds" "ifm" "create full <path>"` also logs ESENT
events (216/325/326/327) in the Application log; IFM media created outside a
DC promotion or backup procedure is a lead. Look for the copied `ntds.dit` +
`SYSTEM` leaving the DC (5145 reads from admin shares, archive creation).

### 4. DPAPI, Credential Manager, browser stores and credential files

```kql
// MDE: command lines touching credential stores or hunting for passwords; stack by process.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has_any (@"\Login Data", @"\Local State", "logins.json", "key4.db", @"\Microsoft\Credentials", @"\Microsoft\Protect",
        "vaultcmd", "cmdkey /list", "dpapi::", "Groups.xml", "cpassword", "unattend.xml")
     or (FileName in~ ("findstr.exe", "select-string") and ProcessCommandLine has_any ("password", "passw", "pwd") and ProcessCommandLine has_any ("/s", "/si", "-Recurse"))
| where not(FileName in~ ("chrome.exe", "msedge.exe", "firefox.exe", "brave.exe"))
| summarize Count = count(), Hosts = dcount(DeviceId), Sample = any(ProcessCommandLine) by FileName, InitiatingProcessFileName, AccountName
| order by Hosts asc
```

```spl
index=sysmon source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  (CommandLine="*\\Login Data*" OR CommandLine="*logins.json*" OR CommandLine="*key4.db*" OR CommandLine="*vaultcmd*"
   OR CommandLine="*dpapi::*" OR CommandLine="*cpassword*" OR (Image="*\\findstr.exe" CommandLine="*/si*" CommandLine="*pass*"))
  NOT Image IN ("*\\chrome.exe","*\\msedge.exe","*\\firefox.exe")
| stats count dc(host) as hosts values(CommandLine) as cmds by Image ParentImage User
```

```yaml
title: Non-Browser Process Accessing Browser Credential Store (SACL Required)
status: experimental
logsource: {product: windows, service: security}
detection:
  selection:
    EventID: 4663
    ObjectName|endswith: ['\User Data\Default\Login Data', '\User Data\Local State', '\logins.json', '\key4.db']
  browsers:
    ProcessName|endswith: ['\chrome.exe', '\msedge.exe', '\firefox.exe', '\brave.exe', '\opera.exe']
  condition: selection and not browsers
falsepositives: [Backup/sync agents, AV scanning, browser updaters - allowlist by signed path]
level: high
tags: [attack.credential_access, attack.t1555.003]
```

Paths: Chromium `%LOCALAPPDATA%\<vendor>\<browser>\User Data\<profile>\Login Data`
(+ `Local State` for the key), Firefox `%APPDATA%\Mozilla\Firefox\Profiles\<p>\logins.json`
and `key4.db`; Credential Manager `%APPDATA%\Microsoft\Credentials` and
`%LOCALAPPDATA%\Microsoft\Credentials`; DPAPI master keys
`%APPDATA%\Microsoft\Protect\<SID>\`. On DCs, Security 4692/4693 record DPAPI
master-key backup/recovery attempts; domain DPAPI backup-key retrieval is a
tier-0 event (hand to `hunt-ad-identity-attacks`). SYSVOL `Groups.xml` with
`cpassword` is a finding even with no attacker: the key is public.

Keylogging (T1056.001) is hard to see in logs. Hunt unsigned binaries in
autostart locations (`hunt-windows-persistence`) and, if your EDR exposes
input-capture API telemetry (MDE has API-call ActionTypes for this; confirm
names in your schema), stack by process and signer.

### 5. Password spraying (on-prem and Entra ID)

4625 `SubStatus`: `0xC000006A` bad password, `0xC0000064` unknown user,
`0xC0000234` locked, `0xC0000072` disabled, `0xC0000071` expired password.
4771 `Status 0x18` = pre-auth failed (bad password). 4776 uses the same
`0xC000006A`/`0xC0000064` codes. Entra `ResultType`: `50126` invalid
username/password, `50053` locked (smart lockout or blocked IP), `50057`
disabled, `50055` expired password, `50076`/`50074` MFA required (the
password was correct), `0` success.

```kql
// Sentinel/Entra: one source, many users, few attempts each; then show users who got past the password.
let window = 1h;
let Sprays = union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(14d) and ResultType in ("50126", "50053", "50055", "50057")
| summarize Users = dcount(UserPrincipalName), Attempts = count() by IPAddress, bin(TimeGenerated, window)
| where Users >= 10 and Attempts / Users <= 3;      // tune thresholds to tenant size
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(14d) and IPAddress in ((Sprays | distinct IPAddress))
| summarize Fails = countif(ResultType == "50126"), PasswordOK = countif(ResultType in ("0", "50076", "50074", "50158")),
    Apps = make_set(AppDisplayName, 10), Agents = make_set(UserAgent, 5) by IPAddress, UserPrincipalName
| where PasswordOK > 0
```

```spl
index=wineventlog source="XmlWinEventLog:Security" (EventCode=4625 SubStatus IN ("0xC000006A","0xc000006a","0xC0000064","0xc0000064")) OR (EventCode=4771 Status=0x18) OR (EventCode=4776 Status IN ("0xC000006A","0xc000006a"))
| eval src=coalesce(IpAddress, Workstation, WorkstationName), user=lower(TargetUserName)
| bin _time span=1h
| stats dc(user) as users count as attempts by src _time
| where users>=10 AND attempts/users<=3
```

```yaml
title: Kerberos Pre-Authentication Failures Across Many Accounts From One Source
status: experimental
logsource: {product: windows, service: security}
detection:
  selection:
    EventID: 4771
    Status: '0x18'
  timeframe: 1h
  condition: selection | count(TargetUserName) by IpAddress > 10
falsepositives: [NAT/VPN concentrators and Citrix/RDS hosts aggregating many users; stale credentials on shared kiosks]
level: medium
tags: [attack.credential_access, attack.t1110.003]
```

The Sigma rule uses the legacy aggregation syntax; newer Sigma correlation
rules express the same as a `value_count` correlation - convert with
`sigma-rules` for your backend.

### 6. Kerberos brute force and user enumeration

- **Brute force against one account:** many 4771 `0x18` for one
  `TargetUserName` (often ending in 4740 lockout). Compare with the account's
  normal failure rate (stale mapped drives and phones cause steady failures).
- **User enumeration:** bursts of 4768 with `Status 0x6`
  (KDC_ERR_C_PRINCIPAL_UNKNOWN) from one IP, then 4768/4771 only for names
  that exist.

```kql
// Sentinel: Kerberos user enumeration (0x6) and per-account brute force (0x18) per source per hour.
SecurityEvent
| where TimeGenerated > ago(14d) and ((EventID == 4768 and Status == "0x6") or (EventID == 4771 and Status == "0x18"))
| summarize Users = dcount(TargetUserName), Attempts = count(), Codes = make_set(Status) by IpAddress, EventID, bin(TimeGenerated, 1h)
| where (EventID == 4768 and Users >= 20) or (EventID == 4771 and Attempts / Users >= 10)
```

## Baselining and stacking

- **LSASS:** stack (source image path, signer, mask) across hosts. Expect a
  short list of EDR/AV, `MsMpEng.exe`, `csrss.exe`, `wininit.exe`, `svchost.exe`,
  some management agents. Any unsigned, user-path or script-host source, or a
  signed tool seen on <= 3 hosts, is a lead.
- **Spray:** baseline failures per source per hour for 30 days; alert on
  sources exceeding the 99th percentile of distinct users. Separate NAT/VPN
  egress and identity proxies first.
- **Credential-store access:** stack processes touching browser/DPAPI paths;
  the legitimate set is browsers, their updaters, sync and backup agents.

## False positives & benign look-alikes

| Look-alike | Resembles | How to tell |
|---|---|---|
| EDR/AV, Windows Defender (`MsMpEng.exe`) | LSASS read access | Signed, installed path, present on every host |
| WER / crash dump of lsass | `.dmp` of lsass | `WerFault.exe` after an lsass crash, event 1000/1001 |
| Support-led procdump | procdump `-ma lsass` | Support ticket, vendor case number, admin workstation |
| Backup software | Hive/NTDS shadow copies | Backup service account, VSS writers, schedule |
| DC promotion / IFM for RODC | ntdsutil ifm | Change record |
| Password managers, browser sync | Credential store access | Signed vendor binary, consistent across users |
| Expired passwords on phones/mapped drives | Repeated 4771/4625 | One account, one source, steady over days |
| Shared egress (VPN, proxy, Citrix) | Spray from one IP | Many users succeed normally from the same IP |

## Pitfalls

- Hard-coding masks: tools change masks; key on VM_READ and on CallTrace.
- Credential Guard / RunAsPPL in place does not stop a kernel driver or a
  dump of a PPL-bypass; it moves the signal to driver loads (Sysmon 6).
- Missing `AADNonInteractiveUserSignInLogs`: legacy-auth sprays often appear
  only there.
- Counting 50076 as a failure: it means the password was right.
- Ignoring the "success after spray" check - the only question that matters
  for scoping.
- Not hashing and preserving found dump files before analysis (`evidence-handling`).

## Escalation criteria

- Any LSASS dump command line, lsass `.dmp` outside a ticketed support case, or
  LSASS read access from an unsigned / user-path / UNKNOWN-trace source.
- Hive save or IFM/shadow-copy copy of `ntds.dit` on any DC without a change.
- Spray with at least one correct-password result (0, 50076, 50074, 50158) or
  an on-prem success for a sprayed account.
- Non-browser process reading browser stores on more than one host.

| Verdict | Evidence that moves it |
|---|---|
| True Positive | Read/dump + second artefact (dump file, exfil, follow-on logon) |
| Benign True Positive | Signed owned tool, ticket, expected account and host |
| False Positive | Mask/rule matched benign system component; tune allowlist |
| Needs more data | No CallTrace, no file telemetry; pull memory/live response via `memory-forensics` |

## Output

```markdown
## Hunt report - credential access - <HUNT-ID>
- Hypothesis / status: <supported | refuted | inconclusive>
- Scope & window: <hosts/tenant>, <UTC range>; Sysmon 10/MDE coverage <n>%, DC auth logs <yes/no>, Entra logs <yes/no>
- Behaviours covered: <LSASS, hives, NTDS, DPAPI, browser, spray, brute force> (ATT&CK IDs)
- Findings: | Time (UTC) | Host/IP | Account | Behaviour | Evidence (2+) | Accounts exposed | Verdict |
- Spray summary: sources <n>, users targeted <n>, password-correct <n>, MFA-blocked <n>
- Detections proposed: <titles>; protections missing: <ASR LSASS rule, RunAsPPL, Credential Guard, smart lockout>
```

Hand-offs: confirmed theft to `incident-response` (credential-reset scope,
approval-gated), follow-on use to `hunt-lateral-movement`, AD-level attacks to
`hunt-ad-identity-attacks`, Entra cases to `ir-azure-entra`, dump/tool binaries
to `malware-triage`, protections to `hardening-windows-ad` and
`hardening-m365-entra`, detections to `detection-engineering`.

## References

- MITRE ATT&CK TA0006 Credential Access; T1003.001-.006, T1555.003, T1555.004,
  T1552.001, T1552.006, T1056.001, T1110.001/.003/.004: https://attack.mitre.org/tactics/TA0006/
- Microsoft Learn: Process Security and Access Rights (access-mask values).
- Microsoft Learn: Attack surface reduction rules reference ("Block credential stealing from LSASS").
- Microsoft Learn: Microsoft Entra authentication and authorization error codes (AADSTS).
- Microsoft Learn: 4625, 4771, 4776 event documentation (status and sub-status codes).
- Sysinternals Sysmon documentation (Event ID 10 ProcessAccess, CallTrace).
