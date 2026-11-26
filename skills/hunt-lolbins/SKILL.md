---
name: hunt-lolbins
description: Threat hunt for living-off-the-land binaries and scripts (LOLBAS) on Windows: signed binary proxy execution (rundll32, regsvr32 Squiblydoo, mshta, cmstp, msiexec, odbcconf, mavinject), download/decode with certutil, bitsadmin, curl, desktopimgdownldr, trusted developer utilities (msbuild, installutil, regasm/regsvcs), wmic and XSL, cscript/wscript, PowerShell abuse (EncodedCommand, download cradles, -version 2, AMSI bypass strings in 4104), Office spawning shells, parent-child baselines and command-line length/entropy stacking. KQL, SPL and Sigma per behaviour. Use when asked to "hunt LOLBins", "signed binary proxy execution", "T1218", "T1059.001", "encoded PowerShell", "AMSI bypass", "certutil download", "Office spawning cmd" or "weird parent-child processes".
---

# Hunt: LOLBins and script abuse

Attackers prefer installed, Microsoft-signed, allowlisted tools. The binary is
never the signal; arguments, parent, path, network behaviour and rarity are.

## When to use

- Intel describes execution via rundll32, regsvr32, mshta, certutil, msbuild,
  installutil, wmic, script hosts or obfuscated PowerShell.
- Phishing payloads (`phishing-analysis`) used macros, HTA, LNK, ISO or JS.
- WDAC/AppLocker planning needs the list of LOLBins used legitimately.
- A process tree looks wrong and someone asks "is this normal here?".

## Ground rules

1. **The binary name is not evidence.** A finding states the full command
   line, parent chain, user, host role, and what the execution did next
   (child processes, files written, network connections). Two of those must
   be abnormal for the estate before it is called malicious.
2. **Decode before you judge.** Encoded or obfuscated command lines and script
   blocks are decoded (Base64 UTF-16LE for `-EncodedCommand`) and the decoded
   content is quoted in the case, with the decoding method recorded.
3. **Recover payloads safely.** Downloaded payloads are fetched only from
   evidence (disk, EDR file collection) into the sandbox per
   `malware-triage`; never re-download from the attacker URL on a corporate
   network.
4. **Blocking LOLBins is a change.** ASR/WDAC rules that block a binary can
   break administration; propose them via `hardening-windows-ad` with impact
   data from this hunt.

## Workflow

1. Hypothesis and scope via `hunt-dispatch`.
2. Data check: process creation with full command line and parent (MDE or
   Sysmon 1, or 4688 with "Include command line"), PowerShell 4104 on all
   hosts, network events per process.
3. Narrow pass: known-bad argument patterns per binary (sections 1-6).
4. Broad pass: parent-child stacking and command-line length/entropy (section 7).
5. For each lead: decode, walk the tree up (delivery) and down (payload,
   persistence, C2), check the same command line across the estate.
6. Conclude, report, convert: patterns that held up become detections; benign
   usage feeds WDAC/ASR planning.

## ATT&CK sub-technique map

| Binary / behaviour | ATT&CK | Key arguments / signal |
|---|---|---|
| rundll32 | T1218.011 | `javascript:`, `url.dll,OpenURL`, `shell32.dll,ShellExec_RunDLL`, DLL in user path, no arguments, network connections |
| regsvr32 | T1218.010 | `/s /n /u /i:http...` with `scrobj.dll` (Squiblydoo), DLL in user path |
| mshta | T1218.005 | `http(s)://`, `javascript:`, `vbscript:`, `.hta` from Downloads/Temp |
| cmstp / msiexec / odbcconf / mavinject / control / hh | T1218.003 / .007 / .008 / .013 / .002 / .001 | `/au` .inf; `/q /i http`; `/a {REGSVR`; `/INJECTRUNNING`; `.cpl` from user path; `.chm` from web |
| regasm / regsvcs | T1218.009 | `/U` with a non-installed assembly |
| installutil | T1218.004 | `/logfile= /LogToConsole=false /U` |
| msbuild | T1127.001 | Project file from user path, parent is not Visual Studio/build agent |
| certutil | T1105, T1140 | `-urlcache -split -f`, `-verifyctl -f`, `-decode`, `-decodehex` |
| bitsadmin, curl, desktopimgdownldr, esentutl, expand | T1105, T1197 | `/transfer`, `-o`, `/lockscreenurl:`, `/y` with remote path |
| wmic | T1047, T1220 | `process call create`, `/node:`, `/format:` with URL or `.xsl` |
| cscript / wscript | T1059.005 / T1059.007 | `.js/.jse/.vbs/.vbe/.wsf` from Downloads, Temp, archives |
| PowerShell | T1059.001, T1027, T1562.001 | `-enc`, `IEX`, `DownloadString`, `-w hidden`, `-version 2`, AMSI bypass strings |
| Office spawning shells | T1204.002, T1566.001 | winword/excel/powerpnt/outlook -> cmd/powershell/wscript/mshta/rundll32 |
| forfiles / pcalua | T1202 | Indirect execution of a second binary |

The LOLBAS project (lolbas-project.github.io) is the reference catalogue for
functions per binary (download, execute, AWL bypass, encode/decode).

## Data sources required

| Source | Needed for | Note |
|---|---|---|
| MDE DeviceProcessEvents / Sysmon 1 / 4688 + command line | Everything | Command line must be complete (4688 truncation, ProcessCommandLine length limits) |
| DeviceNetworkEvents / Sysmon 3 | LOLBins talking to the internet | Sysmon config must not exclude signed Microsoft binaries |
| DeviceImageLoadEvents / Sysmon 7 | rundll32/regsvr32 loading user-path DLLs | Volume-heavy; scope to these images |
| PowerShell/Operational 4104 (and 4103), Windows PowerShell 400/800 | Script content, downgrade | Enable script block logging via GPO on all hosts |
| DeviceFileEvents / Sysmon 11 | Payload drops (Downloads, Temp, ProgramData) | |
| ASR audit events (DeviceEvents `ActionType` starting `Asr`) | Office child process, script obfuscation | Audit mode gives free hunting data |

## Behaviours and queries

### 1. Signed binary proxy execution (rundll32, regsvr32, mshta and friends)

```kql
// MDE: high-signal proxy-execution argument patterns. Tune: rundll32 control-panel and printer UI usage by IT.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName =~ "rundll32.exe" and (ProcessCommandLine has_any ("javascript:", "url.dll,OpenURL", "url.dll,FileProtocolHandler", "ShellExec_RunDLL", "mshtml,RunHTMLApplication")
          or ProcessCommandLine matches regex @"(?i)\\(users|programdata|windows\\temp)\\[^,]+\.(dll|dat|png|txt|bin)\s*,"
          or ProcessCommandLine matches regex @"(?i)rundll32(\.exe)?""?\s*$"))
     or (FileName =~ "regsvr32.exe" and ProcessCommandLine has_any ("/i:http", "-i:http", "scrobj", @"\AppData\", @"\Temp\"))
     or (FileName =~ "mshta.exe" and ProcessCommandLine has_any ("http:", "https:", "javascript:", "vbscript:", @"\Downloads\", @"\Temp\"))
     or (FileName =~ "cmstp.exe" and ProcessCommandLine has "/au") or (FileName =~ "mavinject.exe" and ProcessCommandLine has "/INJECTRUNNING")
     or (FileName =~ "odbcconf.exe" and ProcessCommandLine has_any ("REGSVR", "-f ", "/f "))
     or (FileName =~ "msiexec.exe" and ProcessCommandLine has_any ("http:", "https:") and ProcessCommandLine has_any ("/q", "-q"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

SPL - same patterns on Sysmon 1; adapt `index`:

```spl
index=sysmon source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  ((Image="*\\rundll32.exe" (CommandLine="*javascript:*" OR CommandLine="*url.dll,OpenURL*" OR CommandLine="*ShellExec_RunDLL*" OR CommandLine="*\\Users\\*.dll,*" OR CommandLine="*\\ProgramData\\*,*"))
   OR (Image="*\\regsvr32.exe" (CommandLine="*/i:http*" OR CommandLine="*scrobj*"))
   OR (Image="*\\mshta.exe" (CommandLine="*http*" OR CommandLine="*javascript:*" OR CommandLine="*vbscript:*"))
   OR (Image="*\\cmstp.exe" CommandLine="*/au*") OR (Image="*\\mavinject.exe" CommandLine="*INJECTRUNNING*"))
| stats count dc(host) as hosts values(ParentImage) as parents by Image CommandLine
```

```yaml
title: Regsvr32 Or Mshta Executing Remote Or Inline Script
status: experimental
logsource: {product: windows, category: process_creation}
detection:
  regsvr32:
    Image|endswith: '\regsvr32.exe'
    CommandLine|contains: ['/i:http', '-i:http', 'scrobj.dll']
  mshta:
    Image|endswith: '\mshta.exe'
    CommandLine|contains: ['http://', 'https://', 'javascript:', 'vbscript:']
  condition: regsvr32 or mshta
falsepositives: [Legacy intranet HTA applications - allowlist by exact URL]
level: high
tags: [attack.defense_evasion, attack.t1218.010, attack.t1218.005]
```

Network view: these binaries (plus msbuild, installutil) connecting to public
IPs (DeviceNetworkEvents `RemoteIPType == "Public"`) are leads almost anywhere.

### 2. Download and decode (certutil, bitsadmin, curl, desktopimgdownldr)

```kql
// MDE: built-in binaries used as downloaders/decoders. Tune: certutil used by PKI admins for -verify/-urlfetch on CRLs.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName =~ "certutil.exe" and ProcessCommandLine has_any ("urlcache", "verifyctl", "-decode", "/decode", "decodehex", "-encode") )
     or (FileName =~ "bitsadmin.exe" and ProcessCommandLine has_any ("/transfer", "/addfile", "/download"))
     or (FileName =~ "curl.exe" and ProcessCommandLine has_any (" -o ", " --output ", " -O ") and InitiatingProcessFileName in~ ("cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe"))
     or (FileName =~ "desktopimgdownldr.exe" and ProcessCommandLine has "/lockscreenurl:")
     or (FileName =~ "esentutl.exe" and ProcessCommandLine has_all ("/y", @"\\"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
```

```spl
index=sysmon source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  ((OriginalFileName="CertUtil.exe" (CommandLine="*urlcache*" OR CommandLine="*verifyctl*" OR CommandLine="*decode*"))
   OR (Image="*\\bitsadmin.exe" (CommandLine="*/transfer*" OR CommandLine="*/addfile*"))
   OR (Image="*\\desktopimgdownldr.exe" CommandLine="*lockscreenurl*"))
| table _time host User ParentImage Image CommandLine
```

```yaml
title: Certutil Used To Download Or Decode A File
status: experimental
logsource: {product: windows, category: process_creation}
detection:
  img:
    - Image|endswith: '\certutil.exe'
    - OriginalFileName: 'CertUtil.exe'
  args:
    CommandLine|contains: ['urlcache', 'verifyctl', '-decode', '/decode', 'decodehex']
  condition: img and args
falsepositives: [PKI administrators testing CRL/AIA retrieval (usually -urlfetch -verify, not -urlcache -f)]
level: high
tags: [attack.command_and_control, attack.t1105, attack.defense_evasion, attack.t1140]
```

Match `OriginalFileName` too: renamed LOLBin copies keep their PE version info.

### 3. Trusted developer utilities (msbuild, installutil, regasm/regsvcs)

```kql
// MDE: .NET build/installer utilities run outside developer and build contexts.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe")
| where not(InitiatingProcessFileName in~ ("devenv.exe", "dotnet.exe", "msbuild.exe", "vstest.console.exe", "Agent.Worker.exe", "msiexec.exe"))
| where ProcessCommandLine has_any (@"\Users\", @"\Temp\", @"\ProgramData\", @"\Downloads\", "/U", "/logfile=", "LogToConsole=false", ".xml", ".csproj")
| summarize Count = count(), Hosts = dcount(DeviceId), Sample = any(ProcessCommandLine) by FileName, InitiatingProcessFileName
```

```spl
index=sysmon source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  Image IN ("*\\MSBuild.exe","*\\InstallUtil.exe","*\\RegAsm.exe","*\\RegSvcs.exe")
  NOT ParentImage IN ("*\\devenv.exe","*\\dotnet.exe","*\\MSBuild.exe","*\\Agent.Worker.exe")
| stats count dc(host) as hosts values(CommandLine) as cmds by Image ParentImage
```

```yaml
title: InstallUtil Or MSBuild Executing From User-Writable Path
status: experimental
logsource: {product: windows, category: process_creation}
detection:
  img:
    Image|endswith: ['\InstallUtil.exe', '\MSBuild.exe', '\RegAsm.exe', '\RegSvcs.exe']
  path:
    CommandLine|contains: ['\Users\Public\', '\AppData\', '\Temp\', '\ProgramData\', '\Downloads\']
  filter_dev:
    ParentImage|endswith: ['\devenv.exe', '\dotnet.exe']
  condition: img and path and not filter_dev
falsepositives: [Developer workstations building from user profiles - scope by host role]
level: medium
tags: [attack.defense_evasion, attack.t1127.001, attack.t1218.004, attack.t1218.009]
```

### 4. WMIC and Windows Script Host

```kql
// MDE: wmic process creation / remote XSL, and script hosts running files from download/temp/archive paths.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName =~ "wmic.exe" and (ProcessCommandLine has "process call create" or ProcessCommandLine matches regex @"(?i)/format:\s*""?(https?:|.*\.xsl)"))
     or (FileName in~ ("wscript.exe", "cscript.exe") and ProcessCommandLine matches regex @"(?i)\.(js|jse|vbs|vbe|wsf|wsh)\b"
         and ProcessCommandLine has_any (@"\Downloads\", @"\AppData\Local\Temp\", @"\Users\Public\", ".zip", "Temp1_", @"\Content.Outlook\"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
```

```spl
index=sysmon source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  ((Image="*\\wmic.exe" (CommandLine="*process call create*" OR CommandLine="*/format:*http*" OR CommandLine="*/format:*.xsl*"))
   OR (Image IN ("*\\wscript.exe","*\\cscript.exe") (CommandLine="*\\Downloads\\*" OR CommandLine="*\\Temp\\*" OR CommandLine="*.zip*")))
| stats count dc(host) as hosts by Image ParentImage CommandLine
```

```yaml
title: Windows Script Host Executing Script From Downloads Or Temp
status: experimental
logsource: {product: windows, category: process_creation}
detection:
  img:
    Image|endswith: ['\wscript.exe', '\cscript.exe']
  ext:
    CommandLine|contains: ['.js', '.jse', '.vbs', '.vbe', '.wsf']
  path:
    CommandLine|contains: ['\Downloads\', '\AppData\Local\Temp\', '\Users\Public\', '\Content.Outlook\']
  condition: img and ext and path
falsepositives: [Login scripts from NETLOGON (not in these paths), vendor installers]
level: high
tags: [attack.execution, attack.t1059.005, attack.t1059.007, attack.t1204.002]
```

### 5. PowerShell: encoded commands, cradles, downgrade, AMSI bypass

```kql
// MDE: encoded/obfuscated launches and download cradles. Decode -enc payloads with base64_decode_tostring after stripping UTF-16 nulls.
DeviceProcessEvents
| where Timestamp > ago(30d) and FileName in~ ("powershell.exe", "pwsh.exe", "powershell_ise.exe")
| extend Enc = extract(@"(?i)\s[-/]e[a-z]*\s+([A-Za-z0-9+/=]{40,})", 1, ProcessCommandLine)
| extend Decoded = iff(isnotempty(Enc), replace_regex(base64_decode_tostring(Enc), @"\x00", ""), "")   // UTF-16LE -> drop NULs
| where isnotempty(Enc) or ProcessCommandLine has_any ("DownloadString", "DownloadFile", "Net.WebClient", "IEX", "Invoke-Expression", "FromBase64String", "-version 2", "-v 2 ")
     or ProcessCommandLine matches regex @"(?i)\s-(w|wi|win|window|windowstyle)\s+h"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine, Decoded
```

```kql
// Sentinel: 4104 script blocks with AMSI-bypass and cradle markers (Event table; adapt to your parser).
Event
| where TimeGenerated > ago(30d) and Source == "Microsoft-Windows-PowerShell" and EventID == 4104
| where EventData has_any ("AmsiUtils", "amsiInitFailed", "AmsiScanBuffer", "amsiContext", "System.Management.Automation.AmsiUtils",
    "VirtualProtect", "DownloadString", "Net.WebClient", "FromBase64String", "Reflection.Assembly]::Load")
| project TimeGenerated, Computer, EventData
```

```spl
index=wineventlog source="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
  (ScriptBlockText="*AmsiUtils*" OR ScriptBlockText="*amsiInitFailed*" OR ScriptBlockText="*AmsiScanBuffer*" OR ScriptBlockText="*DownloadString*" OR ScriptBlockText="*FromBase64String*")
| stats count dc(host) as hosts values(Path) as paths by ScriptBlockText
| sort hosts
```

```yaml
title: PowerShell Script Block Containing AMSI Bypass Markers
status: experimental
logsource: {product: windows, category: ps_script}
detection:
  selection:
    ScriptBlockText|contains: ['AmsiUtils', 'amsiInitFailed', 'AmsiScanBuffer', 'amsiContext']
  condition: selection
falsepositives: [Security research/red-team tooling on approved hosts; AV vendor test scripts]
level: high
tags: [attack.defense_evasion, attack.t1562.001, attack.execution, attack.t1059.001]
```

Obfuscators split these strings (`'Am'+'si'`); also stack 4104 by punctuation
and concatenation ratio. PowerShell auto-logs suspicious blocks at Warning level
even without full script-block logging. Downgrades show in Windows PowerShell
log 400 with `EngineVersion=2.0`; remove the 2.0 feature where present.

### 6. Office applications spawning shells and script hosts

```kql
// MDE: Office as parent of shells/LOLBins. ASR rule "Block all Office applications from creating child processes" (d4f940ab-401b-4efc-aadc-ad5f3c50688a; verify GUID) in audit mode gives the same view.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "mspub.exe", "msaccess.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
    "certutil.exe", "bitsadmin.exe", "msbuild.exe", "schtasks.exe", "wmic.exe", "curl.exe")
| summarize Count = count(), Hosts = dcount(DeviceId), Sample = any(ProcessCommandLine) by InitiatingProcessFileName, FileName
```

```spl
index=sysmon source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  ParentImage IN ("*\\WINWORD.EXE","*\\EXCEL.EXE","*\\POWERPNT.EXE","*\\OUTLOOK.EXE","*\\ONENOTE.EXE","*\\MSPUB.EXE")
  Image IN ("*\\cmd.exe","*\\powershell.exe","*\\wscript.exe","*\\cscript.exe","*\\mshta.exe","*\\rundll32.exe","*\\regsvr32.exe","*\\certutil.exe")
| table _time host User ParentImage Image CommandLine
```

```yaml
title: Office Application Spawning Shell Or LOLBin
status: experimental
logsource: {product: windows, category: process_creation}
detection:
  parent:
    ParentImage|endswith: ['\WINWORD.EXE', '\EXCEL.EXE', '\POWERPNT.EXE', '\OUTLOOK.EXE', '\ONENOTE.EXE', '\MSPUB.EXE', '\MSACCESS.EXE']
  child:
    Image|endswith: ['\cmd.exe', '\powershell.exe', '\pwsh.exe', '\wscript.exe', '\cscript.exe', '\mshta.exe', '\rundll32.exe', '\regsvr32.exe', '\certutil.exe', '\bitsadmin.exe']
  condition: parent and child
falsepositives: [Line-of-business macros and add-ins that shell out - allowlist by document path/macro owner]
level: high
tags: [attack.execution, attack.t1204.002, attack.initial_access, attack.t1566.001]
```

### 7. Parent-child baselines and command-line length/entropy stacking

```kql
// MDE: rare parent->child pairs for LOLBins across the fleet (least-frequency). Baseline 30d, review pairs on <= 3 devices.
let LOL = dynamic(["rundll32.exe","regsvr32.exe","mshta.exe","certutil.exe","bitsadmin.exe","msbuild.exe","installutil.exe","wmic.exe",
  "cscript.exe","wscript.exe","powershell.exe","pwsh.exe","cmstp.exe","odbcconf.exe","msiexec.exe","forfiles.exe","pcalua.exe","hh.exe"]);
DeviceProcessEvents
| where Timestamp > ago(30d) and FileName in~ (LOL)
| summarize Devices = dcount(DeviceId), Execs = count(), First = min(Timestamp), Sample = any(ProcessCommandLine)
    by Parent = tolower(InitiatingProcessFileName), Child = tolower(FileName)
| where Devices <= 3
| order by Devices asc, Execs asc
```

```kql
// MDE: Shannon entropy + length of LOLBin command lines; review top outliers. CPU-heavy - restrict scope/time first.
DeviceProcessEvents
| where Timestamp > ago(7d) and FileName in~ ("powershell.exe", "cmd.exe", "rundll32.exe", "mshta.exe", "wscript.exe")
| extend L = strlen(ProcessCommandLine)
| where L > 200
| mv-apply ch = extract_all(@"(.)", ProcessCommandLine) to typeof(string) on (
    summarize n = count() by ch, L
    | summarize Entropy = -sum(todouble(n) / L * log2(todouble(n) / L)))
| summarize Count = count(), Hosts = dcount(DeviceId) by FileName, L, Entropy = round(Entropy, 2), ProcessCommandLine
| where Entropy > 5.0 or L > 1000      // starting thresholds; calibrate against your own distribution
| order by Entropy desc
```

SPL - rare pairs, then entropy with the URL Toolbox app (`ut_shannon` macro; install and verify first):

```spl
index=sysmon source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-30d
| eval parent=lower(mvindex(split(ParentImage,"\\"),-1)), child=lower(mvindex(split(Image,"\\"),-1))
| stats dc(host) as hosts count by parent child
| where hosts<=3
```

```spl
index=sysmon source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image IN ("*\\powershell.exe","*\\cmd.exe","*\\rundll32.exe") earliest=-7d
| eval len=len(CommandLine)
| where len>200
| `ut_shannon(CommandLine)`
| stats count dc(host) as hosts by Image len ut_shannon CommandLine
| sort - ut_shannon
```

Base64 sits near 6 bits/char; long, high-entropy command lines on few hosts are
leads, but installers and agents produce them too - stack by parent first.

## Baselining and stacking

- **Keys:** (parent, child), (child, normalised command line), (child, signer,
  path), (child, remote destination). Normalise user names, GUIDs, temp
  names and digits before counting.
- **Tail:** pairs on <= 3 hosts, first seen in window, LOLBins in unusual
  directories (copied/renamed: path not System32/SysWOW64 or name differs from
  OriginalFileName), LOLBins with external network connections.
- **Role-aware:** baseline servers, workstations and developer machines
  separately; msbuild on a dev box is normal, on a finance laptop it is not.

## False positives & benign look-alikes

| Look-alike | Resembles | How to tell |
|---|---|---|
| SCCM/Intune scripts, RMM tools | Encoded PowerShell, hidden windows | Parent is the agent (CcmExec, IME), signed script, fleet-wide |
| Software installers | rundll32/msiexec/regsvr32 with odd DLLs | Parent msiexec / setup.exe, Program Files targets, vendor signer |
| Control panel applets, printer UI | rundll32 shell32/printui | Known exports (`Control_RunDLL`, `PrintUIEntry`) with system paths |
| PKI admins | certutil | `-verify`, `-urlfetch`, `-dump` on CRLs/certs, PKI hosts |
| Developers and build agents | msbuild, installutil, regasm | Dev/build hosts, devenv/dotnet/agent parents |
| LOB Office macros | Office spawning cmd | Same document, same users, documented owner |
| Security tools and AV tests | AMSI test strings | Security team hosts, test harness paths |

## Pitfalls

- Matching on `Image` only: renamed binaries; add `OriginalFileName`.
- Truncated command lines (4688 limits, SIEM field limits) hide payloads; check
  maximum field length in your pipeline.
- Filtering out everything signed by Microsoft (a common Sysmon config
  shortcut) blinds exactly this hunt.
- Decoding `-enc` as UTF-8: PowerShell encodes UTF-16LE.
- Treating 4104 absence as clean when script block logging is not enabled on
  every host, or when PowerShell 2.0 (no 4104) is still installed.

## Escalation criteria

- Any LOLBin pattern from sections 1-6 with an external download, a payload
  written to a user path, or a follow-on process/network connection.
- Office or a browser spawning a script host/LOLBin on a host where that pair
  has no baseline.
- AMSI bypass markers outside approved security-testing hosts.
- The same rare command line on multiple hosts in a short window (spread).

| Verdict | Evidence that moves it |
|---|---|
| True Positive | Decoded content malicious, or payload/C2 retrieved, or persistence follows |
| Benign True Positive | Owner, signed script, change record, fleet-wide consistent usage |
| False Positive | Pattern matched a benign export/argument; refine query |
| Needs more data | Command line truncated, script content not logged; collect via live response |

## Output

```markdown
## Hunt report - LOLBins - <HUNT-ID>
- Hypothesis / status: <supported | refuted | inconclusive>
- Scope & window: <hosts/roles>, <UTC range>; command-line coverage <n>%, 4104 coverage <n>%
- Binaries/behaviours covered: <list> (ATT&CK IDs)
- Stacks reviewed: <n> parent-child pairs, <n> rare; entropy outliers <n>
- Findings: | Time (UTC) | Host | User | Parent > Child | Command line (decoded) | Next action | Verdict |
- Legitimate LOLBin usage (input to WDAC/ASR): | Binary | Who/where | Why |
- Detections proposed: <titles>; ASR/WDAC candidates with impact estimate
```

Hand-offs: confirmed execution to `incident-response`, payloads to
`malware-triage`, delivery to `phishing-analysis`, persistence follow-up to
`hunt-windows-persistence`, C2 to `hunt-c2-beaconing`, detections to
`detection-engineering` / `sigma-rules`, blocking rules to `hardening-windows-ad`.

## References

- MITRE ATT&CK T1218 (and sub-techniques), T1127.001, T1059.001/.005/.007,
  T1105, T1140, T1197, T1220, T1562.001: https://attack.mitre.org/techniques/T1218/
- LOLBAS project: https://lolbas-project.github.io/
- Microsoft Learn: Attack surface reduction rules reference.
- Microsoft Learn: about_Logging_Windows (PowerShell script block logging).
- Microsoft Learn: Advanced hunting schema - DeviceProcessEvents.
- Splunk URL Toolbox app documentation (ut_shannon).
