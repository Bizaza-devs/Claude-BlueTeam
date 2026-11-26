---
description: "Artifact-driven forensic triage of a Windows or Linux host, disk image, triage collection (KAPE/Velociraptor/UAC) or memory image, with chain of custody. Usage: /forensics <path-to-image|collection|memory.raw> | /forensics host <name> [--os windows|linux] [--question \"<what to answer>\"] [--case <case-folder>]"
argument-hint: "<image|collection|memory dump> | host <name> [--os windows|linux] [--question \"...\"] [--case <case-folder>]"
---

# /forensics

Answer specific questions from artefacts: was this host compromised, how did the
attacker get in, what ran, what persisted, what left. Questions first, artefacts
second: a forensics run without a question becomes an unbounded dig.

Input: `$ARGUMENTS`

## Usage

```
/forensics evidence/WS-0142_kape_triage.zip --question "What executed between 08:00 and 10:00 UTC?"
/forensics evidence/WS-0142.mem --os windows --case cases/2026-11-25-ws0142-lsass
/forensics host web-02 --os linux --question "Is there persistence after the webshell?"
```

## Skills to load

- Always: `evidence-handling`, `timeline-analysis`
- Windows: `windows-forensics`; Linux: `linux-forensics`; memory images: `memory-forensics`
- Suspicious binaries/scripts: `malware-triage`, `yara-rules`
- Persistence context: `hunt-windows-persistence`, `hunt-linux-persistence`, `hunt-webshells`

## Evidence gate (before any analysis)

- Every evidence item has: **item ID, SHA256, acquisition time (UTC), who acquired it,
  method/tool, source host, storage location** recorded in `evidence-log.csv`.
  No hash, no analysis.
- Work on a **copy**, never the original. Verify the copy's hash matches.
- Findings cite the artefact (file path inside the image, record number, offset) so
  another analyst can reproduce them.

## Procedure

1. **Questions.** Write 1-5 investigative questions with the incident commander
   (e.g. initial access vector, first execution, lateral movement source, data accessed).
2. **Intake.** Hash the item (`Get-FileHash -Algorithm SHA256` / `sha256sum`), record
   it in `evidence-log.csv`, mount or extract read-only.
3. **Live host requested?** Do not log in interactively to explore. Propose a collection
   (Velociraptor / KAPE / UAC / EDR live response) in order of volatility: memory,
   network connections and processes, then disk artefacts. Collection on a production
   host is an action: get approval and log it in `actions.md`.
4. **Artefact plan** by question:

   | Question | Windows artefacts | Linux artefacts |
   |---|---|---|
   | What executed? | Prefetch, Amcache.hve, ShimCache (AppCompatCache), BAM/DAM, 4688 / Sysmon 1, SRUM | shell histories, auditd `execve`, journal, `/proc` (live), package logs |
   | Persistence? | Run/RunOnce keys, services (7045), scheduled tasks (4698, `\Windows\System32\Tasks`), WMI subscriptions, startup folders | cron, systemd units/timers, `~/.ssh/authorized_keys`, rc files, `/etc/ld.so.preload`, PAM modules |
   | Logons / lateral movement? | 4624/4625/4648/4672, RDP 1149 & 21/24/25 (TerminalServices logs), UAL on servers | `auth.log`/`secure`, `wtmp`/`btmp`/`lastlog`, SSH logs |
   | Files touched? | $MFT, $UsnJrnl:$J, LNK files, Jump Lists, ShellBags, RecentDocs | inode times, `find -newermt`, editor/viminfo, tmp dirs |
   | Network? | SRUM network usage, DNS cache (live), firewall logs, browser history | `ss`/`netstat` (live), `/etc/hosts`, iptables/nft logs, web server logs |
   | Memory | processes, injected code, network sockets, command lines (`memory-forensics`, Volatility 3) | same, plus kernel module listing |

5. **Parse** with established tools (e.g. EZ Tools / Eric Zimmerman's parsers, Volatility 3,
   Plaso/log2timeline, Hayabusa/Chainsaw for EVTX). Record tool name and version.
6. **Correlate** into the case timeline (`/timeline`), adjusting for time zones and clock skew.
7. **Answer each question** with evidence and confidence; list what could not be
   answered and why (artefact missing, retention, anti-forensics such as log clearing 1102/104).
8. **Extract IOCs** (defanged) and hand persistence findings to eradication.

## Output format

```markdown
## Forensic triage: <host / item ID>    analyst <name>    <UTC date>
### Evidence
| item_id | description | sha256 (verified) | acquired_utc | method |
### Questions and answers
| # | Question | Answer | Confidence | Key artefacts (path / record) |
### Findings timeline (UTC)
| timestamp_utc | artefact | event | detail |
### Persistence found (for eradication)
### Indicators (defanged)
### Limits: missing artefacts, time-zone assumptions, tool caveats
```

## Case integration

Append each acquired or derived item to `evidence-log.csv`
(`item_id,description,source_host,acquired_utc,acquired_by,method,sha256,storage_location,notes`),
findings to `timeline.csv` (`timestamp_utc,host,source,event,detail,analyst,confidence`;
`source` = artefact name such as `Prefetch` or `4624`), indicators to `iocs.csv`.

## Gates and safety

- Never power off, reboot or reimage a host from this command. Live collection on a
  production system requires approval recorded in `actions.md`.
- Malware samples: analysis only, in an isolated VM without network (or with a
  simulated network); store samples password-protected; never execute on the analyst host.
- Keep personal data found in images need-to-know; note it for the privacy owner.
