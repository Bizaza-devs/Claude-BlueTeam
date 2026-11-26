---
description: "Build or update an incident timeline / super-timeline in UTC from logs, EDR, forensic artefacts and analyst notes; normalise, de-duplicate, mark gaps and phases. Usage: /timeline build [--case <case-folder>] | /timeline add \"<UTC> <host> <event>\" | /timeline import <csv|jsonl|plaso> | /timeline review"
argument-hint: "build | add \"<UTC> <host> <event>\" | import <file> | review [--case <case-folder>]"
---

# /timeline

The timeline is the spine of an incident: every finding hangs on it, every report
quotes it. This command keeps `timeline.csv` in the case folder clean, UTC-only, and
explainable.

Input: `$ARGUMENTS`

## Usage

```
/timeline build --case cases/2026-11-25-ws0142-lsass
/timeline add "2026-11-25T09:11:47Z WS-0142 RDP logon from 198.51.100.23 as j.doe"
/timeline import evidence/derived/WS-0142_plaso.csv
/timeline review          # gaps, contradictions, phase markers, confidence
```

## Skills to load

- Always: `timeline-analysis`, `evidence-handling`
- Source-specific parsing: `windows-forensics`, `linux-forensics`, `memory-forensics`
- Log queries to fill gaps: `kql-sentinel-defender`, `spl-splunk`, `elastic-eql-esql`
- Cloud control plane: `hunt-cloud-control-plane`, `ir-cloud-aws`, `ir-azure-entra`

## Format (fixed)

`timeline.csv` header, exactly:

```csv
timestamp_utc,host,source,event,detail,analyst,confidence
2026-11-25T09:11:47Z,WS-0142,Security 4624,RDP logon (type 10),"j.doe from 198.51.100[.]23",analyst1,high
```

- `timestamp_utc`: ISO 8601 with `Z`, seconds precision (keep milliseconds if the source has them).
- `host`: hostname, or the cloud account/tenant/resource for control-plane events.
- `source`: log or artefact (`Sysmon 1`, `Prefetch`, `CloudTrail CreateAccessKey`, `analyst note`).
- `detail`: quoted when it contains commas; indicators defanged.
- `confidence`: `high` (direct artefact), `medium` (inferred from one source), `low` (hypothesis).

## Evidence gate

- Each row traces to a source someone else can re-check. Analyst inferences are
  allowed only as `source = analyst note` with `confidence = low|medium`.
- Every time conversion states the original time zone / offset. Known clock skew is
  noted in `notes.md` and corrected consistently, never row by row silently.

## Procedure - build

1. **Collect sources**: case `notes.md`, triage/investigation outputs, `iocs.csv`
   first/last seen, forensic parser output, SIEM query results, `actions.md` (response actions).
2. **Normalise time.** Convert to UTC. Watch for: Windows event XML `SystemTime` (UTC)
   vs rendered local time; Linux syslog without year or zone; Prefetch/Amcache
   semantics (last run vs first run vs key write time); `$SI` vs `$FN` timestamps
   (timestomping, T1070.006); cloud logs already UTC.
3. **Normalise hosts and users** (FQDN vs short name, UPN vs SAM account).
4. **De-duplicate** the same event reported by several tools; keep the most precise
   source and mention the others in `detail`.
5. **Sort** and mark phase boundaries with `analyst note` rows: initial access,
   execution, persistence, privilege escalation, lateral movement, collection/exfil,
   impact, detection, containment.
6. **Gaps.** Identify periods without data for scoped hosts (log rollover, missing
   agent, cleared logs 1102/104) and list them; gaps are findings.

## Procedure - import

Map the input columns to the fixed header. For super-timelines (Plaso/log2timeline,
Hayabusa, Chainsaw output), filter to the investigation window and relevant hosts
first, keep the full output as an evidence-derived file (logged in `evidence-log.csv`
with SHA256), and only bring the meaningful rows into `timeline.csv`.

```bash
# Plaso example: filtered CSV export for a window (adjust storage file and window)
psort.py -o dynamic -w WS-0142_window.csv WS-0142.plaso "date > '2026-11-25 08:00:00' AND date < '2026-11-25 11:00:00'"
```

## Procedure - review

Print: total rows, rows per host, earliest/latest, phase markers present/missing,
low-confidence rows that need corroboration, contradictions (effect before cause,
action logged before approval), and gaps.

## Output format

```markdown
## Timeline summary: <case>    rows: N    window: <first> -> <last> (UTC)
### Key events (10-25 rows, chronological)
| timestamp_utc | host | event | source | confidence |
### Phases (ATT&CK tactics) with first/last time
### Gaps and contradictions
### Dwell time: initial access -> detection = <duration> (or "unknown: initial access not established")
```

## Gates and safety

- `add` and `import` only append. Corrections are new rows with `analyst note`
  explaining the fix, plus a note in `notes.md` - never rewrite history silently.
- `build` may sort and de-duplicate, but first copies the current file to
  `timeline.csv.bak-<YYYYMMDDTHHMMSSZ>` in the case folder and logs the rebuild in `notes.md`.
- Timelines contain sensitive data: do not paste them into external tools without approval and TLP check.
