---
description: "Hypothesis-driven threat hunt routed through hunt-dispatch: hypothesis, data check, queries, findings, and a detection or hardening hand-off. Usage: /hunt \"<hypothesis>\" | /hunt <ATT&CK ID> | /hunt <topic> [--platform kql|spl|esql|eql] [--window 30d] [--scope <hosts|OU|account>] [--case <case-folder>]"
argument-hint: "\"<hypothesis>\" | <T####[.###]> | <topic> [--platform kql|spl|esql|eql] [--window 30d] [--scope <...>] [--case <...>]"
---

# /hunt

A hunt starts from a testable hypothesis and ends with one of three outcomes:
evidence of attacker activity (-> incident), a clean result with a coverage
statement, or a gap (-> telemetry or detection work). Every hunt leaves something
behind: a detection, a tuning note, or a logging request.

Input: `$ARGUMENTS`

## Usage

```
/hunt "An attacker is using scheduled tasks for persistence on finance servers" --platform kql
/hunt T1021.002 --window 14d
/hunt beaconing --platform spl --scope "DMZ hosts"
/hunt webshells --case cases/2026-11-25-iis-webshell
/hunt "Stolen IdP session used from new ASN" --platform kql
```

## Routing

Load `hunt-dispatch` first. It turns the input into a hypothesis and selects the
domain skill(s):

| Topic / technique family | Skill |
|---|---|
| Run keys, services, tasks, WMI subscriptions (T1547, T1543, T1053, T1546.003) | `hunt-windows-persistence` |
| PsExec/SMB, WinRM, RDP, WMI, DCOM (T1021, T1047, T1569.002) | `hunt-lateral-movement` |
| LSASS, SAM, DCSync, Kerberoasting, AS-REP roasting (T1003, T1558) | `hunt-credential-access` |
| AD abuse, ADCS, delegation, GPO changes | `hunt-ad-identity-attacks` |
| Signed-binary proxy execution (T1218, T1059) | `hunt-lolbins` |
| Periodic outbound, DNS tunnelling (T1071, T1572, T1568) | `hunt-c2-beaconing` |
| Large or unusual egress, cloud storage uploads (T1041, T1567) | `hunt-exfiltration` |
| cron, systemd, SSH keys, LD_PRELOAD (T1053.003, T1543.002, T1098.004) | `hunt-linux-persistence` |
| Web server spawning shells, new scripts in web roots (T1505.003) | `hunt-webshells` |
| CloudTrail / Azure Activity / Entra audit abuse | `hunt-cloud-control-plane` |
| Container escapes, exec into pods, privileged pods | `hunt-k8s-runtime` |

Also load the query skill for `--platform`: `kql-sentinel-defender`, `spl-splunk`,
`elastic-eql-esql`. Indicator-driven hunts add `threat-intel-ioc`.

## Evidence gate

- A hunt is not "clean" until you list the data sources queried, their time range and
  retention, and the host/account coverage (e.g. "EDR on 94% of servers; 6 hosts without it").
- A hit is not a finding until triaged with the `/triage` evidence gate (second source,
  benign causes ruled out).

## Procedure

1. **Hypothesis.** Write it as: *actor behaviour* + *where* + *observable*. Map to ATT&CK.
   Note the source (intel report, incident lesson, coverage gap, red team finding).
2. **Data check.** Which tables/indices hold the observable? Is the field populated
   (run a count first)? If the data is missing, stop and record a logging gap (`logging-coverage`).
3. **Baseline query.** Wide and aggregated first (stack counts by parent/child, by
   destination, by account), not a needle search. Long tail = candidates.
4. **Narrow.** Exclude known-good with a documented allowlist (who approved each entry).
   Every query is labelled with its platform and has a comment on what to tune.
5. **Investigate candidates** with the `/triage` gate. Promote real hits to `/investigate` or `/ir`.
6. **Conclude** with one of: Confirmed activity / Suspicious, needs follow-up / Not found
   (with coverage) / Could not test (data gap).
7. **Leave something behind:** convert the best-performing query into a detection
   (`/detect`), file a logging request, or a hardening item (`/harden`).

## Output format

```markdown
## Hunt: <short name>    (<YYYY-MM-DD>, analyst <name>)
**Hypothesis:** ...
**ATT&CK:** T1053.005 (Scheduled Task)    **Window (UTC):** ...    **Scope:** ...
**Outcome:** <Confirmed | Suspicious | Not found | Could not test>

### Data sources and coverage
| Source | Table / index | Fields used | Retention | Coverage |
|---|---|---|---|---|

### Queries run
<labelled code blocks, each with a one-line comment: what it finds, what to tune>

### Results
| Candidate | Why it stood out | Verdict | Evidence |
|---|---|---|---|

### Allowlist decisions (entry, reason, approved by)
### Follow-ups: detections / logging gaps / hardening / incidents opened
```

## Case integration

If run inside a case (`--case` or active from `/ir`): confirmed hits go to
`timeline.csv` (`timestamp_utc,host,source,event,detail,analyst,confidence`), new
indicators to `iocs.csv` defanged, and the hunt report into `notes.md`. Hunts outside
a case can be saved where the user chooses; suggest a hunt log file.

## Gates and safety

- Hunting is read-only. Containment ideas go to `/contain`.
- Heavy queries on production SIEMs: estimate cost/time first, prefer summarised tables
  and shorter windows, and avoid running unbounded searches during peak hours.
- If a hit suggests an active intrusion, stop hunting and escalate (`/ir`); speed matters more than completeness.
