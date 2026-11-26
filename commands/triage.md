---
description: "Fast verdict on one alert: True Positive, Benign True Positive, False Positive, Needs more data, or Escalate, with the evidence behind it. Usage: /triage <alert text | alert ID | pasted JSON> [--case <case-folder>]"
argument-hint: "<alert text | alert ID | pasted JSON> [--case <case-folder>]"
---

# /triage

One alert in, one defensible verdict out, in minutes rather than hours. `/triage`
answers "is this real, and does someone need to act now?". It does not run the
whole investigation: that is `/investigate` (entity deep-dive) or `/ir` (declared
incident).

Input: `$ARGUMENTS`

## Usage

```
/triage <paste the alert JSON or text>
/triage "Defender: Suspicious LSASS access on WS-0142 by procdump64.exe"
/triage SentinelIncident 4821 --case cases/2026-11-25-ws0142-lsass
```

If `$ARGUMENTS` is empty, ask for the alert body (raw JSON preferred over a
summary; the raw fields carry the evidence).

## Skills to load

- Always: `alert-triage`, `defender-mindset`
- Query language for the alert's source: `kql-sentinel-defender`, `spl-splunk` or `elastic-eql-esql`
- By alert family: `phishing-analysis` (email), `hunt-credential-access` (LSASS, Kerberos),
  `hunt-lateral-movement` (remote exec, RDP, SMB), `hunt-lolbins` (signed binary abuse),
  `hunt-c2-beaconing` (periodic outbound), `hunt-ad-identity-attacks` / `ir-azure-entra` (sign-in risk),
  `hunt-cloud-control-plane` (CloudTrail / Azure Activity), `hunt-webshells` (web server child processes)
- Indicators present: `threat-intel-ioc`

## Evidence gate

- No True Positive verdict on a single alert without a **second, independent source**
  (another log source, an EDR process tree, an authentication record, a user confirmation).
- No False Positive verdict without naming the **specific benign cause** (the admin
  script, the scanner, the change ticket) and where you verified it.
- If the gate cannot be met with the data available, the verdict is **Needs more data**,
  with the exact query or person that would settle it. Never guess to close an alert.

## Procedure

1. **Parse the alert.** Extract: rule name, source product, alert time (convert to UTC,
   ISO 8601 with `Z`), host, user, process + command line + parent, network peers,
   hashes, mapped ATT&CK technique. Note fields that are missing.
2. **Restate the hypothesis** the rule encodes in one sentence ("procdump read LSASS
   memory, consistent with T1003.001").
3. **Context first.** Asset criticality, user role, is this host/user on an allowlist,
   change window, known pentest or purple exercise (`actions.md` of any open case).
4. **Corroborate.** Pull the +/- 15 minutes around the alert on the same host and user:
   process tree, logons (4624/4625/4648/4672), network connections, file writes.
   Write each query with its platform label and note what needs local tuning.
5. **Check prevalence.** How many hosts/users show the same hash, command line or
   destination in the last 30 days? Rare + privileged + new = escalate faster.
6. **Enrich indicators** (hash, IP, domain) via `threat-intel-ioc` passively. Never browse
   to an indicator from an analyst workstation; defang everything you write down.
7. **Decide** using the table below. One verdict, one confidence (High / Medium / Low).
8. **Route.** TP -> `/investigate` or `/ir`; scoping needed -> `/hunt`; noisy rule ->
   tuning note for `/detect`.
9. **Record.** If a case is active, append to its `timeline.csv` and `iocs.csv` (see below).

## Decision table

| Verdict | Evidence that supports it | Next |
|---|---|---|
| True Positive | Malicious behaviour confirmed by >= 2 independent sources | `/ir` or `/investigate`; consider `/contain` |
| Benign True Positive | Behaviour is real and matches the rule, but authorised (ticket, admin, scanner, pentest) | Close; propose tuning/allowlist with owner |
| False Positive | Rule logic matched something that is not the behaviour (parsing error, wrong field, benign look-alike) | Close; tuning ticket via `/detect` |
| Needs more data | Gate not met; data source missing or retention expired | List the exact query / owner to ask; set a re-check time |
| Escalate | Any of: domain admin / Tier 0 asset, active data movement, ransomware precursors, multiple hosts | Page on-call / incident commander now; then `/ir` |

## Output format

```markdown
## Triage: <rule name> - <host or user>
**Verdict:** <TP | BTP | FP | Needs more data | Escalate>    **Confidence:** <High|Medium|Low>
**Alert time (UTC):** 2026-11-25T09:14:03Z    **Source:** <product / rule ID>
**ATT&CK:** T1003.001 (OS Credential Dumping: LSASS Memory)

### What happened (2-3 sentences, facts only)
### Evidence
| # | Source | Observation | Supports |
|---|---|---|---|
| 1 | Defender DeviceProcessEvents | procdump64.exe -ma lsass.exe, parent cmd.exe | TP |
| 2 | Security 4624 | Type 10 logon from 198.51.100.23 at 09:11:47Z | TP |

### Indicators (defanged)
### Benign explanations considered and why rejected / accepted
### Gaps (what would change the verdict)
### Recommended next step
```

## Case integration

When `--case` is given or a case was opened earlier in the session (`/ir`):

- Append one row per significant event to `timeline.csv`:
  `timestamp_utc,host,source,event,detail,analyst,confidence`
- Append indicators to `iocs.csv` (defanged):
  `type,value_defanged,first_seen_utc,last_seen_utc,source,confidence,tlp,notes`
- Add a short triage entry to `notes.md`. Do not edit or reorder existing rows.

## Gates and safety

- Triage is read-only. No containment, no account changes, no blocking from `/triage`:
  hand off to `/contain`, which requires explicit approval.
- Do not detonate, open or fetch attachments or URLs from the alert. Use `/phish` for email.
- All timestamps UTC. State the original time zone if the source was local time.
