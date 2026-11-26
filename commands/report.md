---
description: "Write the incident report from the case folder: executive summary for leadership plus technical report (timeline, scope, root cause, IOCs, actions, recommendations), every claim traceable to case evidence. Usage: /report [--case <case-folder>] [--audience exec|technical|both] [--draft|--final]"
argument-hint: "[--case <case-folder>] [--audience exec|technical|both] [--draft|--final]"
---

# /report

Turns the case folder into `report.md`: a one-page executive summary and a technical
report another responder could verify. The report states what is known, how it is
known, and what is still unknown.

Input: `$ARGUMENTS`

## Usage

```
/report --case cases/2026-11-25-ws0142-lsass --audience both --draft
/report --audience exec            # active case, executive summary only
/report --final                    # after IC review; locks version and date
```

No case folder: ask for one, or for the facts in writing; do not reconstruct an
incident from memory of the conversation alone.

## Skills to load

- Always: `ir-report-writing`
- Inputs: `timeline-analysis` (timeline quality), `threat-intel-ioc` (IOC appendix),
  `evidence-handling` (evidence appendix)
- Scenario specifics: `ir-ransomware`, `ir-bec-m365`, `ir-cloud-aws`, `ir-azure-entra`, `ir-insider-threat`

## Evidence gate

- Every factual statement maps to a `timeline.csv` row, an `evidence-log.csv` item,
  an `actions.md` entry, or a named source. Use footnote-style references
  (`[T14]` timeline row, `[E3]` evidence item, `[A2]` action).
- Distinguish **confirmed**, **likely** and **unknown**. Root cause and initial access
  are stated as unknown when not established - no plausible-sounding guesses.
- Numbers (hosts, users, records, durations) come from the case files, with the query
  or source that produced them.

## Procedure

1. **Read the case**: `notes.md`, `timeline.csv`, `iocs.csv`, `evidence-log.csv`, `actions.md`.
2. **Consistency check** before writing: timeline vs actions (no action before its
   approval), IOC first/last seen vs timeline, evidence items without SHA256, open
   questions still open. List problems to the user first.
3. **Draft the technical report**, then derive the executive summary from it (never the reverse).
4. **Sensitivity pass**: remove credentials and secrets, minimise personal data, defang
   indicators, set TLP and distribution list.
5. Write to the case `report.md` with a version line; keep previous versions
   (`report.v1.md`) when revising after review.

## Report template

```markdown
# Incident report: <case ID> - <short title>
Version: <draft 0.x | final 1.0>    Date (UTC): <date>    TLP: <AMBER>    Distribution: <names/roles>
Author: <name>    Reviewed by (IC): <name>

## 1. Executive summary   (max one page, no jargon)
- What happened, in two sentences.
- Impact: systems, data, people, business operations; regulatory relevance flagged for legal.
- Current status: contained / eradicated / recovered; residual risk.
- Key decisions needed from leadership.
- Top 3-5 recommendations with owners.

## 2. Incident overview
| Field | Value |
|---|---|
| Detection source / time (UTC) | |
| Declared / contained / closed (UTC) | |
| Dwell time | |
| Severity | |
| Incident type | |
| ATT&CK techniques observed | |

## 3. Timeline (key events, UTC)          [from timeline.csv]
## 4. Scope: affected hosts, accounts, data (confirmed / suspected / ruled out, with method)
## 5. Attack narrative by phase (initial access -> impact), with references
## 6. Root cause and contributing factors (or "not established" + why)
## 7. Response actions                       [from actions.md: action, time, approver, result]
## 8. Evidence summary                       [from evidence-log.csv: item, hash, custody]
## 9. Indicators of compromise (defanged)    [from iocs.csv]
## 10. Recommendations
| # | Recommendation | Addresses | Priority | Owner | Due |
## 11. Open questions and limitations
## Appendix: detection rules created, queries used, glossary
```

## Executive summary rules

- Business language; translate techniques into effects ("the attacker obtained a
  password that let them sign in to the finance file server").
- Lead with impact and status, then actions and asks.
- No blame of individuals. Avoid absolute claims ("no data was taken") unless the
  evidence supports them; say "no evidence of exfiltration was found in <sources>, which
  cover <period>".

## Technical section rules

- Times in UTC everywhere; local time only in brackets where it helps readers.
- Each ATT&CK technique listed in section 2 appears in the narrative with evidence.
- Queries and detection logic in the appendix are labelled with their platform.
- IOCs are defanged and carry confidence and TLP from `iocs.csv`.

## Gates and safety

- `--final` only after the incident commander has reviewed the draft; record reviewer and date.
- Regulatory, customer, insurer or law-enforcement notifications are decided by legal
  / privacy owners. The report flags them; it does not make them.
- Do not send or publish the report from this command; produce the file and let the
  user distribute it.
- Follow-up: `/postmortem` for the blameless review and action tracking.
