---
description: "Blameless post-incident review: what happened, what went well, what was hard, contributing factors across detection, response, people and process, and owned, dated actions. Usage: /postmortem [--case <case-folder>] [--facilitate] [--out <file>]"
argument-hint: "[--case <case-folder>] [--facilitate] [--out <file>]"
---

# /postmortem

Learn from the incident without blaming people. The output is a short review
document and a list of improvements with owners and dates, each one traceable to
something that happened in the case.

Input: `$ARGUMENTS`

## Usage

```
/postmortem --case cases/2026-11-25-ws0142-lsass
/postmortem --facilitate        # produce the meeting agenda and questions first
/postmortem --out docs/reviews/2026-11-ws0142.md
```

Default output: `postmortem.md` in the case folder (it is not one of the scaffolded
files; create it there).

## Skills to load

- Always: `post-incident-review`
- Inputs and measurement: `ir-report-writing`, `timeline-analysis`
- Turning lessons into work: `detection-engineering`, `logging-coverage`, `vuln-prioritization`,
  and the relevant `hardening-*` skill

## Evidence gate

- Every "what went wrong" item points to a timeline row, action or note in the case,
  not to someone's recollection alone. Recollections are welcome as context, labelled as such.
- Metrics (time to detect, time to contain) are computed from `timeline.csv` /
  `actions.md` timestamps, with the rows used.

## Blameless rules

- Describe decisions in the context the person had at the time (information,
  time pressure, tools). Ask "what made this the reasonable choice then?"
- No names attached to mistakes in the document; use roles. Names appear only as
  action owners.
- "Human error" is never a root cause; look for the condition that made the error
  likely (missing alert, confusing runbook, no access, alert fatigue).

## Procedure

1. **Read the case**: `report.md`, `timeline.csv`, `actions.md`, `notes.md` decisions log.
2. **Compute metrics** (state the start/end rows for each):

   | Metric | From -> To |
   |---|---|
   | Dwell time | First attacker activity -> first detection |
   | Time to triage | Alert -> analyst verdict |
   | Time to declare | Verdict -> incident declared |
   | Time to contain | Declared -> last containment action verified |
   | Time to recover | Declared -> business owner sign-off |

3. **Facilitate** (`--facilitate`): agenda (timeline walk-through, then the questions
   below), attendee roles, a reminder of the blameless rules.
4. **Analyse** by area: detection (did a rule fire? when? was it triaged correctly?),
   response (approvals, communication, tooling, access), prevention (which control would
   have stopped or slowed it), recovery, communication.
5. **Contributing factors**: list several, not a single root cause; tie each to evidence.
6. **Actions**: specific, owned, dated, sized; each maps to a factor. Route to
   `/detect`, `/coverage`, `/harden`, `/purple`, or runbook updates.

Questions to ask: What surprised us? Where did we wait, and for what? What
information did we lack, and where was it? Which alert should have fired earlier?
Which approval took longest and why? What would we do the same way next time?

## Output format

```markdown
# Post-incident review: <case ID> - <title>
Date of review (UTC): <date>    Facilitator: <role/name>    Attendees: <roles>
## Summary (3-5 sentences)
## Metrics
| Metric | Value | Rows used |
## What went well
## What was hard / what went wrong   (each with evidence reference)
## Contributing factors
| # | Factor | Area (detect/respond/prevent/recover/communicate) | Evidence |
## Actions
| # | Action | Addresses factor | Type (detection/logging/hardening/process/training) | Owner | Due | Tracking ID |
## Follow-up review date
```

## Gates and safety

- Do not publish or circulate the review from this command; produce the file.
- Keep personal data and HR matters out; insider-threat cases follow `ir-insider-threat`
  and legal guidance on what may be documented.
- An action without an owner and due date is listed separately as "unassigned" and
  flagged to the incident commander.
