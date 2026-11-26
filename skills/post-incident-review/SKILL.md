---
name: post-incident-review
description: Run a blameless post-incident review (postmortem / lessons learned) after a security incident and turn it into tracked improvements. Covers when to hold one, roles (facilitator, scribe, incident lead), preparation from the timeline and case notes, blameless facilitation and questioning, 5 whys and its limits, contributing-factor analysis (technical, process, detection, organisation), what went well / poorly / where we got lucky, detection and response metrics (time to detect, acknowledge, contain, recover, dwell time, MTTD/MTTR) with clear timestamp definitions, action items with owners, due dates and verification, and feeding lessons into playbooks, detections, hardening and training. Use when asked to "/postmortem", run a lessons-learned meeting, compute MTTD/MTTR/dwell time for an incident, or follow up open incident action items.
---

# Post-incident review (blameless)

## When to use

- After every incident of medium severity or higher, every incident that hit a
  regulator/customer, and any near miss that "could have been bad".
- When incidents repeat (same root cause twice) or detection was late/external
  (customer, law enforcement, attacker ransom note).
- Quarterly, to review open action items and incident metrics across cases.

Hold the review within roughly 1-2 weeks of closure, while memory is fresh but after
fatigue has passed. Input comes from `incident-response` case notes, the timeline from
`timeline-analysis`, and the report from `ir-report-writing`.

## Ground rules

- **Blameless, not accountability-free.** People acted reasonably given what they
  knew, the tools they had and the pressure they were under. Ask *what made this
  action make sense at the time?*, never *who messed up?*. Outputs change systems, not
  people's performance records. Performance or disciplinary matters are out of scope
  and go through HR separately.
- **Timeline before analysis.** No contributing factor is discussed until the group
  agrees the UTC timeline; disagreements about facts are resolved with evidence
  (log, ticket, chat export), not seniority.
- **Every action item has an owner (a person who agreed), a due date, a tracking
  ticket and a verification method.** An item without these is a wish and is not
  recorded as an action.
- **Metrics use defined timestamps.** MTTD, MTTR and dwell time are computed from the
  timestamps defined below, stated with their evidence, and never mixed between
  definitions across incidents.
- **Confidentiality:** the review document follows the incident's classification and
  legal guidance; legal counsel may need to approve attendance or distribution when
  litigation or regulatory action is possible.

## Workflow

1. **Schedule** (60-90 min) with the incident lead, responders (SOC, IR, IT ops,
   cloud/identity owners), the detection owner, and a decision-maker who can fund
   actions. Facilitator is someone who was **not** in the incident.
2. **Prepare** (facilitator + scribe): draft UTC timeline, key decisions, metrics,
   alerts and tickets; send it 2 days before so people can correct it.
3. **Meeting**: ground rules (2 min) -> walk the timeline (25 min) -> what went well /
   poorly / lucky (15 min) -> contributing factors (20 min) -> actions (15 min) ->
   close (5 min).
4. **Write up** within 3 working days using the template; circulate for factual
   corrections; publish to the agreed audience.
5. **Track** actions in the normal work-tracking system with a tag (e.g. `PIR-<case>`).
6. **Follow up** at 30/60/90 days; close items only on verified evidence.
7. **Feed back**: playbook updates, new detections, hardening changes, training,
   tabletop scenarios, and incident metrics trend.

## Facilitation

- Open by restating the blameless rule and the purpose: learn how the system
  (technology + process + organisation) behaved.
- Use neutral, open questions:
  - "What did you see at that point? What were you expecting to see?"
  - "What options did you have? What made this one the best at the time?"
  - "What information would have changed the decision? Where would it have come from?"
  - "What slowed you down? What helped?"
- Avoid counterfactual blame ("you should have…"), hindsight ("it was obvious"),
  and the word *why* aimed at a person; aim *why* at conditions.
- Give quieter participants (junior analysts, on-call staff) explicit turns; they
  often saw the earliest signals.
- Park off-topic items (budget fights, unrelated projects) in a visible list.

## Analysis: 5 whys and contributing factors

**5 whys** is useful for a single chain but tends to find one "root cause" and stop at
a person. Use it as a starting tool, then widen to contributing factors.

Example chain (business email compromise):
1. Why did the attacker read the mailbox? They signed in with the user's password.
2. Why did the password alone work? IMAP legacy authentication bypassed MFA.
3. Why was legacy auth allowed? A Conditional Access exclusion for an old scanner.
4. Why did the exclusion persist? No owner or expiry for CA exclusions.
5. Why did nobody notice? No alert on legacy-auth sign-ins; no periodic CA review.

Then categorise **contributing factors** (usually several, none sufficient alone):

| Category | Questions | Example |
|---|---|---|
| Prevention / technical controls | Which control was missing, misconfigured or bypassed? | Legacy auth exclusion |
| Detection | Did telemetry exist? Did a rule exist? Did it fire? Was it triaged? | Alert fired after 6 h, queued at low severity |
| Response / process | Were playbooks, access and approvals ready? | Responder lacked rights to revoke sessions; waited 40 min |
| Communication / coordination | Did the right people know in time? | Finance not told to hold payments |
| Organisation / people | Staffing, training, workload, ownership | Single on-call analyst covering two queues |
| External | Vendor, partner, threat actor capability | MSP delay in providing logs |

Also capture **what went well** (to keep doing) and **where we got lucky** (luck is an
unmanaged risk: each lucky break becomes a candidate action).

## Metrics

Define the timestamps once (store them in the case record):

| Timestamp | Definition | Typical evidence |
|---|---|---|
| T0 First malicious activity | Earliest confirmed attacker action | Forensic timeline |
| T1 Detection | First alert/report that, in hindsight, concerned this incident | Alert/ticket creation time |
| T2 Acknowledgement | Analyst started working the alert | Ticket assignment/status change |
| T3 Declared incident | Incident opened / IC assigned | IR case open time |
| T4 Containment | Attacker access effectively cut (accounts, hosts, sessions) | Change/action log |
| T5 Eradication | Persistence and access paths removed | Case notes, verification hunt |
| T6 Recovery | Business services restored to normal | Service ticket |

| Metric | Formula | Notes |
|---|---|---|
| Dwell time | T1 − T0 | Depends on how far back forensics could see; state the limit |
| Time to detect (TTD) | T1 − T0 | Often equal to dwell time; some orgs define dwell to T4 — state yours |
| Time to acknowledge (TTA) | T2 − T1 | SOC queue health |
| Time to contain (TTC) | T4 − T1 (or T4 − T3) | State which start point |
| Time to recover (TTR) | T6 − T1 | Business impact duration |
| MTTD / MTTR | Mean (and median) across incidents in a period | Report median too: one long incident skews the mean |

- Record the **detection source**: internal alert (which rule), threat hunt, user
  report, third party (customer, vendor, law enforcement), attacker notification.
  A rising share of external detections is a key signal.
- Count **alerts that fired but were not actioned** before T1; they show triage gaps.

```kql
// Example: compute TTA and time-to-close for Sentinel incidents in the last 90 days (tune to your status workflow)
SecurityIncident
| where CreatedTime > ago(90d)
| summarize arg_max(LastModifiedTime, *) by IncidentNumber
| extend TTA_min = datetime_diff('minute', FirstModifiedTime, CreatedTime),
         TTClose_h = datetime_diff('hour', ClosedTime, CreatedTime)
| summarize Incidents=count(), MedianTTA_min=percentile(TTA_min, 50), MedianClose_h=percentile(TTClose_h, 50) by Severity
```

Queue metrics from the SIEM measure the SOC process; dwell time and containment
require the forensic timeline. Do not mix them.

## Action items

| Field | Rule |
|---|---|
| Description | Specific and testable ("Block legacy auth for all users via CA, no exclusions without expiry"), not "improve MFA" |
| Linked factor | Which contributing factor it addresses |
| Type | Prevent / Detect / Respond / Recover / Process / Training |
| Priority | Based on risk reduction, not ease |
| Owner | Named person who agreed in or after the meeting |
| Due date | Agreed with the owner |
| Ticket | Link in the team's normal tracker, tagged `PIR-<case>` |
| Verification | How we prove it is done (purple test, config export, drill) |
| Status | Open / In progress / Done (verified) / Won't do (risk accepted by <name>) |

- Prefer a few high-impact actions over a long list nobody finishes. Quick wins are
  fine but label them as such.
- "Won't do" requires an explicit risk acceptance by someone with authority.
- Detection actions are verified by a true-positive test (`purple-team-validation`).

## Feeding lessons back

- **Playbooks** (`incident-response`, `ir-bec-m365`, `ir-ransomware`, ...): update the
  step that was missing or slow; record the change in the playbook history.
- **Detections**: new or tuned rules via `detection-engineering` / `/detect`; telemetry
  gaps via `logging-coverage` / `/coverage`.
- **Hardening**: control gaps to `hardening-windows-ad`, `hardening-m365-entra`,
  `hardening-linux`, `hardening-cloud`; vulnerabilities to `vuln-prioritization`.
- **Hunts**: if the technique could be elsewhere, a hypothesis to `hunt-dispatch`.
- **People**: training needs, on-call staffing, access pre-provisioning for responders.
- **Exercises**: turn the incident into a tabletop scenario for the next quarter.

## False positives & benign look-alikes

- A "slow" metric caused by a definition change (e.g. ticket auto-created at a
  different stage) is not a performance drop; normalise definitions first.
- An action item that looks unfinished because the ticket was closed in another
  system; check before escalating.
- Incidents closed as benign true positive (authorised test, admin activity) usually
  need only a short review focused on why the activity was not pre-announced or
  allowlisted.

## Pitfalls

- Turning the review into a hunt for the person who clicked the link.
- Stopping at "human error" or "user clicked phishing" as the root cause.
- Analysing before agreeing the timeline; arguing facts in the meeting.
- Action items owned by "IT" or "Security" (no person) or with no due date.
- Never revisiting actions; the same incident recurs a year later.
- Comparing MTTD/MTTR across teams or years with different timestamp definitions.
- Publishing raw review notes with customer data or names beyond the agreed audience.

## Output

- Post-incident review document (template below) in the case folder
  (`cases/<case-id>/pir/`).
- Action items in the tracker with owners, dates and verification.
- Metrics record for the incident (T0-T6, detection source) added to the quarterly trend.
- Hand-offs: playbook changes, detection requests, hardening tasks, hunt hypotheses.
  Start with `/postmortem`; the report itself comes from `/report`.

## Template

```markdown
# Post-incident review — <Case ID>: <neutral title>
Date of review: <date> | Facilitator: <name> | Scribe: <name> | Classification: <label>
Attendees: <roles/teams>
Incident severity: <level> | Detection source: <rule / hunt / user / third party>

## Summary (3-5 sentences, blameless)
## Timeline (UTC, agreed)
| Time | Event | Source |
## Metrics
| T0 | T1 | T2 | T3 | T4 | T5 | T6 | Dwell | TTA | TTC | TTR |
## What went well
## What went poorly
## Where we got lucky
## Contributing factors (by category)
## Action items
| # | Action | Factor | Type | Owner | Due | Ticket | Verification | Status |
## Follow-up dates (30/60/90 days)
## Parking lot
```

## References

- NIST SP 800-61 Rev. 3 (lessons learned and continuous improvement in incident
  response, aligned with CSF 2.0).
- Google SRE Book, chapter "Postmortem Culture: Learning from Failure".
- John Allspaw, "Blameless PostMortems and a Just Culture" (Etsy Code as Craft).
- Sidney Dekker, "The Field Guide to Understanding 'Human Error'".
- PagerDuty Incident Response documentation (postmortem process).
- MITRE ATT&CK (https://attack.mitre.org/) for mapping observed techniques to
  detection gaps.
