---
name: ir-report-writing
description: Write incident response reports that are accurate, defensible and readable by their audience. Covers report structure (executive summary for non-technical readers, impact, scope, UTC timeline, root cause and attack path, actions taken, recommendations with owners and dates, IOC appendix with defanging and TLP, MITRE ATT&CK mapping), estimative and confidence language (ICD 203 style), separating facts from assessments, evidence references, what not to write (speculation, blame, unsupported "no data was exfiltrated", unredacted PII or credentials), interim vs final versions, and audiences such as executives, boards, regulators (GDPR Art. 33, NIS2, SEC Item 1.05), cyber insurers and legal counsel. Use when asked to "/report", write an incident report, executive summary or regulator notification draft, or turn case notes and a timeline into a final IR report.
---

# Incident report writing

## When to use

- An incident (or a significant investigation that turned out benign) needs an interim
  or final written report.
- Leadership, legal, a regulator, an insurer or a customer needs a version of the
  incident story at their level of detail.
- Case notes, a timeline (`timeline-analysis`) and forensic findings
  (`windows-forensics`, `linux-forensics`, `memory-forensics`) need to become one
  coherent, evidence-backed document.

Not for: running the investigation (`incident-response`) or the blameless review
meeting (`post-incident-review`), although its outputs feed the recommendations.

## Ground rules

- **Every factual statement traces to evidence.** Each finding in the technical body
  cites an evidence reference (exhibit ID, log source + query, artifact path + hash,
  case note ID). If it cannot be cited, it is an assessment and is worded as one, or
  it is removed.
- **Facts, assessments and unknowns are visibly separated.** "We observed" (fact),
  "we assess with moderate confidence" (assessment), "we could not determine because
  logs were not retained beyond 30 days" (gap).
- **Absence of evidence is stated with its limits.** Never write "no data was
  exfiltrated". Write "we found no evidence of exfiltration in [sources] covering
  [period]; [sources] were not available".
- **No blame, no names for errors.** Describe actions and conditions ("the
  account had no MFA because of an exclusion created in 2023"), not people's
  failings. Named individuals appear only as roles in the timeline where needed.
- **No secrets or unnecessary personal data.** Redact passwords, tokens, keys, full
  customer records and employee personal data; use pseudonyms/IDs with a separate
  restricted key if needed.
- **Legal review before release outside the IR team.** Counsel decides on privilege
  markings, distribution and regulatory wording; the analyst does not add legal
  labels on their own initiative.
- **All times in UTC (ISO 8601)**; state the source of each timestamp and known
  clock skew.

## Workflow

1. **Confirm audience, purpose and distribution** with the incident commander and
   counsel (internal exec, board, regulator, insurer, customer, technical team).
2. **Freeze the evidence set** the report will rely on: timeline version, case notes,
   exhibit list (`evidence-handling`).
3. **Draft the technical body first** (timeline, attack path, scope, actions), then
   derive impact and root cause, then write the executive summary last.
4. **Confidence pass**: tag every key judgement with likelihood/confidence and the
   evidence it rests on.
5. **Redaction and sensitivity pass**: PII, credentials, internal IPs/hostnames for
   external versions, TLP marking for IOCs.
6. **Peer review** by an analyst not involved in the investigation: can each claim be
   traced? Is anything overstated?
7. **Version and release**: interim reports clearly labelled "interim, findings may
   change"; final report supersedes them with a change log.

## Report structure

| Section | Audience | Content |
|---|---|---|
| Document control | All | Title, case ID, version, status (draft/interim/final), date, authors, reviewers, distribution, TLP/classification |
| Executive summary | Execs, board | One page max: what happened, business impact, is it contained, what data/systems affected, what we are doing, decisions needed |
| Incident overview | Managers | Detection source, incident type, dates (first malicious activity, detection, containment, recovery), severity |
| Impact | Execs, legal | Systems, data categories, people affected, operational/financial impact (with confidence), regulatory relevance |
| Scope | Technical, legal | Affected accounts/hosts/tenants; how scope was determined; what was ruled out and how |
| Timeline | Technical | UTC table: time, source, event, evidence ref |
| Root cause and attack path | Technical, mgmt | Initial access vector, how the attacker progressed, contributing conditions |
| Actions taken | All | Containment, eradication, recovery, with times and approvals |
| Recommendations | Mgmt, owners | Prioritised, each with owner, due date, and the gap it closes |
| Limitations | All | Missing logs, unavailable systems, assumptions |
| Appendices | Technical | IOCs, ATT&CK mapping, evidence list, queries used, glossary |

## Executive summary rules

- Plain language; no acronyms without explanation; no tool names unless meaningful.
- Answer in this order: **What happened? What is the impact? Is it over? What are we
  doing? What do you need to decide?**
- Quantify with ranges and confidence instead of false precision.
- Example:

> On 3 February 2026 an attacker used a stolen employee password to access one
> mailbox and send fraudulent payment requests to two customers. The attacker had
> access for about six hours before our security team detected and removed it. We
> found no evidence that other accounts or systems were accessed (based on sign-in
> and mailbox audit logs for all users from 1 January to 4 February). One customer
> paid an invoice of [amount]; recovery is in progress with the bank. We have reset
> the account, enforced stronger sign-in protection for all staff, and recommend
> [decision] by [date].

## Timeline table

```markdown
| # | Time (UTC) | Source | Event | Evidence |
|---|---|---|---|---|
| 1 | 2026-02-03T07:41:12Z | Entra SigninLogs | Successful sign-in for user-17 from 203.0.113.20 (new country), single-factor (legacy auth) | EX-004, query Q-02 |
| 2 | 2026-02-03T07:52:30Z | UAL (New-InboxRule) | Inbox rule moving messages with "invoice" to RSS Feeds | EX-005 |
| 3 | 2026-02-03T13:40:05Z | Sentinel incident 4521 | Alert "Suspicious inbox manipulation rule" | EX-001 |
| 4 | 2026-02-03T13:58:00Z | IR case notes | Sessions revoked, password reset (approved by IC) | CN-012 |
```

Mark inferred times ("~", "between X and Y") and explain the inference.

## Confidence language

Use one consistent scale (ICD 203 style) and define it in the report:

| Term | Approximate probability |
|---|---|
| Almost no chance / remote | 1-5% |
| Very unlikely | 5-20% |
| Unlikely | 20-45% |
| Roughly even chance | 45-55% |
| Likely | 55-80% |
| Very likely | 80-95% |
| Almost certain | 95-99% |

Separate **likelihood** (how probable the event is) from **analytic confidence**
(how good the evidence and reasoning are: low / moderate / high). Example: "We assess
it is *likely* (moderate confidence) that the password was obtained via the phishing
email of 28 January; the user entered credentials on the page, but we lack proxy logs
for the following 24 hours."

Words to avoid without qualification: "clearly", "obviously", "proves", "sophisticated
nation-state", "all data", "nothing was taken", "the user failed to".

## Root cause and contributing factors

- State the **initial access vector** and the **conditions that let it succeed**
  (missing control, misconfiguration, detection gap), not "human error".
- Map each contributing condition to a recommendation; recommendations without a
  finding behind them belong in a separate "general improvements" list.
- If root cause is undetermined, say so, list the hypotheses with likelihood, and the
  evidence that would resolve them.

## Recommendations

| # | Recommendation | Closes gap | Priority | Owner | Due | Status |
|---|---|---|---|---|---|---|
| R1 | Block legacy authentication for all users via Conditional Access | Root cause (legacy auth bypassed MFA) | Critical | Identity team lead | 2026-02-17 | In progress |
| R2 | Alert on new inbox rules that move/delete messages with finance keywords | Detection delay (6 h) | High | SOC detection lead | 2026-03-01 | Open |

Owners are roles or named teams agreed with them before publication; due dates are
agreed, not imposed by the report author. Track them in `post-incident-review`.

## IOC appendix and ATT&CK mapping

- IOCs defanged (`hxxps://`, `[.]`), with type, first/last seen, context, confidence,
  and TLP marking (`threat-intel-ioc`). Omit internal IOCs from external versions.

| Tactic | Technique | Observed procedure | Evidence |
|---|---|---|---|
| Initial Access | T1078.004 Valid Accounts: Cloud Accounts | Sign-in with stolen password via IMAP | EX-004 |
| Persistence / Defense Evasion | T1564.008 Hide Artifacts: Email Hiding Rules | Inbox rule moving "invoice" emails | EX-005 |
| Collection | T1114.002 Email Collection: Remote Email Collection | Mailbox items accessed via IMAP | EX-006 |

Map only what evidence shows; do not add techniques "typical of the actor".

## Audience variants

- **Executives / board**: executive summary, impact, decisions, high-level
  recommendations, residual risk. Two to four pages.
- **Regulators**: content and deadlines are set by law and counsel. Examples of regimes
  with short clocks: GDPR Art. 33 (supervisory authority within 72 hours of becoming
  aware of a personal data breach, Art. 34 for data subjects), NIS2 (early warning
  within 24 hours, notification within 72 hours, final report within one month),
  US SEC Form 8-K Item 1.05 (within four business days of determining materiality).
  Provide facts and confidence; counsel owns wording and submission.
- **Cyber insurers / breach coach**: usually engaged through counsel; follow their
  reporting format and channel; do not volunteer opinions on coverage or liability.
- **Customers / partners**: what affects them, what they should do, contacts; no
  internal details or other customers' data.
- **Technical teams**: full timeline, queries, artifacts, IOCs, detection and hardening
  actions.

## False positives & benign look-alikes

- Events in the timeline that turned out benign (admin activity, scanner noise) are
  either removed or explicitly marked "investigated, benign" so readers do not
  misread them as attacker activity.
- Alerts that triggered the investigation but were unrelated to the root cause are
  noted as detection context, not as part of the attack path.
- For benign-true-positive outcomes (e.g. an authorised test), a short closure report
  with evidence of authorisation is the correct output, not a full IR report.

## Pitfalls

- Writing the executive summary first and bending the findings to fit it.
- Mixing local time zones and UTC, or copying tool timestamps without noting skew.
- Overstating scope certainty when key logs were missing or retention was short.
- Attributing to a named threat actor on weak overlap (a shared tool or IP).
- Leaving passwords, session tokens or full PII in screenshots and log excerpts.
- Recommendations without owners or dates, which therefore never happen.
- Releasing an interim report without labelling it, then contradicting it later.

## Output

- Report in the case folder (`cases/<case-id>/report/`), Markdown or the organisation's
  template, with version history; exec and external variants derived from the same
  source.
- Recommendation list exported to the tracking system and to `post-incident-review`
  for the review meeting; IOC appendix to `threat-intel-ioc`; detection gaps to
  `detection-engineering`. `/report` produces the draft; `/postmortem` follows.

## Template

```markdown
# Incident Report — <Case ID>: <short neutral title>
Version <x.y> | Status: Draft / Interim / Final | Date (UTC): <date> | TLP:<label>
Authors: <roles> | Reviewers: <roles> | Distribution: <list>

## 1. Executive summary
## 2. Incident overview (type, detection source, key dates, severity)
## 3. Impact (systems, data, people, operations; confidence)
## 4. Scope (in scope, ruled out, method)
## 5. Timeline (UTC)
## 6. Root cause and attack path
## 7. Actions taken (containment, eradication, recovery; approvals)
## 8. Recommendations (owner, due date, status)
## 9. Limitations and open questions
## Appendix A — Indicators of compromise (defanged, TLP)
## Appendix B — MITRE ATT&CK mapping
## Appendix C — Evidence list (ID, description, hash, custodian)
## Appendix D — Queries and methods
## Appendix E — Glossary and confidence scale
```

## References

- NIST SP 800-61 Rev. 3: Incident Response Recommendations and Considerations for
  Cybersecurity Risk Management.
- ODNI Intelligence Community Directive (ICD) 203: Analytic Standards (expressions of
  likelihood and confidence).
- CISA: Federal Government Cybersecurity Incident and Vulnerability Response Playbooks.
- Regulation (EU) 2016/679 (GDPR) Articles 33-34; Directive (EU) 2022/2555 (NIS2)
  Article 23; SEC Form 8-K Item 1.05.
- MITRE ATT&CK (https://attack.mitre.org/); FIRST TLP 2.0.
