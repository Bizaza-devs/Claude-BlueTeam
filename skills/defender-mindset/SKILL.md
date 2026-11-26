---
name: defender-mindset
description: Analytic discipline for SOC analysts, incident responders and threat hunters. Covers hypothesis-driven investigation, Analysis of Competing Hypotheses (ACH, Heuer), the Pyramid of Pain (hashes to TTPs), the Diamond Model (adversary, capability, infrastructure, victim), Lockheed Martin Cyber Kill Chain vs MITRE ATT&CK, cognitive biases in triage (anchoring, confirmation, availability, automation bias), calibrated confidence language (high/moderate/low, ICD 203 style), rules for "absence of evidence", and writing notes for the next analyst. Use when an investigation stalls, when two explanations both fit, when writing a verdict or assessment, when reviewing another analyst's conclusion, or when asked "how confident are we", "are we sure it's not X", "what else could explain this".
---

# Defender mindset

How to think so that verdicts survive review. The tools change; the failure
modes of analysts do not.

## When to use

- Before writing any verdict, assessment or executive statement.
- When two or more explanations fit the evidence.
- When a case has stalled or the team is "sure" without being able to say why.
- When peer-reviewing another analyst's triage or report.
- When choosing what to detect or hunt (Pyramid of Pain, ATT&CK).

## Ground rules

1. **Every conclusion names its evidence and its confidence.** "Malicious
   (moderate confidence): parent process is Outlook, child is a signed LOLBin
   fetching from a 2-day-old domain; no admin ticket explains it."
2. **At least one alternative hypothesis is written down and actively tested**
   before a TP or FP verdict on anything SEV3 or above.
3. **Absence of evidence is only evidence of absence when you have proven the
   telemetry would have recorded it** (source enabled, covering that host,
   retained for that period, and your query returns known-good positives).
4. **Facts, inferences and assumptions are labelled separately** in notes and
   reports.

## Workflow

1. **State the question** precisely: "Did account X authenticate to host Y
   between T1 and T2, and was it the legitimate user?"
2. **Generate hypotheses** (at least three for anything non-trivial),
   including a benign one and a "worse than it looks" one.
3. **List evidence** you have and evidence you could get, with cost to get it.
4. **Seek disconfirming evidence first.** The test that could kill your
   favourite hypothesis is the most valuable query.
5. **Score with ACH** (below) when hypotheses are close.
6. **State the conclusion with confidence** and what would change it.
7. **Write it for the next analyst** (template at the end).

## Hypothesis-driven investigation

A good hypothesis is testable and names the data that would confirm or refute it.

| Weak | Strong |
|---|---|
| "The host might be compromised." | "If `svc_backup` was used for lateral movement, we expect 4624 Type 3 logons from WS-114 to servers outside the backup subnet between 02:00 and 04:00 UTC." |
| "Looks like phishing." | "If the user entered credentials on the page, we expect a successful sign-in from a non-corporate ASN within ~1 h of the URL click, likely with a different user agent." |

For each hypothesis write: expected observables, where to look, what result
would refute it. This is the same structure `hunt-dispatch` uses for hunts.

## Analysis of Competing Hypotheses (ACH)

From Richards J. Heuer Jr., *Psychology of Intelligence Analysis*. Its key
move: judge hypotheses by **inconsistency**, not by how much evidence agrees.

1. List hypotheses (columns): H1 malicious actor, H2 authorised admin, H3
   misconfigured software, H4 red team...
2. List significant evidence and arguments (rows), including absences you
   have verified.
3. Mark each cell: CC very consistent, C consistent, N neutral/not applicable,
   I inconsistent, II very inconsistent.
4. Weight evidence by credibility and relevance (a single log line from a
   source that can be spoofed is weaker than an EDR process tree).
5. Discard / deprioritise the hypothesis with the most inconsistencies; do
   not crown the one with the most "C" marks.
6. Ask which evidence is **diagnostic** (differs across hypotheses). Evidence
   consistent with everything does not help; go and get diagnostic evidence.
7. Report the conclusion with the remaining uncertainty and the milestones
   that would change it.

```
| Evidence                                   | H1 attacker | H2 IT admin | H3 software |
|--------------------------------------------|-------------|-------------|-------------|
| PsExec service PSEXESVC created (7045)     | C           | C           | I           |
| Source host is a user workstation          | C           | I           | N           |
| No change ticket for that window           | C           | I           | N           |
| Executed `nltest /domain_trusts` first     | CC          | I           | II          |
| Inconsistency score                        | 0           | 3 (I)       | 3 (I, II)   |
```

## Pyramid of Pain (David Bianco, 2013)

How much it costs the adversary when you detect or deny each indicator type:

| Level | Indicator | Adversary cost to change | Defender takeaway |
|---|---|---|---|
| 6 (top) | TTPs | Tough | Behavioural detections; most durable |
| 5 | Tools | Challenging | Detect tool behaviour, not the binary |
| 4 | Network / host artifacts | Annoying | URI patterns, JA3/JA4, named pipes, registry keys |
| 3 | Domain names | Simple | Useful short-term, block + hunt |
| 2 | IP addresses | Easy | Expires quickly; cloud/CDN IPs are shared |
| 1 (bottom) | Hash values | Trivial | Good for scoping a known sample, poor for detection |

Use hashes and IPs to **scope** a known incident fast; invest detection
engineering time at the top (`detection-engineering`, `sigma-rules`).

## Diamond Model of Intrusion Analysis

Caltagirone, Pendergast and Betz (2013). Every event has four vertices:

```
            Adversary
              /   \
   Infrastructure -- Capability
              \   /
             Victim
```

- **Pivoting**: from one known vertex find the others. A C2 domain
  (infrastructure) -> passive DNS -> other domains on the same IP -> other
  victims; a malware sample (capability) -> config -> more infrastructure.
- **Meta-features**: timestamp, phase, result, direction, methodology,
  resources. Socio-political and technology axes connect adversary/victim
  and infrastructure/capability.
- **Activity threads** chain events into a campaign view; useful for
  `threat-intel-ioc` and for grouping cases that look separate.

## Kill chain vs ATT&CK

| | Lockheed Martin Cyber Kill Chain | MITRE ATT&CK |
|---|---|---|
| Structure | 7 linear phases: Reconnaissance, Weaponization, Delivery, Exploitation, Installation, Command & Control, Actions on Objectives | Matrix of tactics (the "why") x techniques/sub-techniques (the "how"), per platform (Enterprise, Mobile, ICS) |
| Strength | Executive communication; "break the chain early" | Granular, shared vocabulary for detections, hunts and coverage |
| Weakness | Perimeter- and malware-centric; weak on insider, cloud, identity abuse | Large; easy to "colour the matrix" without measuring detection quality |
| Use it for | Narrative in reports, phase of an incident | Mapping detections (`/coverage`), hunts, intel, purple tests |

Map observed behaviour to the most specific technique ID you can defend
(e.g. `T1003.001` LSASS Memory, not just `T1003`). One event can map to more
than one technique; do not force a single label.

## Cognitive biases in triage

| Bias | How it shows up in a SOC | Countermeasure |
|---|---|---|
| Anchoring | First alert title ("Mimikatz") frames everything after | Write your own one-line description of the raw evidence before reading the vendor title |
| Confirmation | Only running queries that can confirm the favoured story | Run the disconfirming query first; record it |
| Availability | Last week's incident type is seen everywhere | Check base rates: how often has this rule been TP in 90 days? |
| Automation bias | "The EDR said benign" / "the sandbox found nothing" | Tools are evidence, not verdicts; know their blind spots (sandbox evasion, sleep, geofencing) |
| Premature closure | Stopping at the first plausible explanation | Require one alternative hypothesis for SEV3+ |
| Satisficing under queue pressure | Closing as FP because the queue is long | Timebox and escalate as "Needs-data" instead of guessing |
| Sunk cost | Continuing a dead-end theory after hours of work | Re-score hypotheses at each timebox |
| Groupthink / authority | Junior analyst defers to senior's early call | Ask the newest analyst for their view first in case reviews |
| Hindsight | Post-incident review judges decisions with later knowledge | Use the decision log: what was known at that time |

## Confidence language

Separate **likelihood** (how probable the judgement is) from **confidence**
(how good the evidence base is). Pattern follows the US ODNI Intelligence
Community Directive (ICD) 203 analytic standards.

| Confidence | Meaning | Typical evidence base |
|---|---|---|
| High | Judgement based on high-quality, corroborated evidence from independent sources; alternative explanations tested and rejected | EDR process tree + network logs + host artifact agree; no plausible benign explanation |
| Moderate | Credibly sourced and plausible, but not corroborated enough for high, or one alternative remains open | Two consistent sources, a gap in telemetry or one untested alternative |
| Low | Fragmentary, single-source, or significant gaps; plausible but could be wrong | One alert, missing logs, inference from absence |

Likelihood words (use consistently, define them in the report appendix):
almost certainly, very likely, likely, roughly even chance, unlikely, very
unlikely, almost no chance.

Rules:
- Never write "confirmed" unless confidence is high.
- Never write "no evidence of compromise" without stating what was examined
  and for which period. Prefer: "In the 30 days of EDR and sign-in data
  reviewed, we found no evidence of ...".
- Put the confidence next to the claim, not in a footnote.

## Absence of evidence

Before writing "not observed" or using absence in ACH, check:

| Check | Question |
|---|---|
| Collection | Was the source enabled for that host/user/tenant (e.g. Sysmon installed, Audit Process Creation on, M365 audit enabled, CloudTrail data events on)? |
| Coverage | Did the agent report during the window (heartbeat, last-seen)? Was the host offline? |
| Retention | Does the data still exist for that date range? |
| Fidelity | Does the source record that field (command line in 4688 requires the separate "Include command line in process creation events" policy)? |
| Query validity | Does the query return a known-good positive when pointed at a test case? |
| Tampering | Any log clear (Security 1102, System 104), agent stop, `StopLogging`, audit policy change (4719)? Tampering is itself evidence. |

If any check fails, report a **gap**, not an absence. Gaps go to
`logging-coverage`.

## Writing for the next analyst

Your notes will be read at 03:00 by someone who was not in the room.

```
## Analyst note - <case id> - <UTC time> - <name>
Question: <what I was trying to establish>
Done: <queries/artifacts examined, time ranges, ref to queries/ files>
Found (facts): <bullets, each with source + UTC time>
Assessment: <judgement> (<likelihood>, <confidence> confidence)
Alternatives considered: <H2/H3 and why rejected or still open>
Gaps: <data not available or not yet checked>
Next steps: <ordered, with owner if known>
Do not: <anything that would destroy evidence or tip off the actor>
```

Style: short sentences, entities in backticks, defanged indicators
(`hxxps://evil[.]example`), UTC everywhere, no unexplained acronyms in
customer-facing text.

## False positives & benign look-alikes

The mindset version of a false positive is a **wrong frame**:

- Treating "unusual" as "malicious". New admin tooling, a migration or a
  user travelling produce anomalies; an anomaly is a lead, not a verdict.
- Treating "signed by Microsoft" or "known tool" as "benign". LOLBins and
  RMM tools are signed (see `hunt-lolbins`).
- Treating a matching IOC as proof. Shared hosting, CDN and VPN IPs and
  sinkholed domains produce matches with no compromise.

## Pitfalls

- Hypotheses that cannot be refuted ("an APT could be hiding anywhere").
- Counting supporting evidence instead of seeking inconsistent evidence.
- Over-precision: "the attacker entered at 09:14:07" when the source has
  minute-level timestamps or clock skew.
- Mixing confidence and severity ("high confidence" is not "high severity").
- Notes that record conclusions but not the queries that produced them.

## Output

- Written hypotheses with expected observables.
- ACH matrix for contested cases, stored in the case folder.
- Verdicts and assessments with likelihood + confidence + alternatives.
- Gap list handed to `logging-coverage`.
- Hand-offs: `alert-triage`, `hunt-dispatch` (`/hunt`), `threat-intel-ioc`
  (Diamond pivots), `ir-report-writing` (confidence language),
  `post-incident-review` (bias review).

## References

- Richards J. Heuer Jr., *Psychology of Intelligence Analysis* (CIA Center
  for the Study of Intelligence, 1999) - ACH and cognitive bias.
- David J. Bianco, "The Pyramid of Pain" (2013).
- Caltagirone, Pendergast, Betz, "The Diamond Model of Intrusion Analysis" (2013).
- Lockheed Martin, "Intelligence-Driven Computer Network Defense Informed by
  Analysis of Adversary Campaigns and Intrusion Kill Chains" (Hutchins,
  Cloppert, Amin, 2011).
- US ODNI Intelligence Community Directive 203, Analytic Standards.
- Sherman Kent, "Words of Estimative Probability" (1964).
- MITRE ATT&CK: https://attack.mitre.org/
