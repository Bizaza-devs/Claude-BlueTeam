---
name: blueteam-methodology
description: The defender's operating model for the whole blueteam bundle. Covers NIST SP 800-61 Rev. 3 (CSF 2.0 Govern/Identify/Protect/Detect/Respond/Recover) alongside the classic PICERL lifecycle (Preparation, Identification, Containment, Eradication, Recovery, Lessons learned), assume-breach thinking, the detect-triage-investigate-respond-improve loop, case discipline (case folder, UTC timeline, evidence log, decision log), a severity/priority matrix (SEV1-SEV4, P1-P4), comms cadence and escalation triggers. Use when starting any security case, deciding which skill to load next, setting severity, asking "how do we run this incident", "what phase are we in", "who do I escalate to", or when building a SOC/IR process.
---

# Blue team methodology

The operating model every other skill in this bundle plugs into. It answers
three questions: what phase are we in, what is the minimum discipline the case
needs, and who must know now.

## When to use

- At the start of any case (alert, report, hunt finding, third-party tip).
- When you are unsure which skill to load next, or the case is drifting.
- When setting or changing severity, or deciding to escalate / declare.
- When designing or reviewing a SOC / IR process, runbook or on-call model.

## Ground rules

1. **No case, no work.** Anything beyond a sub-15-minute triage gets a case ID,
   a case folder and a timeline before analysis continues.
2. **Every claim cites evidence.** A timeline entry or report sentence has a
   source (log, query, artifact, hash) and a time in UTC. "We think" entries
   are labelled as hypotheses, not facts.
3. **Evidence before change.** No containment or remediation step that destroys
   state (reboot, reimage, account delete, log rotation) until the volatile
   evidence it would destroy is captured or the incident commander (IC)
   explicitly accepts the loss in the decision log.
4. **Severity is set by impact and scope evidence, not by alert label.** A
   vendor "High" with no corroboration is a triage item; a "Low" touching a
   tier-0 asset may be a SEV2.
5. **Destructive or business-affecting actions need an owner.** Disabling
   accounts, isolating servers, blocking at the edge, resetting krbtgt: IC or
   change-approver signs off, and it is logged with who/when/why.

## Workflow

1. **Intake.** Record source, reporter, first-seen time (UTC), affected
   entities. Assign a case ID (`YYYYMMDD-<short-slug>`), or attach to an open case.
2. **Triage** with `alert-triage` (or `phishing-analysis` for reported mail).
   Output: TP / Benign TP / FP / Needs-data / Escalate.
3. **Scope.** If TP: what else does this entity touch, what touched it, since
   when. Pivot on user, host, IP, hash, process tree. Use `/investigate`.
4. **Set severity** with the matrix below. Declare an incident if criteria in
   `incident-response` are met; open the case with `/ir`.
5. **Contain** with blast radius and approvals (`/contain`), then **eradicate**
   and **recover** per the matching playbook (`ir-ransomware`, `ir-bec-m365`,
   `ir-cloud-aws`, `ir-azure-entra`, `ir-insider-threat`).
6. **Preserve and analyse** in parallel: `evidence-handling`,
   `windows-forensics`, `linux-forensics`, `memory-forensics`,
   `timeline-analysis`, `malware-triage`.
7. **Close the loop.** Every TP produces at least one of: a new or tuned
   detection (`detection-engineering`), a hunt (`/hunt`), a hardening item
   (`/harden`), an IOC package (`threat-intel-ioc`). Then `ir-report-writing`
   and `post-incident-review`.

## Frameworks and how they fit

### NIST SP 800-61 Rev. 3 (CSF 2.0 aligned)

Rev. 3 (2025) replaces the Rev. 2 four-phase lifecycle with a CSF 2.0
Community Profile: incident response is treated as part of overall
cybersecurity risk management, not a standalone process.

| CSF 2.0 Function | IR meaning | Bundle layer |
|---|---|---|
| Govern (GV) | Policy, roles, authority to act, legal/regulatory obligations | `blueteam-methodology`, `incident-response` |
| Identify (ID) | Asset inventory, risk, lessons-learned feeding improvement | `logging-coverage`, `vuln-prioritization`, `post-incident-review` |
| Protect (PR) | Hardening, identity, backups that survive an incident | `hardening-windows-ad`, `hardening-m365-entra`, `hardening-linux`, `hardening-cloud` |
| Detect (DE) | Continuous monitoring, adverse-event analysis | `detection-engineering`, `hunt-dispatch`, `alert-triage` |
| Respond (RS) | Incident management, analysis, reporting/comms, mitigation | `incident-response`, `ir-*` playbooks, forensics skills |
| Recover (RC) | Recovery plan execution, recovery comms | `incident-response`, `ir-ransomware` |

Rev. 2 phases (Preparation; Detection & Analysis; Containment, Eradication &
Recovery; Post-Incident Activity) are still widely used in runbooks and
contracts; they map cleanly onto PICERL below.

### PICERL (SANS six-step)

| Phase | Exit criterion (move on only when true) |
|---|---|
| Preparation | Playbooks, contacts, log sources, tooling and access tested before the incident |
| Identification | Incident confirmed, initial scope and severity set, case open |
| Containment | Attacker can no longer expand access or exfiltrate; evidence preserved |
| Eradication | All known footholds removed (accounts, persistence, malware, keys) and verified by hunt |
| Recovery | Systems restored from known-good, monitored for re-entry for an agreed window |
| Lessons learned | Blameless review done, actions owned and dated |

Phases overlap in real life: you will scope while containing. Track the phase
per workstream, not per incident.

### Assume breach

- Design detection and response as if an attacker already has a user
  foothold. Ask "if this account/host is compromised, what would we see, and
  how fast could we cut it off?"
- Treat identity as the perimeter: tokens, sessions, app consents and cloud
  keys are as important as malware.
- Any single compromised credential is presumed to have been used everywhere
  it is valid until logs prove otherwise.

### Detection and response loop

```
 telemetry -> detection -> triage -> investigation -> response -> lessons
     ^                                                               |
     +------------- new detections, hunts, hardening, coverage ------+
```

A loop that never feeds back is a ticket queue, not a security programme.
Measure it: mean time to detect (MTTD), to triage, to contain (MTTC), and
the share of incidents first found by a detection vs by a user or third party.

### How the bundle's layers fit

| Layer | Question it answers | Skills |
|---|---|---|
| Think | How do we reason and run cases? | `blueteam-methodology`, `defender-mindset` |
| Triage & respond | Is it real, and what do we do now? | `alert-triage`, `incident-response`, `ir-*`, `phishing-analysis` |
| Detect | How do we see it next time? | `detection-engineering`, `sigma-rules`, `kql-sentinel-defender`, `spl-splunk`, `elastic-eql-esql`, `yara-rules`, `network-detection-suricata-zeek`, `logging-coverage` |
| Hunt | Is it already here and unseen? | `hunt-dispatch` and the `hunt-*` skills |
| Forensics | Exactly what happened, provably? | `windows-forensics`, `linux-forensics`, `memory-forensics`, `timeline-analysis`, `malware-triage`, `evidence-handling` |
| Harden & prioritise | How do we make it harder? | `hardening-*`, `vuln-prioritization` |
| Intel, validate, report | What do we share, test and write? | `threat-intel-ioc`, `purple-team-validation`, `ir-report-writing`, `post-incident-review` |

## Case discipline

### Case folder

Use the case scaffolder in `scripts/` if present, otherwise create:

```
cases/<case-id>/
  README.md          one-paragraph summary, severity, IC, status, next update time
  timeline.md        UTC, append-only
  evidence-log.md    every artifact: id, description, source, hash, acquired by, time, storage location
  decisions.md       every decision: time, decision, by whom, rationale, alternatives rejected
  iocs.csv           type,value(defanged),first_seen,last_seen,source,confidence,status
  queries/           every query run, with platform, time range and result count
  notes/             scratch per analyst (never the source of truth)
  comms/             sent updates, exactly as sent
```

### Timeline entry format

```
| UTC time            | Source            | Entity          | Event                                   | Fact/Hyp | Ref        |
|---------------------|-------------------|-----------------|-----------------------------------------|----------|------------|
| 2026-03-02 09:14:07 | SigninLogs        | j.doe@corp      | Sign-in from new ASN, MFA satisfied by claim in token | Fact | Q-004 |
| 2026-03-02 09:20    | analyst           | j.doe@corp      | Likely AiTM token replay                | Hyp      | H-1        |
```

- Always UTC, always say which clock (log ingestion time vs event time).
- Record the timezone and clock skew of each source when you first use it.
- Never edit past entries; add a correction line referencing the original.

### Evidence log minimum

Item ID, description, source system, acquisition method/tool and version,
SHA-256, acquired by, acquisition time (UTC), storage location, access list.
Details and chain-of-custody form: `evidence-handling`.

### Decision log

Containment and scoping choices are the things post-incident reviews and
lawyers examine. Record what you knew at the time, not what you learned later.

## Severity and priority

### Severity (impact of the incident)

| SEV | Definition (adapt to your business) | Examples |
|---|---|---|
| SEV1 Critical | Confirmed active compromise with business-wide impact, or of tier-0 identity/infra, or confirmed exfiltration of regulated data at scale | Domain admin compromise, ransomware executing, cloud org-admin keys abused, active wire fraud |
| SEV2 High | Confirmed compromise contained to a business unit or a few systems; plausible path to SEV1 | One server with hands-on-keyboard activity, a compromised mailbox with forwarding to external |
| SEV3 Medium | Confirmed malicious activity with limited impact, no evidence of spread | Commodity malware blocked post-execution on one workstation, single phished credential reset before use |
| SEV4 Low | Policy violation or attempted attack with no impact | Blocked phishing campaign, scanning, PUA |

### Priority (how fast we work it)

Priority = severity adjusted by urgency (is it still happening?) and asset
criticality.

| | Ongoing / spreading | Contained or historical |
|---|---|---|
| Tier-0 asset (DC, IdP, PKI, backup, cloud admin, CI/CD) | P1 | P2 |
| Business-critical system or privileged user | P1 | P2 |
| Standard workstation / user | P2 | P3 |
| Lab / non-production with no prod trust | P3 | P4 |

Indicative response targets (set your own in policy): P1 work starts within 15
minutes, 24x7; P2 within 1 hour; P3 same business day; P4 next business day.

**Re-evaluate severity at every update.** Upgrades are cheap; late upgrades are
the most common IR failure.

## Communications cadence

| Severity | Internal update cadence | Audience | Channel |
|---|---|---|---|
| SEV1 | Every 1-2 h, plus on material change; exec brief at least twice daily | IC, exec sponsor, legal, comms, IT ops leads | Out-of-band bridge and chat (assume corporate email/chat may be compromised) |
| SEV2 | Every 4 h or twice daily | IC, security lead, system owners, legal if data involved | Incident channel |
| SEV3 | Daily | Security team, system owner | Ticket |
| SEV4 | On closure | Ticket | Ticket |

Each update states: current severity, what changed since last update, what we
know (facts), what we believe (with confidence), actions in progress with
owners, decisions needed, next update time. Templates: `incident-response`.

## When to escalate

Escalate to the next tier / IC / on-call manager **immediately** when any of:

- Evidence of privileged or tier-0 compromise (domain/enterprise admin, Global
  Administrator, cloud root/org admin, backup admin, CI/CD secrets).
- Hands-on-keyboard activity: interactive commands, discovery bursts
  (`whoami /all`, `nltest /domain_trusts`, `net group "domain admins"`),
  lateral movement.
- Ransomware precursors: shadow copy deletion, backup tampering, mass file
  rename, ESXi service manipulation (see `ir-ransomware`).
- Possible personal-data, regulated-data or customer-data exposure (legal clock
  may be running; see `incident-response`).
- Financial fraud in progress (BEC payment change, see `ir-bec-m365`).
- More than one host or identity affected by the same activity.
- An insider is suspected (HR/legal before further action; see `ir-insider-threat`).
- You are about to take a destructive or business-affecting action.
- You are stuck for longer than your timebox (tier-1: ~30 min, tier-2: ~2 h).

Escalating early and being wrong costs minutes; escalating late costs the case.

## False positives & benign look-alikes

At the methodology level, the recurring "false positive" is a process one:

- **Authorised activity nobody told the SOC about**: red team, pentest,
  vulnerability scan, IT admin scripts, migrations. Maintain a change/test
  calendar and an allowlist with expiry dates; verify against it, never on the
  word of the actor alone.
- **Duplicate cases** for the same incident across tools. Correlate by entity
  and time before opening a new case.
- **Severity inflation** from vendor labels. Re-score with the matrix.

## Pitfalls

- Working in chat threads instead of the case folder; the timeline then gets
  rebuilt from memory, badly.
- Mixing local time and UTC, or ingestion time and event time.
- Containing before scoping: you evict one foothold and the attacker, now
  alerted, uses the three you have not found. Contain fast when harm is
  ongoing, but scope in parallel and plan a coordinated eviction for APT-style
  intrusions.
- Communicating over compromised channels (the attacker reads your IR email).
- Declaring "eradicated" without a verification hunt.
- No owner or date on lessons-learned actions.

## Output

- Case folder with README, timeline, evidence log, decision log, IOC list.
- Severity + priority with rationale, re-evaluated at every update.
- Hand-offs: `alert-triage` (`/triage`), `incident-response` (`/ir`,
  `/contain`), `defender-mindset` (analysis quality), `timeline-analysis`
  (`/timeline`), `ir-report-writing` (`/report`), `post-incident-review`
  (`/postmortem`).

## References

- NIST SP 800-61 Rev. 3, Incident Response Recommendations and Considerations
  for Cybersecurity Risk Management: A CSF 2.0 Community Profile (2025).
- NIST SP 800-61 Rev. 2, Computer Security Incident Handling Guide (2012,
  superseded but still referenced).
- NIST Cybersecurity Framework (CSF) 2.0 (2024).
- SANS Incident Handler's Handbook (PICERL).
- CISA Federal Government Cybersecurity Incident and Vulnerability Response
  Playbooks.
- MITRE ATT&CK: https://attack.mitre.org/
