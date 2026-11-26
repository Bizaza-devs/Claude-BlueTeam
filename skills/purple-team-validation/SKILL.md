---
name: purple-team-validation
description: Plan and run defensive detection-validation (purple team) exercises with published test procedures. Covers written authorisation and change approval, rules of engagement, lab-first testing and snapshots, SOC deconfliction, Atomic Red Team with Invoke-AtomicRedTeam (Invoke-AtomicTest -ShowDetailsBrief, -CheckPrereqs, -TestNumbers, -Cleanup, -ExecutionLogPath), MITRE Caldera operations and abilities, the CTID Adversary Emulation Library and micro emulation plans, a test-case template (ATT&CK technique, procedure, expected telemetry, expected alert, result), outcome scoring (blocked / alerted / logged / not seen), ATT&CK Navigator and VECTR tracking, and feeding gaps to detection-engineering. Use when asked to "/purple", validate that a detection fires, test EDR/SIEM coverage for a technique, or prove a new rule works on a true positive.
---

# Purple-team detection validation

## When to use

- A new or changed detection needs a true-positive test before it is called done.
- Leadership or an audit asks "would we detect technique X?" and the answer must be
  evidence, not opinion.
- After an incident or threat-intel report: replay the observed techniques safely to
  confirm the new detections fire.
- Periodic regression testing of EDR/SIEM coverage after agent, parser or rule changes.

Not for: penetration testing, red-team operations against production without a
separate engagement contract, or developing new attack tooling. This skill only runs
**published, well-known test procedures** (Atomic Red Team, Caldera stock abilities,
CTID emulation plans) to validate defences. Pair it with `detection-engineering` for
the fixes and `logging-coverage` for telemetry gaps.

## Ground rules

- **Written authorisation first.** No test runs without a signed scope: systems,
  accounts, techniques, time window, named operators, emergency contact, and stop
  conditions. Production tests also need an approved change ticket.
- **Lab first, always.** Every test runs first on an isolated lab host that mirrors
  production telemetry (same EDR policy, same log pipeline). Only tests that were
  clean in the lab, with working cleanup, are promoted to production.
- **Snapshot before, cleanup after.** Take a VM snapshot (lab) or confirm backup
  (prod); run the test's cleanup and verify the host returned to baseline.
- **Deconflict.** The SOC lead (or a white cell for blind tests) knows the test window,
  host names and operator accounts, so a real incident is never dismissed as "just the
  purple team" and a test is never escalated as a real breach. Tag every test with an
  ID that appears in the operator's notes.
- **No destructive or data-exposing procedures in production.** Exclude tests that
  delete shadow copies/backups (e.g. T1490), encrypt or wipe files, disable security
  tools, dump real credentials to disk, or send data outside the organisation.
  If such a technique must be validated, do it in the lab only.
- **A detection is validated only by evidence:** the raw telemetry event and the alert
  (ID, time, rule name) captured for the test ID. "The EDR probably saw it" is a
  failed test.
- **Never add permanent security-tool exclusions to make a test run.** Temporary,
  scoped exclusions need approval and are removed at the end (record both).

## Workflow

1. **Select techniques**: from an incident, a threat-intel profile (`threat-intel-ioc`),
   or coverage gaps (`/coverage`). Prioritise techniques used by actors relevant to you.
2. **Write test cases** (template below) with the *expected* telemetry and alert
   before running anything.
3. **Paperwork**: authorisation, rules of engagement, change ticket, SOC deconfliction.
4. **Lab run**: execute, capture telemetry and alerts, run cleanup, revert snapshot.
5. **Fix in the lab** what failed (missing log source, parser, rule logic), rerun.
6. **Production run** (if approved): small scope, business hours, operator watching
   the console, cleanup verified.
7. **Score** each test, update the coverage layer, file gaps to
   `detection-engineering`, and schedule a regression rerun.

## Rules of engagement checklist

- [ ] Scope: hosts, OUs/subscriptions, user accounts (dedicated test accounts only)
- [ ] Techniques and exact procedures (test GUID / ability ID / plan step)
- [ ] Time window and time zone; operators named
- [ ] Out of scope: production data, customer systems, third-party services
- [ ] Stop conditions: unexpected impact, real incident detected, service degradation
- [ ] Communications: SOC lead / white cell, IT owner of the hosts, emergency contact
- [ ] Evidence storage location and retention
- [ ] Sign-off: system owner, security lead, change board (for production)

## Atomic Red Team

Atomic tests live in the `atomics/` folder of the redcanaryco/atomic-red-team project,
one YAML per technique (e.g. `atomics/T1003.001/T1003.001.yaml`), each test with an
`auto_generated_guid`, executor, input arguments, prerequisites and cleanup command.
Install the `Invoke-AtomicRedTeam` PowerShell module following the project's wiki,
on lab hosts and approved test hosts only (the atomics folder itself triggers AV/EDR).

```powershell
# Inspect before running: what will execute, what it needs, how it cleans up
Invoke-AtomicTest T1059.001 -ShowDetailsBrief
Invoke-AtomicTest T1059.001 -TestNumbers 1 -ShowDetails
Invoke-AtomicTest T1059.001 -TestNumbers 1 -CheckPrereqs
Invoke-AtomicTest T1059.001 -TestNumbers 1 -GetPrereqs     # may download tools: review first

# Run one test, log execution (timestamp, technique, test, host, user) for correlation
Invoke-AtomicTest T1059.001 -TestNumbers 1 -ExecutionLogPath C:\PurpleLogs\PT-2026-014.csv

# Always clean up and verify
Invoke-AtomicTest T1059.001 -TestNumbers 1 -Cleanup
```

- Use `-TestNames` or `-TestGuids` to pin exact tests; numbering can change between
  versions of the atomics. Pin the atomics repo version (commit) in the test plan.
- `-InputArgs @{ ... }` overrides defaults (e.g. a lab file path); never point
  arguments at real user data.
- Remote execution uses `-Session` with a PowerShell remoting session; that remoting
  itself generates telemetry, so note it to avoid scoring it as the technique.
- Read the test's `executor.command`: some "harmless" tests modify registry run keys,
  services or firewall rules; ensure cleanup exists and works.

## MITRE Caldera

- Server with agents (e.g. Sandcat) on lab hosts; **abilities** (single procedures,
  mapped to ATT&CK) chained into **adversary profiles**; an **operation** runs a
  profile against an agent group. Plugins include stockpile (stock abilities),
  atomic (imports Atomic Red Team), emu (CTID emulation plans), response (blue).
- Change default credentials and config before use; never expose the server to the
  Internet; run it in the lab network.
- Use operation *obfuscators* "plain-text" for validation runs so telemetry is
  readable; export the operation report (ability, command, timestamp, host) for scoring.

## CTID Adversary Emulation Library

- Full emulation plans (e.g. APT29, FIN6, FIN7, menuPass, Carbanak, Sandworm,
  Wizard Spider) describe intelligence summary, operational flow, and step-by-step
  procedures. Use them in the lab to test detection across a whole intrusion chain.
- **Micro emulation plans** target compound behaviours (e.g. web shells, process
  injection, named pipes, AD enumeration) and are easier to run as regression tests.
- Respect each plan's prerequisites and the infrastructure it assumes; do not stand up
  its C2 components outside the lab.

## Test-case template

```markdown
### PT-2026-014 — T1059.001 PowerShell: encoded command
- ATT&CK: T1059.001 (Execution)            Threat link: <report/case ID>
- Procedure: Atomic T1059.001 test "<name>" (GUID <auto_generated_guid>), atomics commit <sha>
- Host / account: LAB-WIN11-03 / lab\pt-user (non-admin)
- Preconditions: Defender for Endpoint policy "Workstations"; PS logging GPO applied
- Expected telemetry:
  - DeviceProcessEvents: powershell.exe with -EncodedCommand / -enc
  - Microsoft-Windows-PowerShell/Operational 4104 with decoded script block
  - Sysmon 1 (process create) with parent process
- Expected alert: Sentinel rule "Encoded PowerShell from Office/WScript parent" (Medium)
- Executed (UTC): 2026-02-03T10:14:05Z   Operator: <name>
- Observed telemetry: <event IDs, table, record IDs / screenshots>
- Observed alert: <alert ID, rule, time, severity> or "none"
- Outcome: Blocked | Alerted | Logged-only | Not observed | Partial
- Time to alert: <minutes>
- Cleanup verified: yes/no (how)
- Gap / action: <ticket to detection-engineering, owner, due>
```

## Scoring

| Outcome | Meaning | Next step |
|---|---|---|
| Blocked (prevented) | Control stopped execution; alert raised | Confirm the block also alerts the SOC |
| Alerted | Correct alert, correct severity, actionable context | Record time-to-alert; done |
| Alerted (low fidelity) | Alert fired but wrong severity/name or too generic to triage | Tune rule (`detection-engineering`) |
| Logged only | Telemetry present in SIEM/EDR, no alert | Write/enable a detection; test again |
| Not observed | No telemetry in the SIEM | Fix logging (`logging-coverage`): source, policy, parser, ingestion |
| Inconclusive | Test failed to execute or prerequisites missing | Fix test, rerun; do not score as detected |

- Measure **time to alert** (execution timestamp to alert creation) and whether the
  alert reached the queue an analyst actually watches.
- Score the *procedure*, not the technique: one PowerShell test passing does not mean
  T1059.001 is covered. Record coverage as "procedures tested / passed".
- Colour an ATT&CK Navigator layer (or VECTR / DeTT&CT) with outcomes and test dates;
  stale results (older than your regression interval) are shown as unknown.

```kql
// Correlate a test window with telemetry and alerts on the test host (Defender XDR; adjust host and time)
let host = "lab-win11-03"; let t0 = datetime(2026-02-03T10:10:00Z); let t1 = datetime(2026-02-03T10:40:00Z);
union
 (DeviceProcessEvents | where Timestamp between (t0 .. t1) and DeviceName startswith host
   | project Timestamp, Src="process", FileName, ProcessCommandLine, InitiatingProcessFileName),
 (AlertEvidence | where Timestamp between (t0 .. t1) and DeviceName startswith host
   | project Timestamp, Src="alert", Title, AlertId, Severity)
| order by Timestamp asc
```

## False positives & benign look-alikes

- Alerts caused by the **test harness** (PowerShell remoting, the Atomic module load,
  Caldera agent beacon) are not detections of the technique; score only the alert
  tied to the procedure's behaviour.
- A generic "suspicious PowerShell" alert that fires for every test is low fidelity:
  it proves telemetry, not a specific detection.
- Real attacker activity during a test window: if anything happens outside the test's
  hosts, accounts or procedures, stop and treat it as a real incident (`alert-triage`).
- AV signature hits on the atomics folder at install time are expected and not a
  validation of the technique.

## Pitfalls

- Testing only as local admin with EDR in audit/passive mode and reporting it as
  production coverage.
- Lab telemetry pipeline differs from production (different policy, parser, table):
  a lab pass proves nothing about production.
- Forgetting cleanup: leftover run keys, services or test accounts later trigger real
  investigations or become real persistence.
- Running `-GetPrereqs` on production: it downloads third-party tools.
- Scoring "detected" from memory instead of captured alert IDs.
- One-off exercises: detections regress after agent, parser or rule changes; schedule
  reruns.

## Output

- Signed test plan (scope, RoE, test cases with expected telemetry/alert).
- Results table per test case with evidence references and outcome score.
- ATT&CK coverage layer (Navigator JSON / VECTR export) with test dates.
- Gap tickets to `detection-engineering` (logic) and `logging-coverage` (telemetry),
  each with the test case to rerun as acceptance criteria; Sigma drafts via
  `sigma-rules` / `/sigma`. Plan an exercise with `/purple`; check coverage with
  `/coverage`.

## References

- MITRE ATT&CK (https://attack.mitre.org/) and ATT&CK Navigator.
- Red Canary: Atomic Red Team and Invoke-AtomicRedTeam documentation (project wiki).
- MITRE Caldera documentation.
- Center for Threat-Informed Defense: Adversary Emulation Library, Micro Emulation
  Plans, "Purple Teaming" and ATT&CK-based SOC assessment resources.
- Security Risk Advisors: VECTR documentation.
- MITRE ATT&CK Evaluations methodology (detection categories) for scoring ideas.
