---
description: "Plan a purple-team detection-validation exercise using published test procedures (e.g. Atomic Red Team) in a lab or under written change approval: scope, safety, expected telemetry, pass/fail criteria, results. Usage: /purple plan <T####|rule|scenario> [--env lab|prod-approved] | /purple results <results-file>"
argument-hint: "plan <T####[.###] | rule name | scenario> [--env lab|prod-approved] | results <file>"
---

# /purple

Prove detections work by running known, published test procedures and checking that
the expected telemetry, alert and response happen. This is validation, not attack
simulation for its own sake: every test maps to a detection hypothesis and ends in a
pass/fail with a fix.

Input: `$ARGUMENTS`

## Usage

```
/purple plan T1003.001 --env lab
/purple plan "win_lsass_access" --env prod-approved
/purple plan "ransomware precursors: shadow copy deletion, service stop, mass rename" --env lab
/purple results exercises/2026-11-25-cred-access-results.md
```

## Skills to load

- Always: `purple-team-validation`, `detection-engineering`, `logging-coverage`
- Technique context: the matching `hunt-*` skill (see `/hunt` routing)
- Query language to verify telemetry: `kql-sentinel-defender`, `spl-splunk`, `elastic-eql-esql`

## Scope and safety rules (hard)

- Use **well-known, published procedures** only (Atomic Red Team tests, vendor-provided
  test tools, documented `MITRE ATT&CK` procedure examples). No custom malware, no
  evasion techniques, no testing against systems the operator does not own or manage.
- **Environment:** a lab by default. Production only with written change approval
  naming hosts, time window, tests, rollback and contacts (`--env prod-approved`); record
  the approval reference in the plan.
- Notify the SOC / MSSP before execution (or run as a declared blind test with a named
  white-cell contact who can stop it), so no real incident response is triggered by mistake.
- Run each test's **cleanup** and verify it. Note any test that changes security
  settings, creates accounts, or touches credentials and how it is reverted.
- Never run destructive tests (encryption, wiping, mass deletion) outside an isolated lab.

## Evidence gate

A test result is recorded as **Pass** only if: the expected raw telemetry was found
(query + count), the rule fired (alert ID / time), and the alert reached the analyst
queue with correct severity and entities. Partial results are recorded as such.

## Procedure - plan

1. **Objective.** Which detections/techniques are being validated and why now (new
   rule, coverage gap from `/coverage`, lesson from an incident).
2. **Select tests** per technique: test identifier and name from the published source,
   executor (powershell / command_prompt / bash), prerequisites, cleanup command.
   Prefer several variants per technique (different binaries/paths) to test rule robustness.
3. **Expected observables** per test: event IDs / tables / fields, the rule that should
   fire, expected severity, expected time to alert.
4. **Run sheet**: order, host, operator, start/stop UTC, abort criteria, contacts.
5. **Approval block** filled before execution.

## Plan format

```markdown
## Purple exercise: <name>    env: <lab|prod-approved>    window (UTC): <start> -> <end>
**Approval ref:** <change ticket / email ID>    **White cell:** <name, contact>    **SOC notified:** <yes, by whom>
| # | ATT&CK | Test (source + ID/name) | Host | Expected telemetry | Expected rule / severity | Cleanup | Risk |
|---|---|---|---|---|---|---|---|
| 1 | T1003.001 | Atomic Red Team T1003.001 - <test name from the atomics file> | LAB-WIN11-01 | Sysmon 10 TargetImage lsass.exe, GrantedAccess 0x1010 | win_lsass_access / High | delete dump file | Low (lab) |
**Abort criteria:** unexpected impact on non-test hosts, real alert on unrelated host, operator request.
```

Copy test names and IDs from the published source the operator uses; do not invent
test numbers.

## Procedure - results

For each test: executed at (UTC), telemetry found (query + count), alert fired
(ID, time, latency), triage outcome, verdict, root cause for failures (no data /
parsing / rule logic / threshold / alert routing), fix owner.

```markdown
| # | Technique | Executed (UTC) | Telemetry | Alert | Latency | Result | Root cause | Fix (-> /detect, logging) | Owner |
|---|---|---|---|---|---|---|---|---|---|
| 1 | T1003.001 | 2026-11-25T13:02:10Z | yes (Sysmon 10, 1 event) | yes, ALRT-882 | 4 min | Pass | - | - | - |
```

Then feed scores back to `/coverage` and failed items to `/detect`.

## Case integration

Exercises are not incidents and should not create case folders. If an exercise
uncovers real malicious activity, stop the exercise and open `/ir`.
