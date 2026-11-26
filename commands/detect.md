---
description: "Turn an attacker behaviour into a tested, tuned, documented detection for any SIEM/EDR (KQL, SPL, ES|QL/EQL, Sigma, YARA, Suricata). Usage: /detect \"<behaviour>\" | /detect <ATT&CK ID> [--platform sentinel|defender|splunk|elastic|sigma|yara|suricata] [--from-hunt <file>]"
argument-hint: "\"<behaviour>\" | <T####[.###]> [--platform sentinel|defender|splunk|elastic|sigma|yara|suricata] [--from-hunt <file>]"
---

# /detect

Detection-as-code, end to end: behaviour -> data -> logic -> test -> baseline ->
tune -> document -> deploy request. The output is a rule an on-call analyst can act
on at 03:00, not just a query that returns rows.

Input: `$ARGUMENTS`

## Usage

```
/detect "rundll32 loading a DLL from a user-writable path" --platform defender
/detect T1558.003 --platform splunk
/detect "new inbox rule forwarding to an external domain" --platform sentinel
/detect --from-hunt hunts/2026-11-20-schtasks.md --platform sigma
```

No `--platform`: write Sigma first (portable), then the native query for the
organisation's SIEM if known.

## Skills to load

- Always: `detection-engineering`, `logging-coverage`
- Platform: `kql-sentinel-defender`, `spl-splunk`, `elastic-eql-esql`, `sigma-rules`,
  `yara-rules`, `network-detection-suricata-zeek`
- Behaviour context: the matching `hunt-*` skill (see `/hunt` routing)
- Validation: `purple-team-validation`

## Evidence gate

A detection is **not done** until:
1. it fired on a true-positive test (lab replay, Atomic Red Team test, or real historical
   event) - record which;
2. it was run against at least **30 days** of production baseline (or the full
   retention if shorter, stated) with the alert volume recorded;
3. every exclusion is justified and scoped as narrowly as possible.
Anything short of this ships as `status: experimental` with the gap named.

## Procedure

1. **Define the behaviour** precisely: what the attacker does, on what, and the
   observable. Map ATT&CK technique + sub-technique. Prefer behaviour over brittle
   indicators (hashes, single IPs) unless it is an IOC rule by design.
2. **Data source check** with `logging-coverage`: event IDs / tables / fields required
   (e.g. Sysmon 1 / `DeviceProcessEvents` / `process.command_line`), whether they are
   collected on the target population, and parsing quirks.
3. **Write the logic.** Start from the minimal reliable signal; add context joins
   (parent, signer, prevalence, user tier) to raise fidelity. Label every code block
   with its platform; comment what to tune (index names, allowlists, thresholds).
4. **True-positive test.** Run or replay the behaviour (`/purple` for the plan). Capture
   the event that fired. If you cannot test, say so.
5. **Baseline.** Run over 30 days; record hit count, distinct hosts/users, top
   contributors. Classify contributors: TP / BTP / FP.
6. **Tune.** Exclude by the most specific stable attribute (full path + signer +
   parent, not process name alone). Never exclude by user-writable fields an attacker
   controls without a second condition.
7. **Set severity and response.** Severity from impact x fidelity; write the triage
   steps (what to check first, what a TP looks like, the first containment option).
8. **Document and hand off** as a rule file plus the deployment request; propose a
   re-validation date.

## Output format

````markdown
## Detection: <name>
| Field | Value |
|---|---|
| ATT&CK | T1218.011 (Rundll32) |
| Platform | Microsoft Defender XDR advanced hunting (custom detection) |
| Data source | DeviceImageLoadEvents, DeviceProcessEvents |
| Status | experimental / test / stable |
| Severity | Medium |
| Expected volume | ~2/week after tuning (30-day baseline: 41 raw hits, 39 BTP excluded) |
| TP test | Atomic Red Team T1218.011 test #<n> in lab, fired 2026-11-24T13:02Z |
| Owner / review date | <team> / <date> |

### Logic
```kql
// Finds rundll32 loading DLLs from user-writable paths. Tune: add org-approved signers.
...
```

### Exclusions (each with reason and approver)
### False positives & benign look-alikes
### Triage guidance (for the analyst receiving the alert)
### Test evidence and baseline numbers
````

Also emit the rule as a file the user can commit (Sigma YAML, `.kql`, `.spl`,
`.toml`, `.yar`, `.rules`), with the path proposed, not written into another
contributor's directories without asking.

## Case integration

When created from an incident, reference the case ID in the rule metadata and add a
line to the case `notes.md` ("Detection <name> created to catch <behaviour>"). Do not
put sensitive case details (victim names, internal hostnames) into rule text that will
be shared.

## Gates and safety

- Testing uses published procedures in a lab or under written change approval
  (`purple-team-validation`). No live malware on production.
- Do not deploy directly to production SIEM/EDR from this command; produce the rule and
  a change request. Auto-response actions attached to a rule (isolation, account
  disable) need separate approval, as in `/contain`.
