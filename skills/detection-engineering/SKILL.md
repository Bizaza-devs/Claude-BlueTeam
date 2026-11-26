---
name: detection-engineering
description: Detection-as-code lifecycle for SOC and detection engineers - turning an attacker behaviour into a tested, tuned, version-controlled detection in any SIEM/EDR (Sentinel, Defender XDR, Splunk ES, Elastic Security, Sigma). Covers behaviour -> data source -> logic -> true-positive emulation (Atomic Red Team) -> 30-day baseline -> tuning -> deployment -> monitoring, MITRE ATT&CK mapping, Pyramid of Pain and detection maturity, alert fidelity metrics (precision, alerts per day, MTTD), rule naming and metadata schema, peer-review checklist, Git + CI pipelines for rules, and the Palantir Alerting & Detection Strategy (ADS) template. Use when asked to "write a detection for", "build an analytic", "tune a noisy rule", "review this detection", "set up detection-as-code", "measure alert quality", or to document a rule with an ADS.
---

# Detection engineering

A detection is a small piece of software that runs forever against changing data.
Treat it like software: requirements, tests, review, versioning, telemetry and
retirement. This skill is the lifecycle; the query-language skills
(`sigma-rules`, `kql-sentinel-defender`, `spl-splunk`, `elastic-eql-esql`,
`yara-rules`, `network-detection-suricata-zeek`) are the implementation.

## When to use

- A new threat report, incident finding or hunt result must become a standing detection.
- A rule is noisy, silent, or nobody knows what it is for.
- Building or auditing a detection-as-code repo and its CI.
- Reporting detection quality to management (precision, volume, MTTD, coverage).
- Writing the documentation (ADS) a triage analyst reads at 03:00.

## Ground rules

**A detection is not done until it fired on a true-positive test and was run
against 30 days of baseline.** Concretely, before a rule is enabled in production:

1. **Data exists.** The required log source is confirmed present, parsed and
   complete for the target scope (query the table/index for the last 24 h and
   count hosts) - see `logging-coverage`. No data, no detection; log a gap instead.
2. **True-positive evidence.** The rule matched a controlled emulation of the
   behaviour (Atomic Red Team test, a replayed sample log, or a real past incident)
   and the test artifact is stored with the rule.
3. **Baseline evidence.** The rule was run retroactively over at least 30 days
   (or the maximum retention, stated) and the hit count, top entities and
   projected alerts/day are recorded.
4. **Documented response.** An ADS (template below) exists with triage steps and
   known false positives. A rule without a response is a log line, not a detection.
5. **No silent tuning.** Every exclusion has a reason, an owner and a review date
   in the rule metadata.

Emulation runs only in a lab or on systems with written change approval
(see `purple-team-validation`).

## Workflow

1. **Define the behaviour, not the IOC.** Write one sentence: "Adversary uses X
   to achieve Y on Z." Map it to ATT&CK technique/sub-technique. Prefer the
   higher levels of the Pyramid of Pain (tools, TTPs) over hashes and IPs, which
   belong in `threat-intel-ioc` watchlists, not handcrafted rules.
2. **Research the technique.** Read the ATT&CK page, public procedure examples,
   existing open rules (SigmaHQ, Elastic detection-rules, Splunk security_content,
   Azure-Sentinel repo) - do not reinvent, do not copy blindly.
3. **Pick the data source.** Which event actually records the behaviour?
   (process creation with command line, registry value set, 4769, CloudTrail
   `CreateAccessKey`...). Note the field names in *your* schema. If several sources
   see it, choose the one hardest for the adversary to avoid and cheapest to keep.
4. **Write the logic in the portable form first** (Sigma where possible,
   `sigma-rules`), then convert or hand-write the platform query. Keep the core
   condition behavioural; put environment-specific exclusions in a separate,
   clearly named filter block or lookup.
5. **Test for true positives.** Emulate (Atomic Red Team test ID, or a published
   sample from Security-Datasets / EVTX-ATTACK-SAMPLES replayed into a test index).
   Confirm the rule fires and the alert carries the entities an analyst needs.
6. **Run the 30-day baseline.** Execute the query over history. Record: total hits,
   distinct hosts/users, top 10 parent processes / command lines / sources, and
   projected alerts per day. Classify each cluster of hits: TP, benign TP, FP.
7. **Tune.** Exclude by the most specific stable attribute (signed path +
   parent + command-line pattern), never by broad host or user unless the asset
   genuinely cannot exhibit the behaviour. Re-run the baseline after each change.
8. **Decide the delivery mode.** Alert (high fidelity), risk/score contribution
   (medium fidelity, see risk-based alerting in `spl-splunk`), or hunting query
   (low fidelity, scheduled review via `hunt-dispatch`). Not everything must page.
9. **Review and merge.** Peer review against the checklist below; CI must pass.
10. **Deploy** through the pipeline (never hand-edited in the console), set
    severity, entity mapping, grouping and suppression.
11. **Monitor.** Weekly: alert volume, precision from triage verdicts, last-fired
    date, and data-source health. Monthly: re-run the TP test (continuous
    validation). Rules that never fire need a health check, not applause.
12. **Retire or rewrite** when the data source changes, precision stays below the
    agreed floor, or the technique is covered better elsewhere.

## Behaviour -> data source -> logic (worked example)

| Step | Example: LSASS memory dump via comsvcs.dll (T1003.001) |
|---|---|
| Behaviour | Adversary runs `rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <lsass PID> <out> full` to dump credentials |
| Data source | Process creation with full command line (Sysmon 1, Security 4688 with command line, MDE `DeviceProcessEvents`); corroborate with Sysmon 10 (process access to lsass.exe) or a new `.dmp` file event |
| Logic | process image/original name is rundll32 AND command line contains `comsvcs` AND contains `minidump` (case-insensitive; also match `#24` ordinal form) |
| TP test | Atomic Red Team T1003.001 comsvcs test in an isolated lab VM |
| Baseline | Expect near-zero hits; any hit is high severity |
| Response | Isolate host per `incident-response` (capture memory first), reset credentials of users logged on, hunt with `hunt-credential-access` |

## ATT&CK mapping rules

- Map to the most specific sub-technique you can defend (`T1059.001`, not `T1059`).
- One rule may map to several techniques; list the primary first.
- Tag the tactic too (`attack.credential-access`) - coverage heat maps group by tactic.
- Mapping is a claim: the TP test must exercise the mapped technique.
- Keep the mapping in the rule metadata, not in a spreadsheet that drifts.
  Coverage is generated from the repo (ATT&CK Navigator layer) - see `/coverage`.
- Record **what the rule does not cover** (other procedures of the same technique)
  in the ADS "Blind spots" section. A green Navigator cell is not full coverage.

## Detection maturity

Use one ladder for every rule so coverage reports mean something:

| Level | Meaning | Minimum evidence |
|---|---|---|
| 0 - Idea | Behaviour + ATT&CK mapping written | ticket |
| 1 - Hunt | Query runs, results reviewed manually | saved hunting query |
| 2 - Tested | TP emulation fires; 30-day baseline recorded | test artifact + baseline numbers |
| 3 - Production | Alerting, ADS written, entity mapping, owner | merged PR, deployed by CI |
| 4 - Validated | Re-tested on schedule, precision tracked over 90 days | validation log, metrics |
| 5 - Resilient | Covers multiple procedures / survives renaming, obfuscation, alternate binaries | variant tests pass |

Organisation-level models to cite when reporting: the Pyramid of Pain (David
Bianco) for indicator durability and the Detection Maturity Level (DML) model
(Ryan Stillions) for "atomic IOCs -> tools -> TTPs -> behaviours".

## Alert fidelity metrics

| Metric | Definition | How to get it | Typical use |
|---|---|---|---|
| Precision | TP / (TP + FP) over a period; count benign TP separately | triage verdicts on closed alerts/incidents | floor per severity, e.g. agree a minimum for high/critical |
| Volume per day | alerts produced per rule per day (median and p95) | SIEM alert table | capacity planning; > analyst budget = demote to risk/hunt |
| MTTD | time from earliest malicious event to alert creation | incident timeline vs alert time | measure pipeline + schedule latency |
| MTTA / MTTT | alert creation -> acknowledged / triaged | case tool timestamps | SOC process, not rule quality |
| Last fired | days since last alert | SIEM | silent rules -> health check |
| Test pass rate | % of rules whose TP test fires this cycle | validation pipeline | detection health |
| Coverage | techniques with >= Level 3 rules / prioritised techniques | repo metadata | report gaps, not percentages of all of ATT&CK |

Set thresholds locally; there is no universal "good" precision. Report the
denominator (how many alerts were triaged) with every precision figure.

```kql
// Sentinel: per-rule volume and precision from incident classification (last 30d)
// Tune: Classification values depend on how your SOC closes incidents
SecurityIncident
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| mv-expand RuleId = RelatedAnalyticRuleIds to typeof(string)
| summarize Incidents = count(),
            TP  = countif(Classification == "TruePositive"),
            BTP = countif(Classification == "BenignPositive"),
            FP  = countif(Classification == "FalsePositive")
    by RuleId
| extend Precision = round(todouble(TP) / iff(TP + FP == 0, 1, TP + FP), 2),
         PerDay = round(Incidents / 30.0, 1)
| order by Incidents desc
```

## Naming and metadata schema

Name pattern: `<Platform/Scope> - <Tactic> - <What happened> [- <qualifier>]`,
for example `WIN - CredAccess - LSASS dump via comsvcs MiniDump`. The name
describes the observed behaviour, never the malware family unless the rule is
family-specific.

Required metadata (keep in the rule file or a sidecar YAML):

```yaml
# detection metadata sidecar - adapt field names to your repo
id: 6f1c2a9e-3b7d-4c1e-9a55-0d2f8b7e4c10   # uuid4, never reused
name: WIN - CredAccess - LSASS dump via comsvcs MiniDump
status: production            # idea | hunt | tested | production | deprecated
maturity: 3
owner: detection-team@corp.example
attack: [T1003.001]
tactics: [credential-access]
data_sources: [sysmon:1, security:4688, mde:DeviceProcessEvents]
severity: high
platforms: [sentinel, defender-xdr, splunk]
tp_test: atomic:T1003.001 comsvcs test (lab-win11-01, 2026-11-20, fired)
baseline: {days: 30, hits: 0, projected_per_day: 0}
exclusions:
  - reason: backup agent dumps its own process via comsvcs
    match: parent=C:\Program Files\Vendor\agent.exe
    owner: j.doe
    review_by: 2027-02-01
ads: docs/ads/lsass-comsvcs.md
created: 2026-11-20
modified: 2026-11-20
```

## Rule review checklist

- [ ] Behaviour sentence and ATT&CK mapping present and defensible.
- [ ] Data source confirmed present for the intended scope (with counts).
- [ ] Logic uses case-insensitive matching where the platform is case-sensitive
      and handles both original file name and renamed binaries where possible.
- [ ] No leading/trailing wildcards that turn the rule into a full scan without need.
- [ ] Exclusions are specific (path + signer/parent + pattern), each with reason,
      owner, review date. No `user != "admin"` style blanket exclusions.
- [ ] TP test artifact attached and reproducible.
- [ ] 30-day baseline numbers recorded; projected volume fits the analyst budget.
- [ ] Output includes the entities triage needs (host, user, process, command
      line, parent, hash, source IP) and maps them to SIEM entities.
- [ ] Time window and schedule do not leave gaps (lookback >= frequency + ingestion delay).
- [ ] Severity matches impact and fidelity, not fear.
- [ ] ADS written; response steps reference real playbooks (`alert-triage`, `incident-response`).
- [ ] Rule converts/validates in CI for every target platform.

## Version control and CI

Repository layout (one pattern that works; adapt to your SIEM tooling):

```
rules/
  sigma/<tactic>/<rule>.yml          portable source of truth
  sentinel/<rule>.yaml               analytics rule (ARM/YAML) or generated
  splunk/<rule>.yml                  e.g. contentctl-style detection YAML
  elastic/<rule>.toml                detection-rules style TOML
tests/
  <rule-id>/events.json              TP sample events
  <rule-id>/expected.yml             expected hit count
docs/ads/<rule>.md
.github/workflows/detections.yml
```

```yaml
# GitHub Actions sketch: validate and convert Sigma on every PR
# Tune: pin versions; add platform-specific validators (KQL parse, Splunk contentctl, Elastic detection-rules CLI)
name: detections
on: [pull_request]
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install sigma-cli
      - run: sigma plugin install splunk && sigma plugin install elasticsearch
      - run: sigma check rules/sigma/
      - run: sigma convert -t splunk -p splunk_windows rules/sigma/ > /dev/null
      - run: python scripts/check_metadata.py rules/   # uuid unique, owner, attack tags, review dates not expired
```

Pipeline gates that pay off:
- Schema/metadata lint (unique UUIDs, required fields, expired exclusion review dates fail the build).
- Conversion for every target backend succeeds.
- Replay tests: load `tests/<id>/events.json` into a test index/workspace and assert the expected hit count.
- Deployment only from the main branch, by a service principal, with the commit SHA written into the rule description so the console shows which version is live.
- Drift check: nightly export of deployed rules diffed against the repo; console edits are reverted or back-ported.

Vendor tooling exists for each platform (Microsoft Sentinel Repositories,
Splunk `contentctl`, Elastic `detection-rules`); use it rather than custom
deployment scripts where it fits.

## ADS (Alerting & Detection Strategy) template

The ADS framework was published by Palantir's incident response team. Keep one
per production rule:

```markdown
# ADS: <rule name>
## Goal
What behaviour this detects and why it matters (one paragraph).
## Categorization
ATT&CK tactic / technique / sub-technique IDs.
## Strategy abstract
High-level how: data source, logic, enrichment, where it alerts.
## Technical context
What the analyst must know to understand the alert: how the technique works,
normal vs abnormal values of the key fields, relevant system internals.
## Blind spots and assumptions
Procedures not covered, data that may be missing, evasions known to bypass it.
## False positives
Known benign sources, how to recognise them, which are excluded and why.
## Validation
Exact steps (or Atomic Red Team test ID) to produce a true positive; expected output.
## Priority
Severity levels and what raises/lowers them (asset criticality, privileged user).
## Response
Triage steps, decision table (TP / BTP / FP / needs data), escalation path,
containment approvals required.
## Additional resources
ATT&CK page, vendor docs, internal runbooks, related rules.
```

## False positives & benign look-alikes

| Pattern | Why it looks malicious | How to handle |
|---|---|---|
| Admin tooling (SCCM/Intune, RMM, backup agents) | Runs scripts, dumps processes, creates services | Exclude by signed path + parent + exact pattern; confirm with asset owner |
| Security products | EDR/AV read LSASS, inject, hook | Exclude by vendor signer and install path, not process name alone |
| Developers and CI runners | Encoded PowerShell, compilers, network tools | Scope exclusion to build hosts/accounts, keep alerting on servers |
| Red team / pentest | True behaviour, sanctioned | Benign TP; require engagement ID; never permanently exclude tester accounts |
| Software updates | Mass new binaries, new services, new scheduled tasks | Correlate with change calendar; short-lived suppression with expiry |

Decision support for tuning a cluster of baseline hits:

| Verdict | Evidence that moves it |
|---|---|
| True Positive | Behaviour unexplained by owner, no change record, other suspicious activity on entity |
| Benign True Positive | Behaviour real and matches the logic, explained by sanctioned activity (pentest, admin) |
| False Positive | Logic matched something that is not the behaviour (bad pattern, field mis-parse) - fix the logic, not an exclusion |
| Needs more data | Missing parent/command line/user; enrich or improve logging before deciding |

## Pitfalls

- Writing for the sample you have instead of the behaviour: one string from one
  report gets renamed tomorrow.
- Excluding by `ProcessName` only - attackers name their binary `MsMpEng.exe`.
- Schedule gaps: a 5-minute rule with a 5-minute lookback misses late-arriving
  events; add ingestion delay to the lookback (or use NRT/streaming where offered).
- Case sensitivity: Splunk field values are case-insensitive in `search`, but
  `where` and ES|QL comparisons are case-sensitive; KQL `==` is case-sensitive, `=~` is not.
- Measuring success by number of rules. A hundred untested rules are a liability.
- Exclusions that never expire and silently grow into blind spots.
- Testing only in the lab with a data shape that differs from production parsing.
- Severity inflation - everything "high" means nothing is.

## Output

- A rule in the repo (portable + platform form), metadata sidecar, TP test
  artifact, baseline numbers, and an ADS - delivered as a PR.
- For tuning requests: before/after baseline table and the exclusion diff with reasons.
- For quality reviews: per-rule metrics table and a retire/rewrite/keep list.
- Hand-offs: `/detect` drives this skill end to end; `/sigma` for the rule body;
  `/purple` and `purple-team-validation` for emulation; `/coverage` and
  `logging-coverage` for gap analysis; `alert-triage` consumes the ADS.

## References

- MITRE ATT&CK: https://attack.mitre.org/ (techniques, data sources / detection guidance, Navigator)
- Palantir, "Alerting and Detection Strategy Framework" (ADS)
- David Bianco, "The Pyramid of Pain"; Ryan Stillions, "The DML Model"
- Atomic Red Team (Red Canary); OTRF Security-Datasets; EVTX-ATTACK-SAMPLES
- SigmaHQ rule repository and specification; Elastic `detection-rules`; Splunk `security_content`; Azure-Sentinel GitHub repository
- NIST SP 800-61 Rev. 3 (incident response, detection and analysis)
