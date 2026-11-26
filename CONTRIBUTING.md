# Contributing & skill authoring guide

This file is the single source of truth for how skills, commands and agents in
`claude-blueteam` are written. Every contributor (human or agent) follows it.

## What this bundle is

A defensive-security (blue team) skill bundle for Claude Code: SOC alert triage,
incident response, detection engineering, threat hunting, digital forensics,
hardening, vulnerability prioritisation, threat intel and reporting. It is the
defensive counterpart of offensive bundles such as Claude-BugHunter.

The operator is a defender working on systems they are responsible for
(their employer's estate, a client under an IR/MSSP contract, a lab). Skills
never help attack third parties. Malware handling is analysis-only: triage,
static/dynamic analysis in an isolated sandbox, signature writing. No
weaponisation, no evasion guidance for attackers. Purple-team content is
limited to running well-known, published test procedures (e.g. Atomic Red Team)
in a lab or with written change approval, to validate detections.

## Layout

```
skills/<skill-name>/SKILL.md     one folder per skill, folder name == frontmatter name
skills/<skill-name>/references/  optional extra files (cheat sheets, query packs)
commands/<command>.md            slash commands
agents/<agent>.md                subagents
scripts/                         installers, case scaffolder, lint
```

## SKILL.md format

```markdown
---
name: <kebab-case, identical to folder name>
description: <one paragraph, 300-900 chars. What it covers + concrete trigger phrases + "Use when ...". This is what makes the skill auto-load, so name the tools, log sources, event IDs, ATT&CK techniques and situations a defender would type.>
---

# <Human title>

## When to use
## Ground rules            <- the evidence gate (see below)
## Workflow                <- numbered, opinionated, the order a senior analyst works in
## <Domain sections>       <- queries, artifacts, decision tables, playbook steps
## False positives & benign look-alikes
## Pitfalls
## Output                  <- what the skill produces and the hand-off (other skills / commands)
## References              <- ATT&CK IDs, NIST/CISA/vendor docs by name
```

Only `name` and `description` go in frontmatter (keeps the skills portable to
other agent harnesses).

### Quality bar

- **Target length 200-450 lines.** Dense, practical, no filler or marketing.
- **Concrete over generic.** Real Windows Event IDs, Sysmon IDs, registry paths,
  artifact locations, CloudTrail `eventName`s, Entra/M365 operation names,
  real table and field names (`DeviceProcessEvents`, `SigninLogs`,
  `index=... sourcetype=...`, ECS fields).
- **Every query is labelled with its platform** in the code-fence info string
  or a heading (`kql`, `spl`, `sigma` as yaml, `esql`/`eql`, `yara`, `bash`,
  `powershell`). Add a one-line comment saying what it finds and what to tune.
- **Say where a query needs local tuning** (index names, allowlists,
  thresholds) instead of pretending it is drop-in.
- **Map to MITRE ATT&CK** technique IDs (e.g. `T1003.001`) where relevant.
- **Decision tables** for verdicts: True Positive / Benign True Positive /
  False Positive / Needs more data, with the evidence that moves each.
- **No invented facts.** No fake CVE numbers, fake URLs, fake statistics or
  made-up "real case" anecdotes. Cite documents by name (e.g. "NIST SP 800-61
  Rev. 3", "CISA #StopRansomware guide", "Microsoft Learn: SigninLogs schema");
  include a URL only if it is a stable, well-known root you are certain of
  (https://attack.mitre.org/techniques/T1003/001/ style is fine).
- **Safety:** containment steps warn about blast radius and evidence loss
  (e.g. "isolate, do not power off, capture memory first"). Destructive actions
  (disabling accounts, wiping, blocking at the edge) are marked as requiring
  incident-commander / change approval.

### The ground-rules (evidence gate) section

Each skill opens with its defensive equivalent of "OOB or it didn't happen":
the minimum evidence required before a verdict, a containment action, or a
claim in a report. Examples: "No TP verdict on a single alert without a
corroborating second source", "Hash + acquisition time + who before any
analysis of an evidence file", "A detection is not done until it fired on a
true positive test and was run against 30 days of baseline".

### Cross-references

Refer to sibling skills by their exact name in backticks (`alert-triage`) and to
commands with a slash (`/triage`). The full catalogue is below; do not invent
names outside it.

## Skill catalogue (v1.0)

| Layer | Skills |
|---|---|
| Think | `blueteam-methodology`, `defender-mindset` |
| Triage & respond | `alert-triage`, `incident-response`, `ir-ransomware`, `ir-bec-m365`, `ir-cloud-aws`, `ir-azure-entra`, `ir-insider-threat`, `phishing-analysis` |
| Detect | `detection-engineering`, `sigma-rules`, `kql-sentinel-defender`, `spl-splunk`, `elastic-eql-esql`, `yara-rules`, `network-detection-suricata-zeek`, `logging-coverage` |
| Hunt (Windows / identity) | `hunt-dispatch`, `hunt-windows-persistence`, `hunt-lateral-movement`, `hunt-credential-access`, `hunt-ad-identity-attacks`, `hunt-lolbins` |
| Hunt (network / Linux / cloud) | `hunt-c2-beaconing`, `hunt-exfiltration`, `hunt-linux-persistence`, `hunt-webshells`, `hunt-cloud-control-plane`, `hunt-k8s-runtime` |
| Forensics | `windows-forensics`, `linux-forensics`, `memory-forensics`, `timeline-analysis`, `malware-triage`, `evidence-handling` |
| Harden & prioritise | `hardening-windows-ad`, `hardening-m365-entra`, `hardening-linux`, `hardening-cloud`, `vuln-prioritization` |
| Intel, validate, report | `threat-intel-ioc`, `purple-team-validation`, `ir-report-writing`, `post-incident-review` |

## Commands

| Command | Purpose |
|---|---|
| `/triage` | Fast verdict on one alert (TP / BTP / FP / escalate) |
| `/investigate` | Structured deep-dive on an entity (user, host, IP, hash) |
| `/ir` | Open an incident case folder and run the IR lifecycle |
| `/contain` | Containment plan with blast-radius and approval gates |
| `/hunt` | Hypothesis-driven hunt; routes through `hunt-dispatch` |
| `/detect` | Turn a behaviour into a tested detection (any SIEM) |
| `/sigma` | Write or convert a Sigma rule |
| `/phish` | Analyse a reported email (headers, URLs, attachments) |
| `/ioc` | Extract, defang, enrich and pivot on indicators |
| `/forensics` | Artifact-driven triage of a host or image |
| `/timeline` | Build a super-timeline / incident timeline |
| `/harden` | Hardening review of a system or tenant |
| `/coverage` | ATT&CK detection-coverage gap analysis |
| `/purple` | Plan a detection-validation exercise |
| `/report` | Incident report (exec + technical) |
| `/postmortem` | Blameless post-incident review |

## Agents

`soc-analyst`, `incident-commander`, `detection-engineer`, `threat-hunter`,
`forensic-analyst` — each a focused subagent that loads the matching skills.

## Checks before a PR

```bash
python scripts/lint_skills.py      # frontmatter, names, length, cross-references
```
