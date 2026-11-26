---
description: "MITRE ATT&CK detection-coverage gap analysis: map rules and telemetry to techniques, score coverage honestly, rank gaps by threat relevance, and optionally emit an ATT&CK Navigator layer (layer format 4.5, enterprise-attack). Usage: /coverage [--rules <dir|export>] [--threat <actor|ransomware|cloud|report>] [--navigator <out.json>]"
argument-hint: "[--rules <dir|export>] [--telemetry <inventory>] [--threat <profile>] [--after-incident <case-folder>] [--navigator <out.json>]"
---

# /coverage

Answers "which attacker techniques would we actually see?" Coverage is measured per
technique from the rules you have, the data they need, and whether they were tested
- not from rule names.

Input: `$ARGUMENTS`

## Usage

```
/coverage --rules detections/ --navigator out/coverage-layer.json
/coverage --rules exports/sentinel-analytics.json --threat ransomware
/coverage --telemetry docs/log-sources.md --threat "cloud control plane"
/coverage --after-incident cases/2026-11-25-ws0142-lsass   # were the case's techniques detected?
```

## Skills to load

- Always: `logging-coverage`, `detection-engineering`
- Validation status and test plans: `purple-team-validation`
- Rule formats: `sigma-rules`, `kql-sentinel-defender`, `spl-splunk`, `elastic-eql-esql`
- Threat profile from intel: `threat-intel-ioc`

## Evidence gate

- A technique counts as **covered** only if a rule exists, its data source is actually
  collected on the relevant assets, and it has a recorded true-positive test (or real
  TP) within the last 12 months. Otherwise it is at most *partial*.
- Rule metadata tags (`attack.t1059.001`) are claims; spot-check the logic before
  trusting the mapping.
- Telemetry presence is verified by a query (count of events in the last 7 days), not by
  the existence of a connector.

## Scoring

| Score | Meaning |
|---|---|
| 0 - None | No rule, or no data source for it |
| 1 - Telemetry only | Data collected and huntable; no rule |
| 2 - Rule, untested | Rule deployed; data present; no TP test recorded |
| 3 - Rule, validated | Rule fired on a TP test or real incident; baseline tuned |
| 4 - Validated + response | Score 3 plus a triage guide / automated enrichment in place |

Note sub-technique granularity: a rule for T1003.001 does not cover T1003.006.

## Procedure

1. **Inventory rules**: parse the rule directory or export; extract ATT&CK tags; where
   missing, map from logic and mark as inferred.
2. **Inventory telemetry**: per data source, which assets send it and what fields are
   populated (`logging-coverage`). Record coverage percentages per asset class.
3. **Validation status**: join with purple-team results / test logs (`/purple`).
4. **Score** each technique (table above).
5. **Threat-weight**: pick the relevant technique set (named actor or campaign from a
   cited report, ransomware playbooks, cloud matrix, techniques seen in your own
   incidents). Gaps in that set rank first.
6. **Recommend** the next 5-10 items: logging fixes first (they unblock many
   techniques), then detections (`/detect`), then validation (`/purple`).

## Output format

```markdown
## ATT&CK coverage: <scope>    as of <UTC date>    rules: N    techniques scored: N
### Summary by tactic
| Tactic | Techniques in scope | Score >= 3 | Score 2 | Score 1 | Score 0 |
### Technique detail
| Technique | Name | Score | Rules | Data sources (present?) | Last TP test | Notes |
|---|---|---|---|---|---|---|
| T1003.001 | LSASS Memory | 3 | win_lsass_access | Sysmon 10 (92% of servers) | 2026-10-02 | no coverage on 8% servers |
### Top gaps for <threat profile> and recommended actions
```

## ATT&CK Navigator layer (`--navigator <file>`)

Emit valid JSON using layer format **4.5** and domain **enterprise-attack**. One entry
per scored technique; `tactic` uses ATT&CK tactic short names (`credential-access`,
`lateral-movement`, ...). Set `versions.attack` and `versions.navigator` to match the
Navigator instance and ATT&CK release the organisation uses (values below are examples).

```json
{
  "name": "Detection coverage - <scope> - 2026-11-25",
  "versions": { "attack": "16", "navigator": "5.1.0", "layer": "4.5" },
  "domain": "enterprise-attack",
  "description": "Scores: 0 none, 1 telemetry only, 2 rule untested, 3 rule validated, 4 validated + response.",
  "sorting": 0,
  "layout": { "layout": "side", "showID": true, "showName": true },
  "hideDisabled": false,
  "techniques": [
    { "techniqueID": "T1003.001", "tactic": "credential-access", "score": 3, "color": "",
      "comment": "win_lsass_access; TP test 2026-10-02", "enabled": true,
      "metadata": [ { "name": "rules", "value": "win_lsass_access" } ], "showSubtechniques": false },
    { "techniqueID": "T1021.002", "tactic": "lateral-movement", "score": 1, "color": "",
      "comment": "4624/5145 collected; no rule", "enabled": true, "metadata": [], "showSubtechniques": false }
  ],
  "gradient": { "colors": ["#ff6666", "#ffe766", "#8ec843"], "minValue": 0, "maxValue": 4 },
  "legendItems": [
    { "label": "0 none", "color": "#ff6666" },
    { "label": "4 validated + response", "color": "#8ec843" }
  ],
  "showTacticRowBackground": false,
  "selectTechniquesAcrossTactics": true,
  "selectSubtechniquesWithParent": false
}
```

Rules for the layer: only technique IDs that exist in the chosen ATT&CK version
(check deprecated/revoked IDs); a technique under several tactics gets one entry per
tactic; leave unscored techniques out rather than scoring them 0 by default, unless
the user asks for an explicit zero-baseline. Validate by loading it in Navigator.

## Gates and safety

- Present coverage honestly: report "rule exists but untested" separately; do not
  inflate scores for management reporting.
- The layer and gap list reveal defensive blind spots: treat as TLP:AMBER (internal) at minimum.
