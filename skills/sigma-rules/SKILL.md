---
name: sigma-rules
description: Writing, reviewing, testing and converting Sigma detection rules - the vendor-neutral YAML format for log-based detections. Covers the full rule specification (title, id uuid, status, description, references, logsource product/category/service, detection selections and filters, value modifiers contains / startswith / endswith / all / re / base64offset / cidr / windash, condition grammar, falsepositives, level, ATT&CK tags like attack.t1059.001), Sigma correlation rules, good vs bad rule examples, conversion with pySigma and sigma-cli to Splunk SPL, Microsoft Sentinel / Defender XDR KQL, Elasticsearch Lucene / EQL / ES|QL, local testing with Chainsaw, Hayabusa or Zircolite on EVTX, and common mistakes. Use when asked to "write a Sigma rule", "convert this Sigma to KQL/SPL", "why does my Sigma rule not match", "sigma convert", "pySigma pipeline", or to port a detection between SIEMs.
---

# Sigma rules

Sigma is to log detections what YARA is to files: a portable rule format that
backends compile into a SIEM query. Write once, convert per platform, but always
check the generated query - conversion is only as good as the field mapping.

## When to use

- A detection must run on more than one SIEM, or the SIEM may change.
- Publishing or sharing a detection (SigmaHQ style) with partners.
- Converting a public Sigma rule into Splunk / KQL / Elastic and debugging why it does not fire.
- Reviewing a Sigma rule in a PR (`detection-engineering` checklist + the specifics below).

## Ground rules

- **A converted rule is not tested until it has run on the target platform.**
  `sigma check` passing proves syntax, not that the field names exist in your index.
- **Every rule needs a true-positive sample** (log event that must match) and a
  30-day baseline run on the target SIEM before it moves past `status: test`
  (see `detection-engineering`).
- **Never trust a backend's field mapping blindly.** Print the converted query,
  compare each field to a real event from your environment.
- **Do not invent ATT&CK IDs.** Tag only techniques the rule actually detects.

## Workflow

1. Get a real event (or a published sample) of the behaviour - Sysmon 1 XML,
   4688, MDE row, CloudTrail JSON.
2. Pick the `logsource` that describes the event generically (`category: process_creation`,
   `product: windows`) rather than a vendor-specific service, so pipelines can map it.
3. Write the narrowest selection that captures the behaviour; add filters for
   known benign patterns in separate `filter_*` blocks.
4. `sigma check` the file; fix all errors, read the warnings.
5. Convert to each target with the correct pipeline; review the output query.
6. Run the converted query against the TP sample and against 30 days of production data.
7. Tune, update `falsepositives`, bump `modified`, set `status`, open the PR.

## Rule specification (Sigma 2.x)

```yaml
title: Rundll32 Comsvcs MiniDump of a Process              # short, behaviour-focused, < ~70 chars
id: 2b8e4a91-7f3c-4d2e-b6a1-9c0d5e7f1a23                   # uuid4; never reuse, never change after publish
related:                                                   # optional: link derived/obsolete rules
  - id: 00000000-0000-0000-0000-000000000000               # placeholder - put the real related rule id
    type: derived                                          # derived | obsolete | merged | renamed | similar
status: test                                               # stable | test | experimental | deprecated | unsupported
description: |
  Detects rundll32 invoking the MiniDump export of comsvcs.dll, commonly used
  to dump LSASS memory for credential theft.
references:
  - https://attack.mitre.org/techniques/T1003/001/
author: Blue Team
date: 2026-11-20                                           # YYYY-MM-DD in Sigma 2.x
modified: 2026-11-20
tags:
  - attack.credential-access
  - attack.t1003.001
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    - Image|endswith: '\rundll32.exe'
    - OriginalFileName: 'RUNDLL32.EXE'
  selection_cli:
    CommandLine|contains|all:
      - 'comsvcs'
      - 'minidump'
  selection_ordinal:
    CommandLine|contains|all:
      - 'comsvcs'
      - '#24'
  condition: selection_img and (selection_cli or selection_ordinal)
fields:                                                    # optional hint for analysts / output columns
  - CommandLine
  - ParentImage
  - User
falsepositives:
  - Unlikely; some backup or diagnostic tools - verify parent process and signer
level: high                                                # informational | low | medium | high | critical
```

Key semantics:

- **Lists of values** under one field = OR. **Keys inside one map** = AND.
  A **list of maps** (as in `selection_img`) = OR between the maps.
- `|all` turns a value list into AND (`CommandLine|contains|all`).
- Value matching is **case-insensitive** by default for plain strings; `|re` is
  case-sensitive unless you add `|re|i` (support varies by backend), and `|cased`
  forces case-sensitive plain matching.
- Wildcards `*` and `?` are allowed in plain values; escape literal ones with `\`.
  Prefer modifiers (`|contains`) over hand-written `*value*` - clearer and safer.
- `null` matches a missing/empty field; `|exists: true|false` tests presence.

### Value modifiers you will actually use

| Modifier | Meaning | Example |
|---|---|---|
| `contains` / `startswith` / `endswith` | substring / prefix / suffix | `Image\|endswith: '\powershell.exe'` |
| `all` | all listed values must match | `CommandLine\|contains\|all: [' -w ', 'hidden']` |
| `re` | regular expression (sub-modifiers `i`, `m`, `s`) | `CommandLine\|re: '\s-[eE][nN]?[cC]?\s'` |
| `windash` | also match `-`, `/` and Unicode dash variants of a flag | `CommandLine\|contains\|windash: ' -enc '` |
| `base64` | match the base64 encoding of the value (exact) | rarely useful alone |
| `base64offset` | match the value base64-encoded at any of the 3 alignments | `CommandLine\|base64offset\|contains: 'IEX'` |
| `utf16le` / `wide` | encode as UTF-16LE before base64 (PowerShell `-enc`) | `CommandLine\|wide\|base64offset\|contains: 'IEX ('` |
| `cidr` | IP in network range | `DestinationIp\|cidr: ['10.0.0.0/8', '192.168.0.0/16']` |
| `gt` / `gte` / `lt` / `lte` | numeric comparison | `EventID\|gte: 4624` (rarely needed) |
| `fieldref` | compare to another field's value | `TargetUserName\|fieldref: SubjectUserName` |
| `exists` | field present / absent | `ParentImage\|exists: false` |
| `expand` | placeholder expanded by a pipeline (e.g. `%admin_users%`) | environment-specific lists |

### Condition grammar

- Boolean: `and`, `or`, `not`, parentheses.
- Groups: `1 of selection_*`, `all of selection_*`, `1 of them`, `all of them`.
- Idiomatic shape: `selection and not 1 of filter_*`.
- The old aggregation syntax (`| count() by X > 5`) is deprecated; use
  **correlation rules** instead.

### Correlation rules (Sigma 2.x)

```yaml
# Sigma correlation: >= 10 failed logons for one target account from one source in 5 minutes
# Tune: threshold and timespan per environment; backend support varies (check sigma list targets)
title: Many Failed Logons For One Account
id: 7d3f0c2e-1a4b-4e8d-9f6a-2b5c8e1d0a47
status: test
correlation:
  type: event_count            # event_count | value_count | temporal | temporal_ordered
  rules:
    - failed_logon_rule        # references the base rule by its `name:` or id
  group-by:
    - TargetUserName
    - IpAddress
  timespan: 5m
  condition:
    gte: 10
level: medium
```

The base rule (separate document, `---` separated or separate file) carries
`name: failed_logon_rule` and selects `EventID: 4625`. Use `value_count` with
`field:` for "many distinct users from one IP" (password spray).

### Logsource cheat sheet (Windows)

| Behaviour | logsource | Typical source events |
|---|---|---|
| Process start | `category: process_creation` | Sysmon 1, Security 4688, MDE process events |
| Network connection | `category: network_connection` | Sysmon 3 |
| File created | `category: file_event` | Sysmon 11 |
| Registry value set | `category: registry_set` | Sysmon 13 |
| DLL load | `category: image_load` | Sysmon 7 |
| LSASS access | `category: process_access` | Sysmon 10 |
| DNS query | `category: dns_query` | Sysmon 22 |
| PowerShell script block | `category: ps_script` | PowerShell 4104 |
| Security log event | `product: windows, service: security` | 4624, 4698, 4769... |
| System log event | `product: windows, service: system` | 7045 |

Other products: `product: linux` (`category: process_creation` from auditd/Sysmon for Linux,
`service: auditd`, `service: sshd`), `product: aws, service: cloudtrail`,
`product: azure, service: signinlogs | auditlogs | activitylogs`,
`product: m365`, `product: okta`, `product: gcp, service: gcp.audit`, `product: zeek, service: dns | http | conn`.

## Good vs bad

```yaml
# BAD: brittle, case/obfuscation-sensitive, no logsource precision, IOC not behaviour
title: Bad Mimikatz
logsource:
  product: windows
detection:
  keywords:
    - 'mimikatz.exe'
  condition: keywords
level: critical
```

Problems: keyword search across all fields (slow, backend-dependent), detects a
file name that attackers rename, no id/status/tags/falsepositives, severity
claimed without evidence.

```yaml
# GOOD: behaviour (encoded PowerShell launched by an Office app), resilient to renaming
title: Office Application Spawning Encoded PowerShell
id: 4c9a1e7b-2d3f-4a8e-b0c6-5e1f7d2a9b34
status: test
description: Detects Word/Excel/PowerPoint/Outlook starting PowerShell with an encoded command, typical of malicious macros.
references:
  - https://attack.mitre.org/techniques/T1059/001/
  - https://attack.mitre.org/techniques/T1566/001/
author: Blue Team
date: 2026-11-20
tags:
  - attack.execution
  - attack.t1059.001
  - attack.initial-access
  - attack.t1566.001
logsource:
  category: process_creation
  product: windows
detection:
  selection_parent:
    ParentImage|endswith:
      - '\winword.exe'
      - '\excel.exe'
      - '\powerpnt.exe'
      - '\outlook.exe'
  selection_child:
    - Image|endswith:
        - '\powershell.exe'
        - '\pwsh.exe'
    - OriginalFileName:
        - 'PowerShell.EXE'
        - 'pwsh.dll'
  selection_enc:
    CommandLine|contains|windash:
      - ' -e '
      - ' -en '
      - ' -enc '
      - ' -enco'
      - ' -ec '
  condition: all of selection_*
falsepositives:
  - Legitimate Office add-ins that launch PowerShell (rare; verify add-in and signer)
level: high
```

Why it is better: field-scoped, `OriginalFileName` survives renaming, `windash`
catches `/enc` and Unicode dashes, explicit tags and false positives.

## Converting with sigma-cli / pySigma

```bash
# Install CLI and backends (pin versions in CI)
pip install sigma-cli
sigma plugin list                       # available backends and pipelines
sigma plugin install splunk
sigma plugin install elasticsearch
sigma plugin install kusto              # Microsoft Sentinel / Defender XDR (replaces the older microsoft365defender backend)
sigma list targets                      # confirm target names in YOUR installed version
sigma list pipelines                    # confirm pipeline names before using them

# Validate
sigma check rules/

# Splunk SPL (Windows TA field names); -f savedsearches emits savedsearches.conf stanzas
sigma convert -t splunk -p splunk_windows rules/proc_creation_office_enc_ps.yml
sigma convert -t splunk -p splunk_windows -f savedsearches rules/ > savedsearches.conf
# Splunk CIM data model / tstats output (pipeline + format names vary by version - check sigma list)
sigma convert -t splunk -p splunk_cim -f data_model rules/proc_creation_office_enc_ps.yml

# Defender XDR advanced hunting / Sentinel KQL
sigma convert -t kusto -p microsoft_xdr rules/proc_creation_office_enc_ps.yml
sigma convert -t kusto -p sentinel_asim rules/proc_creation_office_enc_ps.yml

# Elastic: Lucene, EQL, ES|QL; ECS mapping pipeline for Winlogbeat / Elastic Agent data
sigma convert -t lucene -p ecs_windows rules/proc_creation_office_enc_ps.yml
sigma convert -t eql    -p ecs_windows rules/proc_creation_office_enc_ps.yml
sigma convert -t esql   -p ecs_windows rules/proc_creation_office_enc_ps.yml
sigma convert -t lucene -p ecs_windows -f siem_rule_ndjson rules/ > rules.ndjson   # import into Kibana; format name: check sigma list formats lucene
```

Pipeline names, target names and output formats change between pySigma
releases - always confirm with `sigma list targets|pipelines|formats <target>`.

### Custom field mapping pipeline

When your index uses non-standard field names, write a processing pipeline
instead of editing rules:

```yaml
# pipelines/corp_sysmon.yml - map Sigma fields to local Splunk extractions
# Use: sigma convert -t splunk -p splunk_windows -p pipelines/corp_sysmon.yml rules/
name: corp sysmon field mapping
priority: 100
transformations:
  - id: corp_field_names
    type: field_name_mapping
    mapping:
      CommandLine: process_command_line
      ParentImage: parent_process_path
    rule_conditions:
      - type: logsource
        category: process_creation
        product: windows
  - id: corp_index
    type: add_condition
    conditions:
      index: edr_windows
    rule_conditions:
      - type: logsource
        product: windows
```

### Python API (for CI)

```python
# Convert all rules for Splunk in a CI job; fails loudly on unsupported constructs
from sigma.collection import SigmaCollection
from sigma.backends.splunk import SplunkBackend
from sigma.pipelines.splunk import splunk_windows_pipeline

rules = SigmaCollection.load_ruleset(["rules/"])
backend = SplunkBackend(processing_pipeline=splunk_windows_pipeline())
for query in backend.convert(rules):
    print(query)
```

## Testing

- **Syntax:** `sigma check rules/` (also catches duplicate ids, missing fields).
- **On EVTX without a SIEM:** run the rule with Chainsaw (`chainsaw hunt <evtx_dir> -s rules/ --mapping <sigma-event-logs-all mapping file>`),
  Hayabusa (`hayabusa csv-timeline -d <evtx_dir> -r rules/`) or Zircolite against
  an EVTX that contains your TP sample. Check each tool's docs for the current
  flag names; they evolve.
- **On the SIEM:** paste the converted query, run against the TP sample index
  and against 30 days of production, record hit counts (see `detection-engineering`).
- **Negative test:** keep one benign event that must *not* match (the known FP
  you filtered) and assert zero hits.

## False positives & benign look-alikes

| Pattern | Typical cause | Handle with |
|---|---|---|
| Encoded PowerShell | Management agents (SCCM, Intune scripts), vendor installers | `filter_*` on ParentImage + signed path; never on CommandLine wildcard alone |
| `rundll32` with odd exports | Control panel applets, printing, shell extensions | Exact DLL + export allowlist |
| Scheduled task / service creation | Software updaters | Filter by binary path under `C:\Program Files\` AND known publisher (if signer field exists) |
| Network tools (`curl`, `certutil -urlcache`) | Admin scripts, CI | Scope filters to build hosts or accounts via pipeline `expand` placeholders |

Decision table for a rule that fires after conversion:

| Verdict | Evidence |
|---|---|
| True Positive | Event matches the behaviour, unexplained by owner/change record |
| Benign True Positive | Behaviour real but sanctioned (admin, pentest) - document, consider filter |
| False Positive | Match caused by mapping error, wildcard over-reach, or wrong logsource - fix rule/pipeline |
| Needs more data | Field missing in source (no command line, no OriginalFileName) - fix logging first |

## Pitfalls

- **Wrong logsource** (`service: sysmon` with `EventID: 1`) instead of
  `category: process_creation` - pipelines cannot remap it to 4688/MDE.
- **Field not populated in your data** (e.g. `OriginalFileName` absent in 4688);
  an OR branch on a missing field silently never matches - harmless, but an AND
  on it kills the rule.
- **Backslash escaping:** in single-quoted YAML, `'\rundll32.exe'` is one
  backslash; wildcards and backslashes before `*` need care - read the converted query.
- **`|re` portability:** lookarounds and some flags are unsupported in Splunk/Lucene/ES|QL backends; keep regexes simple.
- **`contains` on huge fields** (raw message) is slow in every backend.
- **Keyword-only rules** (no field) convert to full-text search; avoid outside of very specific services.
- **Forgetting `|all`** - a list under `contains` is OR, which is often far broader than intended.
- **Changing `id` on edit** - breaks tracking, metrics and deduplication downstream.
- **Status inflation** - `stable` means tested broadly; use `test` until baselined.

## Output

- A validated `.yml` Sigma rule, the converted query for each target with the
  pipeline used, TP sample, baseline numbers, and filter rationale.
- Hand-offs: platform tuning in `kql-sentinel-defender`, `spl-splunk`,
  `elastic-eql-esql`; lifecycle, metadata and ADS in `detection-engineering`;
  `/sigma` to write or convert, `/detect` for the full pipeline.

## References

- Sigma specification (SigmaHQ `sigma-specification` repository): rules, modifiers, correlation rules, taxonomy
- SigmaHQ rule repository and contribution conventions
- pySigma and sigma-cli documentation; backend plugins: splunk, kusto, elasticsearch
- Chainsaw (WithSecure Labs), Hayabusa (Yamato Security), Zircolite
- MITRE ATT&CK: https://attack.mitre.org/techniques/T1003/001/, https://attack.mitre.org/techniques/T1059/001/
