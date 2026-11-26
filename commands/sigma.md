---
description: "Write, review, or convert a Sigma rule: valid YAML, correct logsource, ATT&CK tags, false positives, test notes, and backend conversion (Splunk, Sentinel/KQL, Elastic). Usage: /sigma new \"<behaviour>\" | /sigma review <file> | /sigma convert <file> --to splunk|kusto|esql|eql|lucene"
argument-hint: "new \"<behaviour>\" | review <file.yml> | convert <file.yml> --to splunk|kusto|esql|eql|lucene"
---

# /sigma

Sigma is the portable layer of the detection library. This command produces rules
that pass `sigma check`, convert cleanly with pySigma, and carry enough metadata that
another team can deploy them without asking you questions.

Input: `$ARGUMENTS`

## Usage

```
/sigma new "certutil downloading a file with -urlcache"
/sigma review rules/windows/proc_creation_win_certutil_download.yml
/sigma convert rules/windows/proc_creation_win_certutil_download.yml --to splunk
/sigma convert rules/cloud/aws_cloudtrail_stop_logging.yml --to kusto
```

## Skills to load

- Always: `sigma-rules`, `detection-engineering`
- Target backend: `spl-splunk`, `kql-sentinel-defender`, `elastic-eql-esql`
- Data source availability: `logging-coverage`

## Evidence gate

- No `status: stable` without a recorded true-positive test and a 30-day baseline (same
  bar as `/detect`). Default new rules to `status: experimental`.
- A conversion is not "done" until the converted query was run at least once on the
  target platform and returned the expected test event; field-mapping gaps are listed.

## Procedure - new

1. Clarify the behaviour and the log source. Pick the Sigma `logsource` correctly:
   `category: process_creation` + `product: windows` for Sysmon 1 / 4688 / EDR process events;
   `product: aws` + `service: cloudtrail`; `product: azure` + `service: signinlogs` etc.
2. Write the `detection` block: selections as maps, lists for OR, modifiers
   (`|contains`, `|endswith`, `|re`, `|all`, `|windash`, `|cidr`) chosen deliberately.
   Keep `condition` readable (`selection and not filter_*`).
3. Fill metadata: `title`, `id` (fresh UUIDv4), `status`, `description`, `references`
   (only real, stable sources), `author`, `date` (YYYY-MM-DD), `tags` (`attack.<tactic>`,
   `attack.t####.###`), `falsepositives`, `level`.
4. Add filters for known benign look-alikes as named `filter_*` selections, each with a comment.
5. Validate: `sigma check <file>` (sigma-cli) and convert to the main backend to make
   sure the logic survives translation.

```yaml
title: Certutil Download Via URLCache Flag
id: 00000000-0000-4000-8000-000000000000   # replace with a fresh UUIDv4
status: experimental
description: Detects certutil.exe used with -urlcache to fetch a remote file (T1105). Tune filter_admin to your software-deployment tooling.
references:
    - https://attack.mitre.org/techniques/T1105/
author: <name>
date: 2026-11-25
tags:
    - attack.command-and-control
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\certutil.exe'
        - OriginalFileName: 'CertUtil.exe'
    selection_cli:
        CommandLine|contains|windash: '-urlcache'
    filter_admin:
        ParentImage|endswith: '\<approved-deployment-agent>.exe'   # tune locally
    condition: all of selection_* and not filter_admin
falsepositives:
    - Legacy admin scripts that fetch CRLs or installers with certutil
level: medium
```

## Procedure - review

Check and report as a table: YAML validity; `logsource` matches the fields used;
modifiers correct (e.g. `endswith` with the leading backslash); case sensitivity
assumptions; overly broad `contains`; filters that an attacker can satisfy
(e.g. excluding by `CommandLine|contains` alone); missing ATT&CK tags; `level`
consistent with fidelity; `falsepositives` filled; references real.

| # | Line / field | Issue | Severity | Fix |
|---|---|---|---|---|

## Procedure - convert

```bash
# pySigma via sigma-cli; install the backend plugin first (e.g. sigma plugin install splunk)
sigma convert -t splunk -p sysmon rules/windows/proc_creation_win_certutil_download.yml
sigma convert -t kusto  -p microsoft_xdr rules/windows/proc_creation_win_certutil_download.yml
sigma convert -t esql   -p ecs_windows rules/windows/proc_creation_win_certutil_download.yml
```

Backend and pipeline names differ by pySigma version and installed plugins; run
`sigma list targets` and `sigma list pipelines` and use what is installed. Then:
replace index/table names with local ones, check field mappings for every field in
the rule, and note any modifier the backend could not express.

## Output

The rule (or reviewed/converted text) as a file proposal, plus a short table:
`file | status | ATT&CK | backends tested | TP test | baseline | open issues`.

## Gates and safety

- Do not overwrite an existing rule file without showing the diff and getting a yes.
- No internal hostnames, usernames or case details in rules meant for sharing.
- Testing follows `purple-team-validation` (lab or approved change). Use `/detect` for the full lifecycle.
