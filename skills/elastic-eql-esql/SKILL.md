---
name: elastic-eql-esql
description: Hunting and detection engineering in Elastic Security (Elastic Defend, Elastic Agent integrations) with ECS fields and three query languages - EQL (event queries, sequence by host.id with maxspan, until, runs), ES|QL (FROM / WHERE / EVAL / STATS for aggregation and rarity) and Kibana KQL / Lucene. Covers ECS fields (process.*, event.category, host.id, user.name, dns.question.name, registry.path), detection rule types (custom query, EQL, ES|QL, threshold, machine learning, new terms, indicator match), look-back, exceptions, alert suppression, and 10+ ready queries (Office child processes, LSASS dump, brute-force sequence, dropped-and-executed binaries, web shells, rare parent-child, DNS tunnelling, CloudTrail IAM). Use when asked to "write an EQL query", "ES|QL hunt", "Elastic detection rule", "new terms rule", or to tune an Elastic alert.
---

# Elastic Security: EQL, ES|QL and KQL

Elastic gives you three query languages over the same ECS documents. Pick by
the question: **KQL/Lucene** to filter, **EQL** for event ordering and
sequences, **ES|QL** to aggregate, compute and find rarity.

## When to use

- Hunting in Elastic Security / Kibana over Elastic Defend, Sysmon, Windows
  Security, Linux auth, cloud audit integrations.
- Writing or tuning an Elastic detection rule (any rule type).
- Converting Sigma to Elastic (`sigma-rules`) and checking ECS field mapping.

## Ground rules

- **State the index pattern / data view and time range with every result.**
  An empty result over `logs-*` that does not contain process events proves nothing.
- **Confirm coverage first:** count documents and distinct `host.id` per
  `event.dataset` for the window before claiming absence.
- **No TP verdict from one hit;** corroborate with a second event type (process +
  network, auth + process) or a second data source.
- **Rules ship after a TP test and a 30-day baseline** (`detection-engineering`);
  use the rule preview over history to baseline.

## Workflow

1. Identify the dataset and index pattern (`logs-endpoint.events.process-*`,
   `logs-windows.sysmon_operational-*`, `logs-system.security-*`...).
2. Check ECS field population on a sample document (some integrations put
   detail only in `winlog.event_data.*`).
3. Filter with KQL to explore; move to EQL when order or correlation by entity
   matters; move to ES|QL when you need counts, rarity or computed fields.
4. Turn the final query into the matching rule type; add exceptions, suppression,
   MITRE mapping, investigation guide.
5. Preview over 30 days, tune, test with emulation, deploy via `detection-rules`
   or the Detections API.

## ECS fields you will use

| Area | Fields |
|---|---|
| Event classification | `event.category` (process, network, file, registry, authentication, iam, dns), `event.type` (start, end, creation, change, deletion, info), `event.action`, `event.outcome`, `event.code`, `event.dataset` |
| Host / user | `host.id`, `host.name`, `host.os.type`, `user.name`, `user.domain`, `user.id` |
| Process | `process.name`, `process.executable`, `process.command_line`, `process.args`, `process.pid`, `process.entity_id`, `process.pe.original_file_name`, `process.code_signature.subject_name`, `process.code_signature.trusted`, `process.hash.sha256` |
| Parent | `process.parent.name`, `process.parent.executable`, `process.parent.command_line`, `process.parent.entity_id` |
| Network | `source.ip`, `source.port`, `destination.ip`, `destination.port`, `network.direction`, `network.protocol`, `dns.question.name`, `url.full`, `user_agent.original` |
| File / registry | `file.path`, `file.name`, `file.extension`, `file.hash.sha256`, `registry.path`, `registry.value`, `registry.data.strings` |
| Windows raw | `winlog.event_id`, `winlog.channel`, `winlog.event_data.*` |
| Cloud | `cloud.account.id`, `event.provider`, `event.action` (CloudTrail `eventName`), `aws.cloudtrail.*` |

`process.entity_id` is the stable process identifier in Elastic Defend - join on
it rather than `process.pid`, which is reused.

## KQL and Lucene (filtering)

```kql
// Kibana KQL: encoded PowerShell (T1059.001) - exploration filter
// Tune: keyword matching is case-sensitive - include case variants or prefer EQL ':' for case-insensitivity
event.category : "process" and event.type : "start" and process.name : ("powershell.exe" or "pwsh.exe") and process.command_line : (*-enc* or *-EncodedCommand* or *-ec*)
```

```lucene
# Lucene: same intent; escape special characters, wildcard on keyword field (case-sensitive)
event.category:process AND process.name:(powershell.exe OR pwsh.exe) AND process.command_line:(*\-enc* OR *\-EncodedCommand*)
```

## EQL essentials

- Event query: `<category> where <condition>` (`any where` for all categories).
- `==` is case-sensitive; `:` is case-insensitive and supports `*` wildcards;
  `in~` is a case-insensitive list; `like~`, `regex~` also exist.
- Functions: `startsWith~`, `endsWith~`, `stringContains`, `length`, `cidrMatch`.
- **Sequences:** `sequence by <join keys> with maxspan=<time>` then 2+ bracketed
  queries in order; per-query `by` adds keys; `until [...]` expires a partial
  sequence; `with runs=N` repeats a step; newer versions support missing-event
  steps (`![...]`) - check your stack version.
- Pipes: `| head N`, `| tail N`, `| filter`.

## ES|QL essentials

- `FROM <index> | WHERE ... | EVAL ... | STATS ... BY ... | SORT ... | LIMIT ...`;
  also `KEEP`, `DROP`, `RENAME`, `DISSECT`, `GROK`, `ENRICH`, `MV_EXPAND`.
- String comparison is case-sensitive; normalise with `TO_LOWER()`.
- Time: `@timestamp >= NOW() - 7 days`, `DATE_TRUNC(1 hour, @timestamp)`.
- Comparisons on genuinely multi-valued fields return null (with a warning) and
  rows are dropped - use single-valued fields or `MV_EXPAND` first.
- For non-aggregating ES|QL **rules**, add `METADATA _id, _index, _version` to
  the `FROM` clause so alerts can be deduplicated.

## Ready queries

```eql
// 1. EQL: Office application spawning script/LOLBin child (T1566.001, T1059)
// Tune: exclude signed add-ins via process.code_signature; index logs-endpoint.events.process-*
process where host.os.type == "windows" and event.type == "start" and
  process.parent.name : ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe") and
  process.name : ("powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe")
```

```eql
// 2. EQL sequence: Office child process then outbound network from that same child within 1 minute (T1566.001, T1105)
// Tune: maxspan; exclude corporate proxy destinations if process connects via proxy
sequence by host.id with maxspan=1m
  [process where event.type == "start" and process.parent.name : ("winword.exe", "excel.exe", "powerpnt.exe")] by process.entity_id
  [network where event.type == "start" and destination.ip != null and
     not cidrMatch(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")] by process.entity_id
```

```eql
// 3. EQL: LSASS dump via comsvcs MiniDump or procdump (T1003.001)
// Tune: none expected; verify parent and user on any hit
process where host.os.type == "windows" and event.type == "start" and
  ((process.pe.original_file_name : "RUNDLL32.EXE" or process.name : "rundll32.exe") and
     process.command_line : "*comsvcs*" and process.command_line : ("*minidump*", "*#24*")) or
  (process.name : ("procdump.exe", "procdump64.exe") and process.command_line : "*lsass*")
```

```eql
// 4. EQL sequence: >= 10 failed logons then a success for the same user from the same source in 5 min (T1110)
// Tune: runs threshold; exclude vulnerability scanners by source.ip; index logs-system.security-*
sequence by host.id, source.ip, user.name with maxspan=5m
  [authentication where event.outcome == "failure"] with runs=10
  [authentication where event.outcome == "success"]
```

```eql
// 5. EQL sequence: executable written to a user-writable path, then executed (T1105, T1204.002)
// Tune: exclude browser updaters and software deployment agents
sequence by host.id with maxspan=10m
  [file where event.type == "creation" and file.extension : ("exe", "dll", "scr") and
     file.path : ("?:\\Users\\*\\AppData\\*", "?:\\Users\\Public\\*", "?:\\ProgramData\\*", "?:\\Windows\\Temp\\*")] by file.path
  [process where event.type == "start"] by process.executable
```

```eql
// 6. EQL: web server process spawning a shell on Linux - possible web shell (T1505.003)
// Tune: CGI scripts and health checks that legitimately call sh; see hunt-webshells
process where host.os.type == "linux" and event.type == "start" and
  process.parent.name in ("nginx", "apache2", "httpd", "php-fpm", "java", "tomcat") and
  process.name in ("sh", "bash", "dash", "zsh", "python", "python3", "perl", "nc", "curl", "wget")
```

```eql
// 7. EQL sequence: Run-key value set, then the referenced binary starts, same host within 1 hour (T1547.001)
// Tune: registry.data.strings matching is approximate - compare paths during triage
sequence by host.id with maxspan=1h
  [registry where registry.path : "*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run*\\*" and
     registry.data.strings : ("*\\AppData\\*", "*\\Users\\Public\\*", "*powershell*", "*mshta*")]
  [process where event.type == "start" and process.executable : ("?:\\Users\\*", "?:\\ProgramData\\*")]
```

```esql
// 8. ES|QL: rare parent -> child pairs across the fleet over 7 days (T1059 discovery aid)
// Tune: host threshold; exclude software deployment parents
FROM logs-endpoint.events.process-*
| WHERE @timestamp >= NOW() - 7 days AND event.type == "start" AND host.os.type == "windows"
| STATS hosts = COUNT_DISTINCT(host.id), runs = COUNT(*) BY process.parent.name, process.name
| WHERE hosts <= 2
| SORT hosts ASC, runs ASC
| LIMIT 200
```

```esql
// 9. ES|QL: encoded PowerShell, normalised for case, grouped by command (T1059.001, T1027)
// Tune: parent allowlist (management agents)
FROM logs-endpoint.events.process-*
| WHERE @timestamp >= NOW() - 7 days AND event.type == "start"
| EVAL pname = TO_LOWER(process.name), cmd = TO_LOWER(process.command_line)
| WHERE pname IN ("powershell.exe", "pwsh.exe")
  AND (cmd LIKE "* -enc*" OR cmd LIKE "* -e *" OR cmd LIKE "* -ec *" OR cmd LIKE "*/enc*")
| STATS hosts = COUNT_DISTINCT(host.id), first_seen = MIN(@timestamp) BY process.parent.name, cmd
| SORT hosts ASC
| LIMIT 100
```

```esql
// 10. ES|QL: possible DNS tunnelling - long query names and many unique subdomains per registered domain (T1071.004, T1048)
// Tune: CDN / security vendor domains with long hashes; length threshold; uses Elastic Defend DNS events
FROM logs-endpoint.events.network-*
| WHERE @timestamp >= NOW() - 1 day AND dns.question.name IS NOT NULL
| EVAL qlen = LENGTH(dns.question.name)
| WHERE qlen > 50
| STATS queries = COUNT(*), unique_names = COUNT_DISTINCT(dns.question.name), hosts = COUNT_DISTINCT(host.id) BY dns.question.registered_domain
| WHERE unique_names > 100
| SORT unique_names DESC
```

```esql
// 11. ES|QL: SSH brute force on Linux from the system integration (T1110)
// Tune: index pattern and event.action values depend on integration version
FROM logs-system.auth-*
| WHERE @timestamp >= NOW() - 1 day AND event.outcome == "failure" AND process.name == "sshd"
| STATS attempts = COUNT(*), users = COUNT_DISTINCT(user.name) BY source.ip, host.name
| WHERE attempts > 30
| SORT attempts DESC
```

```esql
// 12. ES|QL: AWS IAM persistence actions by principal (T1098.001, T1136.003)
// Tune: exclude IaC/CI roles; event.action carries the CloudTrail eventName in the AWS integration
FROM logs-aws.cloudtrail-*
| WHERE @timestamp >= NOW() - 7 days
  AND event.action IN ("CreateAccessKey", "CreateUser", "CreateLoginProfile", "AttachUserPolicy", "PutUserPolicy", "UpdateAssumeRolePolicy")
| STATS actions = COUNT(*), kinds = COUNT_DISTINCT(event.action) BY aws.cloudtrail.user_identity.arn, source.ip
| SORT kinds DESC
```

## Detection rule types

| Type | Use for | Key settings |
|---|---|---|
| Custom query | Single-event matches (KQL or Lucene) | index patterns / data view, query, optional saved query |
| EQL | Single events with richer logic; sequences | query; sequences alert on the full matched sequence |
| ES|QL | Aggregations, computed thresholds, rarity | aggregating query alerts per row; non-aggregating needs `METADATA _id, _index, _version` |
| Threshold | "N events by field(s)" or cardinality of a field | group-by fields, threshold count, optional cardinality (e.g. distinct `user.name` >= 20 by `source.ip`) |
| Machine learning | Anomalies from an ML job (rare process, unusual login time) | job ID, anomaly score threshold; requires ML jobs running |
| New terms | First time a value (or combination of up to a few fields) appears in a history window | fields (e.g. `host.id` + `process.executable`), history window |
| Indicator match | Events matching threat-intel indicators | source index + query, indicator index (e.g. `logs-ti_*`), field mapping (e.g. `destination.ip` -> `threat.indicator.ip`) |

Common settings: run interval and **additional look-back** (covers ingestion
delay - set look-back >= expected delay), max alerts per run, severity and risk
score (with overrides from fields), MITRE ATT&CK mapping, **exceptions**
(structured, with expiry where supported), **alert suppression** by fields and
time window, investigation guide (Markdown - put the ADS here), timeline
template, building-block flag for low-fidelity rules feeding correlation.
Response actions (Elastic Defend host isolation, Osquery) affect production
hosts - require IR lead / change approval and test them first.

Rules-as-code: the Elastic `detection-rules` repository defines rules as TOML
with a CLI for validation, testing and import/export; use it (or the Detection
Engine API) instead of console-only edits.

## False positives & benign look-alikes

| Query | Benign source | Distinguish by |
|---|---|---|
| Office child process | Add-ins, DLP agents, document management integrations | `process.code_signature.trusted == true` with known subject, fleet-wide prevalence |
| Dropped + executed | Installers, browser updaters, Teams/Slack/Zoom updaters in AppData | Signed by vendor, path matches app's own folder |
| Web server shell | CGI scripts, health checks, deploy hooks | Fixed command lines, runs on schedule, owned by deploy user |
| DNS long names | CDN, AV cloud lookups, telemetry with hashes in labels | Known vendor registered domains, many hosts, steady volume |
| Brute force | Service with expired password, scanner | Single account looping, scanner IP in inventory |

| Verdict | Evidence |
|---|---|
| True Positive | Hit + corroborating event (network/file/auth) + no owner explanation |
| Benign True Positive | Real behaviour, sanctioned (admin, pentest ID, change) |
| False Positive | Mapping/wildcard error, wrong field (`.text` vs keyword) - fix query |
| Needs more data | Field not populated by integration, host not enrolled, retention short |

## Pitfalls

- Case sensitivity: KQL/Lucene on keyword fields and ES|QL `==` are
  case-sensitive; EQL `:` is not. `PowerShell.exe` vs `powershell.exe` matters.
- Mixed sources: `winlog.event_data.CommandLine` (raw Windows) vs `process.command_line`
  (ECS) - check what your integration populates.
- `process.args` is multi-valued; ES|QL comparisons on it drop rows.
- Joining on `process.pid` instead of `process.entity_id` creates false sequences.
- Rule interval without additional look-back misses late-arriving events.
- Threshold and ES|QL rules alert on aggregates - make sure the alert still
  carries the entity fields the analyst needs.
- Exceptions on broad fields (`user.name`) quietly blind the rule.

## Output

- Query labelled with language, index pattern, time range and tuning notes;
  results summary with coverage numbers.
- For rules: rule type, settings, exceptions with reasons, suppression,
  MITRE mapping, investigation guide/ADS, preview baseline numbers.
- Hand-offs: `alert-triage` / `/investigate` for hits, `hunt-webshells`,
  `hunt-exfiltration`, `hunt-cloud-control-plane` for follow-up hunts,
  `sigma-rules` for portability, `detection-engineering` for the lifecycle.

## References

- Elastic Docs: EQL syntax reference (sequences, maxspan, until, runs); ES|QL reference (commands and functions)
- Elastic Docs: Kibana Query Language; Elastic Security detection rule types and rule settings; alert suppression; exceptions
- Elastic Common Schema (ECS) field reference
- Elastic `detection-rules` repository; Elastic Security prebuilt rules
- MITRE ATT&CK: https://attack.mitre.org/techniques/T1505/003/, https://attack.mitre.org/techniques/T1071/004/
