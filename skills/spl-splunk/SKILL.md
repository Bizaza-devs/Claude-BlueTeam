---
name: spl-splunk
description: SPL for Splunk Enterprise and Enterprise Security - hunting and correlation searches over Windows Security, Sysmon and network data. Covers tstats with accelerated CIM data models (Endpoint.Processes, Authentication, Network_Traffic), stats / eventstats / streamstats, lookups and first-seen tracking, correlation searches and risk-based alerting (Risk data model, risk incident rules), performance rules, and 10+ ready hunts (encoded PowerShell, LSASS access Sysmon 10, services 7045, scheduled tasks 4698, Kerberoasting 4769, password spray, log clearing 1102, Run keys, beaconing, group changes 4728/4732/4756). Use when asked to "write an SPL search", "hunt in Splunk", "build a correlation search", "convert to tstats", "set up RBA", or "why is my Splunk search slow".
---

# SPL for Splunk and Splunk ES

SPL is a pipeline: the part before the first `|` decides how much data is read
from disk; everything after only reshapes it. Most performance and accuracy
problems are decided in that first segment.

## When to use

- Hunting in Splunk over Windows Security, Sysmon, EDR, proxy, firewall or auth data.
- Writing or tuning an ES correlation search or a risk rule.
- Converting a Sigma rule to SPL and verifying field names (`sigma-rules`).
- Speeding up a search that times out or skews the search head.

## Ground rules

- **Name the index, sourcetype and time range in every search you report.**
  "No results" is meaningful only together with "index=wineventlog, 30 days,
  1,180 hosts reporting EventCode=4688".
- **Prove the data exists before hunting:** `| tstats count where index=* by index sourcetype`
  for the last 24 h, and check that the field you filter on is extracted (`| fieldsummary`).
- **Data-model searches with `summariesonly=true` see only accelerated data.**
  Check acceleration status/coverage before concluding "nothing happened".
- **No TP verdict from one search hit alone** - corroborate with a second source
  (EDR, proxy, auth) or the raw event.
- **Correlation searches ship only after a TP test and a 30-day baseline**
  (`detection-engineering`).

## Workflow

1. Identify the data: index, sourcetype, source, and whether a CIM data model
   is populated and accelerated for it (Splunk Add-on for Microsoft Windows,
   Splunk Add-on for Sysmon, CIM add-on).
2. Start with `tstats` over the data model (fast); drop to raw events only for
   fields the model lacks (e.g. Sysmon `GrantedAccess`).
3. Filter as early as possible with field=value pairs in the base search.
4. Aggregate with `stats` by entity; use `eventstats`/`streamstats` for
   baselines and sequences; avoid `join`/`transaction` unless unavoidable.
5. Enrich with lookups (asset/identity, allowlists, first-seen).
6. For detections: decide between notable/finding (alert) and risk
   contribution (RBA); baseline 30 days; write the ADS.

## Field-name reality check

Windows events look different depending on the add-on and rendering:

| Data | Typical source/sourcetype (Splunk Add-on for Microsoft Windows / Sysmon) | Field name examples |
|---|---|---|
| Security log (XML) | `source="XmlWinEventLog:Security"`, `sourcetype=XmlWinEventLog` | `EventCode`, `TargetUserName`, `IpAddress`, `LogonType`, `TicketEncryptionType`, `ServiceName` |
| Security log (classic) | `source="WinEventLog:Security"`, `sourcetype=WinEventLog` | `EventCode`, `Account_Name`, `Source_Network_Address`, `Logon_Type`, `Ticket_Encryption_Type`, `Service_Name` |
| System log | `source="XmlWinEventLog:System"` | `EventCode=7045`, `ServiceName`, `ImagePath` |
| Sysmon | `source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"` | `EventCode`, `Image`, `CommandLine`, `ParentImage`, `TargetImage`, `GrantedAccess`, `TargetObject`, `Details` |

Index names (`wineventlog`, `sysmon`, `edr`...) are local. The searches below
use `index=wineventlog` and `index=sysmon` as placeholders; many shops wrap them
in macros (ESCU ships `` `sysmon` `` and `` `wineventlog_security` ``).

## tstats with CIM data models

```spl
`comment("Encoded PowerShell, from the Endpoint.Processes data model (T1059.001, T1027). Tune: exclude management parents")`
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("powershell.exe","pwsh.exe")
      AND (Processes.process="* -enc*" OR Processes.process="* -e *" OR Processes.process="* -ec *" OR Processes.process="*/enc*")
    by Processes.dest Processes.user Processes.parent_process_name Processes.process
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
```

- `drop_dm_object_name` is a macro shipped with ES / ESCU; without it use
  `| rename Processes.* as *`. The `` `comment("...")` `` lines are a no-op
  macro used here for annotation; if your instance lacks it, use SPL inline
  block comments (three backticks, Splunk 8.0+) or delete the line.
- Data model roots: `Endpoint.Processes`, `Endpoint.Registry`, `Endpoint.Filesystem`,
  `Authentication` (root `Authentication`), `Network_Traffic.All_Traffic`,
  `Network_Resolution.DNS`, `Web.Web`.
- `summariesonly=true` = accelerated summaries only (fast, may miss recent
  minutes or unaccelerated buckets); `false` falls back to raw (slow).

## stats, eventstats, streamstats

```spl
`comment("eventstats: users whose daily logon count is 5x their own 30-day average. Tune: multiplier, min count")`
| tstats summariesonly=true count from datamodel=Authentication where Authentication.action=success by Authentication.user _time span=1d
| `drop_dm_object_name(Authentication)`
| eventstats avg(count) as avg_daily stdev(count) as sd_daily by user
| where count > 5*avg_daily AND count > 50
```

```spl
`comment("streamstats: time between consecutive events per pair (sequence / beacon building block)")`
| sort 0 src_ip dest_ip _time
| streamstats current=f last(_time) as prev_time by src_ip dest_ip
| eval delta=_time-prev_time
```

- `stats` collapses events; `eventstats` adds aggregate columns without collapsing;
  `streamstats` computes running values in event order (sort first; `sort 0` = no row limit).

## Lookups

```spl
`comment("First-seen tracking: maintain a lookup of parent>child pairs; scheduled daily")`
| tstats summariesonly=true min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes by Processes.parent_process_name Processes.process_name
| `drop_dm_object_name(Processes)`
| inputlookup append=true process_pairs_first_seen.csv
| stats min(firstTime) as firstTime max(lastTime) as lastTime by parent_process_name process_name
| outputlookup process_pairs_first_seen.csv
```

```spl
`comment("Use it: pairs first seen in the last 24h. Tune: allowlist lookup of known installers")`
| inputlookup process_pairs_first_seen.csv
| where firstTime > relative_time(now(), "-24h")
| lookup process_allowlist.csv process_name OUTPUT reason
| where isnull(reason)
```

Enrich with ES asset and identity lookups (priority, owner, category) so
severity reflects asset criticality.

## Correlation searches and risk-based alerting (ES)

Classic model: one correlation search -> one notable event per match. RBA:
many lower-fidelity rules write **risk events** (risk object, score, ATT&CK
annotations) to the risk index; a **risk incident rule** alerts when an entity
accumulates enough score or distinct tactics. RBA cuts alert volume while keeping
weak signals. (ES 8.x renames parts of this model - notables to findings,
correlation searches to event-based / finding-based detections; concepts are
the same.)

Risk rule pattern: the correlation search output carries the entity fields and
the Risk Analysis adaptive response action assigns `risk_object`
(e.g. `dest`, type `system`), `risk_score` and a `risk_message`; annotate with
ATT&CK technique IDs in the search's annotations.

```spl
`comment("Risk incident rule: entity with >=100 risk from >=3 distinct rules and >=2 tactics in 24h. Tune: thresholds per entity type")`
| tstats summariesonly=false sum(All_Risk.calculated_risk_score) as risk_score
    dc(source) as rule_count
    dc(All_Risk.annotations.mitre_attack.mitre_tactic_id) as tactic_count
    values(source) as rules
    from datamodel=Risk.All_Risk
    where earliest=-24h
    by All_Risk.risk_object All_Risk.risk_object_type
| `drop_dm_object_name(All_Risk)`
| where risk_score >= 100 AND rule_count >= 3 AND tactic_count >= 2
```

Correlation search settings: schedule (cron) with time range overlapping
ingestion delay (e.g. run every 15 min over `-20m@m` to `-5m@m`), throttling by
entity fields, notable/finding title using tokens, drill-down search, severity,
ATT&CK annotations, and next steps referencing the ADS. Adaptive responses that
change systems (block, disable) require IR lead / change approval.

## Performance rules

1. Always specify `index=` and `sourcetype=`/`source=`; never `index=*` in a scheduled search.
2. Narrow the time range; use `earliest=`/`latest=` in saved searches.
3. Put field=value filters in the base search, not after `| search` or `| where`.
4. Prefer `tstats` (accelerated data models or indexed fields) over raw searches.
5. Use `TERM()` for tokens containing minor breakers (`TERM(10.1.2.3)`), and
   `PREFIX()` in tstats for indexed tokens.
6. Avoid leading wildcards (`*mimikatz`) in the base search - they defeat the index.
7. `fields` early to drop unused fields (`| fields _time host CommandLine`).
8. Replace `join` with `stats ... by key` over both datasets (`(search A) OR (search B) | stats values(...) by key`).
   Subsearches are truncated by default limits on rows and runtime - silent data loss.
9. Avoid `transaction`; use `stats` with `range(_time)` or `streamstats`.
10. Check the Job Inspector: scan count vs event count shows how much was read for nothing.

## Ready hunting searches

```spl
`comment("1. Office spawning script interpreters (T1566.001, T1059). Tune: add-ins that launch scripts")`
| tstats summariesonly=true count min(_time) as firstTime from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("winword.exe","excel.exe","powerpnt.exe","outlook.exe")
      AND Processes.process_name IN ("powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe")
    by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
```

```spl
`comment("2. LSASS access with dump-capable rights, Sysmon 10 (T1003.001). Tune: allowlist EDR/AV SourceImage paths; GrantedAccess values seen in your fleet")`
index=sysmon source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10 TargetImage="*\\lsass.exe"
    GrantedAccess IN ("0x1010","0x1410","0x143a","0x1438","0x1fffff")
| stats count min(_time) as firstTime values(GrantedAccess) as access by host SourceImage SourceUser
| where NOT match(SourceImage, "(?i)\\\\(MsMpEng|csrss|wininit|svchost)\.exe$")
```

```spl
`comment("3. New service installed, System 7045 (T1543.003). Tune: allowlist signed paths under Program Files; watch cmd/powershell/temp paths")`
index=wineventlog source="XmlWinEventLog:System" EventCode=7045
| eval suspicious=if(match(ImagePath, "(?i)(cmd\.exe|powershell|\\\\temp\\\\|\\\\users\\\\|\\\\programdata\\\\|%comspec%|\\\\admin\$)"), 1, 0)
| stats count values(ImagePath) as ImagePath max(suspicious) as suspicious by host ServiceName
| sort - suspicious
```

```spl
`comment("4. Scheduled task created, Security 4698 (T1053.005). Tune: requires 'Other Object Access Events' auditing; allowlist updater task names")`
index=wineventlog source="XmlWinEventLog:Security" EventCode=4698
| rex field=TaskContent "(?s)<Command>(?<task_command>[^<]+)</Command>"
| search task_command="*\\AppData\\*" OR task_command="*powershell*" OR task_command="*\\Users\\Public\\*" OR task_command="*mshta*" OR task_command="*rundll32*"
| table _time host SubjectUserName TaskName task_command
```

```spl
`comment("5. Kerberoasting - RC4 service tickets for user (non-computer) SPNs, 4769 (T1558.003). Tune: legacy apps needing RC4; field names differ in classic rendering")`
index=wineventlog source="XmlWinEventLog:Security" EventCode=4769 TicketEncryptionType=0x17 Status=0x0
    NOT ServiceName="*$" NOT ServiceName="krbtgt"
| stats dc(ServiceName) as spn_count values(ServiceName) as spns by TargetUserName IpAddress
| where spn_count >= 5
```

```spl
`comment("6. Password spray - one source, many users failing (T1110.003). Tune: exclude NAT/VPN concentrators; thresholds")`
| tstats summariesonly=true count dc(Authentication.user) as users from datamodel=Authentication
    where Authentication.action=failure by Authentication.src _time span=1h
| `drop_dm_object_name(Authentication)`
| where users >= 15 AND count/users < 4
```

```spl
`comment("7. Brute force followed by success from same source (T1110.001). Tune: thresholds; scanners")`
| tstats summariesonly=true count from datamodel=Authentication
    where Authentication.action IN ("failure","success") by Authentication.src Authentication.user Authentication.action _time span=1h
| `drop_dm_object_name(Authentication)`
| stats sum(eval(if(action="failure",count,0))) as failures sum(eval(if(action="success",count,0))) as successes values(user) as users by src _time
| where failures >= 20 AND successes > 0
```

```spl
`comment("8. Security log cleared (1102) or other event log cleared (System 104) (T1070.001). Tune: none - always review")`
index=wineventlog ((source="XmlWinEventLog:Security" EventCode=1102) OR (source="XmlWinEventLog:System" EventCode=104))
| table _time host EventCode SubjectUserName Channel
```

```spl
`comment("9. Run-key persistence to user-writable paths, Sysmon 13 (T1547.001). Tune: allowlist signed updaters by Image")`
index=sysmon source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
    TargetObject="*\\CurrentVersion\\Run*"
| where match(Details, "(?i)(\\\\appdata\\\\|\\\\temp\\\\|\\\\users\\\\public\\\\|powershell|mshta|rundll32|https?://)")
| stats count min(_time) as firstTime values(Details) as values by host Image TargetObject
```

```spl
`comment("10. Privileged group membership added, 4728/4732/4756 (T1098). Tune: group list per domain; change tickets")`
index=wineventlog source="XmlWinEventLog:Security" EventCode IN (4728, 4732, 4756)
    TargetUserName IN ("Domain Admins","Enterprise Admins","Administrators","Schema Admins","Account Operators","Backup Operators")
| table _time host EventCode SubjectUserName MemberName TargetUserName
```

```spl
`comment("11. Beacon-like periodic connections (T1071, T1573). Tune: dest allowlist (updates, telemetry), jitter tolerance; see hunt-c2-beaconing")`
| tstats summariesonly=true count from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.action=allowed All_Traffic.dest_port IN (80, 443) by _time All_Traffic.src_ip All_Traffic.dest_ip span=1m
| `drop_dm_object_name(All_Traffic)`
| sort 0 src_ip dest_ip _time
| streamstats current=f last(_time) as prev_time by src_ip dest_ip
| eval delta=_time-prev_time
| stats count as intervals avg(delta) as avg_delta stdev(delta) as sd_delta by src_ip dest_ip
| where intervals >= 60 AND sd_delta < 0.1*avg_delta
```

```spl
`comment("12. Rare process network connections, Sysmon 3 (T1071). Tune: process allowlist; min host count")`
index=sysmon source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 Initiated=true
| stats dc(host) as host_count values(DestinationIp) as dests count by Image
| where host_count <= 2
| sort host_count
```

```spl
`comment("13. Explicit-credential logons from workstations to many hosts, 4648 (T1021, T1550). Tune: admin jump hosts")`
index=wineventlog source="XmlWinEventLog:Security" EventCode=4648 NOT TargetUserName="*$"
| stats dc(TargetServerName) as targets values(TargetServerName) as servers by host SubjectUserName TargetUserName
| where targets >= 5
```

## False positives & benign look-alikes

| Search | Benign source | Distinguish by |
|---|---|---|
| LSASS access | EDR/AV, Windows Defender, backup and monitoring agents | Signed vendor path, constant across fleet, documented |
| New service / scheduled task | Software deployment, updaters | Change calendar, publisher path in Program Files, same on many hosts |
| Kerberoasting | Legacy apps requesting RC4, scanners | Same SPN set daily from a service host vs one-off burst from a workstation |
| Password spray | VPN/NAT concentrators, expired service passwords | One account repeating vs many accounts once each |
| Beaconing | Update agents, telemetry, monitoring, NTP-like polling | Known vendor destinations, signed process, fleet-wide prevalence |

| Verdict | Evidence |
|---|---|
| True Positive | Hit + corroboration (EDR process tree, proxy, auth) + no owner explanation |
| Benign True Positive | Real behaviour, sanctioned (admin task, pentest ID, change ticket) |
| False Positive | Field extraction or wildcard error matched unrelated data - fix search |
| Needs more data | Field not extracted, data model not accelerated, gap in forwarding |

## Pitfalls

- Field names differ between XML and classic Windows rendering - a search using
  `Logon_Type` returns nothing on XML data (`LogonType`).
- `summariesonly=true` hides unaccelerated data; acceleration lag hides the last minutes.
- `search` comparisons are case-insensitive for values; `where` and `eval`
  comparisons are case-sensitive (`where user="Admin"` misses `admin`) - use `lower()`.
- Backslashes: in the base search `"*\\lsass.exe"`; inside `match()`/`rex` regexes,
  each literal backslash needs `\\\\` in the SPL string.
- `join`, `append` and subsearches silently truncate.
- Throttling by the wrong fields suppresses distinct incidents.
- Scheduled searches whose window does not overlap ingestion delay miss events.

## Output

- SPL with platform label, index/sourcetype assumptions, time range, tuning
  notes; result summary with coverage numbers.
- For ES: correlation search settings, risk object/score/annotations, throttle
  fields, drill-down, baseline numbers, ADS (`detection-engineering`).
- Hand-offs: `alert-triage` / `/investigate` for hits, `hunt-c2-beaconing` for
  beacon follow-up, `hunt-credential-access` for Kerberos/LSASS,
  `sigma-rules` for portability, `logging-coverage` when data is missing.

## References

- Splunk Docs: Search Reference (tstats, stats, eventstats, streamstats, lookup, inputlookup, outputlookup)
- Splunk Docs: Common Information Model (CIM) add-on manual - Endpoint, Authentication, Network_Traffic, Risk data models
- Splunk Docs: Splunk Enterprise Security - risk-based alerting, correlation searches / detections, adaptive response
- Splunk Add-on for Microsoft Windows; Splunk Add-on for Sysmon (sourcetypes and field extractions)
- Splunk Security Content (ESCU) repository
- MITRE ATT&CK: https://attack.mitre.org/techniques/T1558/003/, https://attack.mitre.org/techniques/T1003/001/
