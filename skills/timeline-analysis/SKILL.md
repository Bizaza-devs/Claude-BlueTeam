---
name: timeline-analysis
description: Building and analysing incident timelines and super-timelines. Covers plaso (log2timeline.py, psort.py, pinfo.py), Sleuth Kit bodyfile + mactime, MFTECmd bodyfiles, Timesketch import and analysis, Hayabusa and Chainsaw EVTX timelines, Timeline Explorer filtering, time zone and clock-skew normalisation to UTC (FILETIME, WebKit, PRTime, Unix epoch, syslog without year), the anchor-event pivot technique (anchor plus/minus a window), and the incident timeline CSV used by the case scaffolder (timestamp_utc, host, source, event, detail, analyst, confidence). Use when asked to "build a timeline", "super-timeline this image", "what happened between", "sequence of events", "first malicious activity", "patient zero", "normalise time zones", or when running /timeline.
---

# Timeline analysis

## When to use

- You need the ordered sequence of attacker activity across one or many
  hosts, identities and cloud services.
- To find first malicious activity (initial access, patient zero) and dwell
  time.
- To reconcile evidence from EDR, SIEM, disk, memory and cloud logs into one
  defensible narrative for the report.

Artifact meaning comes from `windows-forensics`, `linux-forensics` and
`memory-forensics`; the report narrative goes to `ir-report-writing`.

## Ground rules

1. **UTC only.** Every row in a working or final timeline is UTC in ISO 8601
   with `Z` (`2025-03-01T10:15:42Z`, sub-seconds optional). Convert at ingest,
   not at the end, and record the original zone of each source.
2. **Every row is traceable.** A timeline entry names its source artifact
   (file, log, query) precisely enough that another analyst can find the raw
   record again. No source, no row.
3. **Timestamp semantics travel with the row.** "File created ($SI)",
   "Prefetch last run", "4624 logon" - not just "file activity".
4. **Confidence is explicit.** Inferred events (e.g. "probably executed
   because Amcache shows it") are marked lower confidence than directly
   logged ones.
5. **Hash the inputs.** The plaso storage file, bodyfiles and source images
   are evidence derivatives - hash and log them (`evidence-handling`).
6. **Skew is measured, not assumed.** Correct for clock drift only with a
   documented reference (NTP log, a known event seen by two systems).

## Workflow

1. **Collect time context per source:** host time zone, NTP/clock status,
   log format and zone, retention window.
2. **Pick depth:** targeted timeline (specific artifacts + window) first;
   full super-timeline only when the window or vector is unknown - plaso
   on a full image can produce tens of millions of events.
3. **Generate** per-source timelines (plaso, MFTECmd bodyfile, Hayabusa,
   EDR/SIEM exports) normalised to UTC.
4. **Find the anchor event:** the most certain malicious event (alert,
   confirmed malicious file creation, first bad logon).
5. **Pivot:** filter all sources to anchor +/- window (start with 5 minutes,
   widen to 1 hour, then the day). New malicious events become new anchors.
6. **Walk backwards** to initial access and **forwards** to impact and
   containment; look for gaps (log clearing, reboots, retention edges).
7. **Curate** only relevant events into the incident timeline CSV with
   analyst and confidence.
8. **Review:** a second analyst checks every high-impact row against its
   source before the report.

## Time zones and clock skew

| Source | Stored as | Notes |
|---|---|---|
| NTFS ($MFT, $J), Prefetch, registry last-write, EVTX | FILETIME UTC (100-ns since 1601-01-01) | Event Viewer displays local time; parsers usually output UTC |
| FAT32 / some USB media | Local time, 2-second resolution (mtime) | No zone stored; infer from host |
| exFAT | Local time + UTC offset field | Use the offset when present |
| Chromium history | WebKit: microseconds since 1601-01-01 UTC | |
| Firefox places.sqlite | PRTime: microseconds since 1970-01-01 UTC | |
| Linux ext4/xfs inodes, journald | Unix epoch UTC (ns/us) | `journalctl --utc` |
| Classic syslog (RFC 3164) | Local time, **no year, no zone** | Infer year from rotation/mtime; zone from host config |
| RFC 5424 / rsyslog high-precision | Includes offset | Preferred |
| Web servers (Apache/nginx) | Local time with offset (`+0100`) | Convert using the offset in the line |
| Cloud (CloudTrail, Entra, M365 UAL) | UTC | M365 UAL `CreationDate` is UTC; portals may show local |
| Firewalls, appliances, SaaS consoles | Often device-local | Check device time zone config |

**Skew:** at acquisition record `date -u` / `w32tm /query /status` and the
reference time. On Windows look for time changes in Security 4616 ("system
time was changed") and System log Kernel-General Event 1; on Linux check
systemd-timesyncd or chronyd logs. Apply a correction offset per host only
with a written justification in the notes, and keep the original timestamp
in `detail`.

## Generating timelines

### plaso

```bash
# Super-timeline of an image (plaso >= 2020 uses --storage-file); restrict parsers to save time
log2timeline.py --storage-file host01.plaso --parsers "win7,!filestat" host01.E01
# Targeted: only artifacts defined in a filter file (e.g. registry, EVTX, prefetch paths)
log2timeline.py --storage-file host01.plaso -f filter_windows.txt host01.E01
# Inspect what was parsed and any errors
pinfo.py host01.plaso
# Export to CSV in UTC for a window
psort.py --output-time-zone UTC -o l2tcsv -w host01_window.csv host01.plaso \
  "date > '2025-03-01 00:00:00' AND date < '2025-03-03 00:00:00'"
# Export for Timesketch / JSON tooling
psort.py -o json_line -w host01.jsonl host01.plaso
```

- Parser preset names (`win7`, `win7_slow`, `linux`, `webhist`) and option
  spelling (`--output-time-zone` vs `--output_time_zone`) changed across
  releases - check `log2timeline.py --help` / `psort.py --help`. The official
  Docker image (`log2timeline/plaso`) avoids dependency issues.
- `-z/--timezone` on log2timeline tells plaso the zone of sources that store
  local time (FAT, some logs).

### Sleuth Kit bodyfile + mactime

```bash
# Bodyfile of a partition (offset in sectors from mmls); -m sets the mount-point prefix
fls -r -m C: -o 2048 host01.raw > host01.body
# Or from an extracted $MFT
MFTECmd.exe -f '$MFT' --body .\out --bdl C
# Linux UAC already produces a bodyfile; merge bodyfiles then render a window in UTC
cat host01.body uac_bodyfile.txt > all.body
mactime -b all.body -d -z UTC 2025-03-01..2025-03-03 > fs_timeline.csv
```

`mactime -d` gives comma-delimited output; `-z` sets the output zone.
Each line shows which of M (modified), A (accessed), C (changed metadata /
MFT entry), B (born) the timestamp represents.

### EVTX timelines

```bash
# Hayabusa: detection + event timeline, UTC, choose a profile (minimal..super-verbose; timesketch-* for import)
hayabusa csv-timeline -d ./evtx/ -o hayabusa.csv -U -p standard
hayabusa json-timeline -d ./evtx/ -o hayabusa.jsonl -L -U -p timesketch-verbose
# Chainsaw: rule hits with timestamps
chainsaw hunt ./evtx/ -s ./sigma/ --mapping ./mappings/sigma-event-logs-all.yml --csv --output ./chainsaw/
```

Profiles, flags (`-U` UTC, `-L` JSONL) and the interactive rule wizard differ
by Hayabusa version - check `hayabusa help csv-timeline`. Severity levels are
rule metadata, not verdicts.

### Timesketch

- Import `.plaso` directly, or CSV/JSONL that has at least `message`,
  `datetime` (ISO 8601) and `timestamp_desc` columns (`timesketch_importer`
  or the web UI).
- One sketch per incident; one timeline per host/source; use saved
  searches, stars, tags (`malicious`, `suspicious`, `benign`) and comments so
  the curation is shared. Built-in analyzers (e.g. browser search, domain,
  Sigma) produce leads - verify before tagging.
- Query examples: `data_type:"windows:evtx:record" AND event_identifier:4624`,
  `filename:*\\Temp\\*.exe`, date-range filter around the anchor.

### Timeline Explorer (EZ tools CSVs)

- Open the CSV, drag a column header to the group-by bar to group (e.g. by
  `EventId`, `Computer`), use the per-column filter row (`contains`,
  `equals`, regex), and the global search.
- Use the Tag column to mark rows of interest, then filter Tagged = true and
  export - that export feeds the incident timeline.
- Keep separate tabs per artifact; merge only curated rows.

## Pivot technique (anchor +/- window)

1. Anchor: `2025-03-01T10:15:42Z` `4624 type 10 from 203.0.113.50 to HOST01 (svc_backup)`.
2. Window +/- 5 min on HOST01: Prefetch, $J, 4688, Sysmon, EDR.
3. Entity pivots: same user on other hosts (4624/4648), same source IP in
   VPN/firewall logs, same hash fleet-wide (EDR), same file name in $J.
4. Each confirmed event becomes a new anchor; repeat until the chain from
   initial access to last activity has no unexplained gaps.
5. Document gaps explicitly ("no logs 09:00-11:00 due to Security log
   rollover") rather than bridging them with assumptions.

```kql
// Defender XDR: everything on one device within +/- 10 minutes of the anchor (tune DeviceName, window)
let anchor = datetime(2025-03-01T10:15:42Z);
union DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceLogonEvents, DeviceRegistryEvents
| where DeviceName =~ "host01.contoso.local"
| where Timestamp between (anchor - 10m .. anchor + 10m)
| project Timestamp, ActionType, FileName, ProcessCommandLine, RemoteIP, AccountName, InitiatingProcessFileName
| order by Timestamp asc
```

~~~spl
```Splunk: all events for one host +/- 10 minutes of the anchor (tune index list and host field)```
index IN (wineventlog, sysmon, edr) host="HOST01" earliest="03/01/2025:10:05:42" latest="03/01/2025:10:25:42"
| table _time, index, sourcetype, EventCode, user, Image, CommandLine, dest_ip
| sort 0 _time
~~~

Splunk `earliest/latest` strings are interpreted in the searching user's
time zone setting - set your user profile to UTC for IR work.

## Incident timeline CSV (case scaffolder format)

Header, exactly:

```csv
timestamp_utc,host,source,event,detail,analyst,confidence
2025-03-01T10:15:42Z,HOST01,Security.evtx 4624 RecordId 88213,RDP logon svc_backup from 203.0.113.50,"LogonType 10; LogonId 0x3E7A1; source workstation unknown",jdoe,high
2025-03-01T10:16:30Z,HOST01,Amcache.hve InventoryApplicationFile,rclone.exe present with SHA-1,"Inferred arrival before first run; no $J record (journal wrapped)",jdoe,medium
2025-03-01T10:17:03Z,HOST01,Prefetch RCLONE.EXE-1A2B3C4D.pf,rclone.exe executed (last run),"Run count 1; path \USERS\SVC_BACKUP\APPDATA\LOCAL\TEMP\RCLONE.EXE",jdoe,high
```

| Column | Content |
|---|---|
| `timestamp_utc` | ISO 8601 UTC with `Z`; for ranges use the start time and give the end in `detail` |
| `host` | Hostname, cloud account/tenant, or service (`M365`, `AWS:123456789012`) |
| `source` | Artifact + locator (log + record ID, file path, query name, plaso storage + row) |
| `event` | One-line what happened, with the timestamp's meaning |
| `detail` | Supporting fields, original timestamp/zone if converted, caveats; quote fields containing commas |
| `analyst` | Initials or handle of who added and verified the row |
| `confidence` | `high` (directly logged, verified in raw source), `medium` (single artifact or inferred from strong artifact semantics), `low` (circumstantial; needs corroboration) |

Sort by `timestamp_utc` before hand-off. Keep raw tool timelines separate
from this curated file; the curated file is what the report cites. (If the
scaffolder in your copy defines different confidence values, follow it.)

## False positives & benign look-alikes

- Mass timestamp changes from AV scans, backup agents, indexing (atime), or
  Windows Update - they flood MACB timelines without being attacker activity.
- Identical timestamps on many files from archive extraction or copy with
  preserved times (looks like timestomping).
- Clock jumps at boot before NTP sync (VMs restored from snapshot,
  hosts with dead CMOS batteries).
- DST transitions in local-time sources producing duplicated or missing hour.

## Pitfalls

- Mixing local and UTC rows in one timeline - the most common and most
  damaging error.
- Running plaso with all parsers on a full image when a targeted run would
  answer the question in a fraction of the time.
- Treating `$SI` modified as "attacker edited the file" without checking $J.
- Inferring syslog year incorrectly around New Year rotation.
- Losing the provenance of a row after copy-paste between spreadsheets.
- Excel auto-reformatting timestamps and stripping leading zeros - import
  CSVs as text or use Timeline Explorer.
- Building the story first and fitting events to it; let gaps stay gaps.

## Output

- Curated incident timeline CSV (format above) in the case folder, sorted,
  reviewed; raw tool outputs (plaso storage, Hayabusa CSV, bodyfiles) kept
  alongside with hashes in the evidence log.
- A short narrative of phases (initial access, execution, persistence,
  lateral movement, exfiltration/impact) with ATT&CK IDs for the report
  (`ir-report-writing`, `/report`) and the post-incident review
  (`post-incident-review`, `/postmortem`). Entry point `/timeline`.

## References

- MITRE ATT&CK: T1070.006 Timestomp, T1070.001 Clear Windows Event Logs,
  T1070.002 Clear Linux or Mac System Logs (gaps to explain).
- plaso documentation (log2timeline.py, psort.py, pinfo.py, filter files).
- The Sleuth Kit: fls(1), mactime(1), bodyfile format.
- Timesketch documentation (import formats, analyzers).
- Hayabusa (Yamato Security) and Chainsaw (WithSecure Labs) READMEs.
- Eric Zimmerman: Timeline Explorer, MFTECmd documentation.
- NIST SP 800-86; NIST SP 800-61 Rev. 3.
