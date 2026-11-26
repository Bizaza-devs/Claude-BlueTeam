---
name: hunt-exfiltration
description: Hypothesis-driven hunt for data exfiltration and the staging that precedes it. Covers outbound volume anomalies per host against baseline (Zeek conn.log, firewall SentBytes, CIM Network_Traffic), rclone / MEGAsync / MEGAcmd / restic / WinSCP and cloud-sync tooling, archive staging with 7-Zip / WinRAR / tar of file-share content, DNS and ICMP exfil, uploads to personal cloud and file-sharing sites, mailbox auto-forwarding rules (New-InboxRule, Set-Mailbox ForwardingSmtpAddress), USB mass storage (MDE UsbDriveMounted, Event ID 6416), S3 / Azure Blob public sharing and snapshot sharing, and correlation with DLP alerts. Maps to T1041, T1048, T1567, T1052.001, T1537, T1560.001, T1074, T1114.003. Use when asked to "hunt for exfil", "did data leave", "check for rclone", "find large uploads", "look for mailbox forwarding", or during double-extortion ransomware and insider cases.
---

# Hunt: data exfiltration and staging

## When to use

- Ransomware or intrusion case: answer "was data taken, how much, where to" (double extortion).
- Insider-risk lead (departing employee, DLP alert cluster) needing network/endpoint corroboration.
- Proactive hunt for exfil tooling and staging that EDR did not alert on.
- Regulatory question (breach notification) where the scope of data loss must be evidenced.

Not for: legal/HR handling of an insider (`ir-insider-threat`), mailbox compromise end-to-end (`ir-bec-m365`), cloud account IR (`ir-cloud-aws`, `ir-azure-entra`).

## Ground rules

- **"Exfiltration occurred" needs two independent sources**: e.g. staging artefact on the host (archive, rclone config) **and** a network record (bytes out to the destination), or a cloud audit record of the download/share. One alone is "possible exfiltration".
- **Quantify with stated precision.** Report bytes from the source that measured them (firewall, Zeek, proxy, CloudTrail) and say whether it includes protocol overhead or compression. Never extrapolate a total from a sample without saying so.
- **Data-loss claims drive legal notification.** Mark every number as observed / estimated, keep the queries and exports as evidence (`evidence-handling`), and route the conclusion through the incident commander and legal before it leaves the team.
- **Insider cases are privacy-sensitive**: hunt only on accounts and devices in scope of an approved case; record who authorised it.
- **Do not alert the actor**: no blocking of destinations, disabling forwarding rules or revoking shares without incident-commander approval (`/contain`); capture the rule/share configuration first.

## Workflow

1. **Frame the question**: which data (crown-jewel shares, databases, mailboxes, repos), which actors/hosts, which window. For ransomware, start 2-4 weeks before encryption.
2. **Map egress paths**: proxy, firewall, direct cloud, VPN split tunnel, email, USB, cloud-to-cloud (no network hop through you at all).
3. **Find staging first** (it is noisier and local): archives, collection directories, rclone/MEGA configs, unusual reads of shares.
4. **Measure outbound volume** per host and per destination against baseline; rank outliers.
5. **Hunt tooling and channels**: sync/transfer tools, personal cloud uploads, DNS/ICMP, mail forwarding, USB, cloud sharing changes.
6. **Correlate with DLP / CASB alerts** on the same user, host and window.
7. **Bound the loss**: list files/objects touched, bytes out, destination, timestamps; hand to IR with confidence level.

## Hypothesis templates

- "Before the encryption event, the actor staged file-share content into password-protected archives on <host> and uploaded them with rclone to MEGA or an S3-compatible endpoint."
- "A host's outbound bytes to a single external destination exceeded its 30-day baseline by more than 3 standard deviations during non-business hours."
- "A departing user forwarded mail externally or uploaded documents to personal cloud storage in their last 30 days."
- "An identity changed an S3 bucket policy/ACL, an EBS/RDS snapshot or an Azure container to public or cross-account access."
- "Data was exfiltrated over DNS or ICMP from a segment without direct internet access."

## ATT&CK sub-technique map

| Behaviour | Technique |
|---|---|
| Archive with 7-Zip / WinRAR / tar, password, split volumes | T1560.001 Archive via Utility |
| Local / remote staging directory | T1074.001 Local Data Staging, T1074.002 Remote Data Staging |
| Collection from network shares | T1039 Data from Network Shared Drive |
| rclone / MEGA / restic to cloud storage | T1567.002 Exfiltration to Cloud Storage |
| Paste / text storage sites | T1567.003; webhooks T1567.004 |
| Upload to code repositories | T1567.001 |
| Over existing C2 | T1041 |
| FTP/SFTP/DNS/ICMP or other non-C2 protocol | T1048.001/.002/.003 |
| Size-limited chunks, scheduled transfers | T1030, T1029 |
| Automated exfil | T1020 |
| USB | T1052.001 |
| Cloud: share snapshot / bucket to other account | T1537 Transfer Data to Cloud Account |
| Mail forwarding rules | T1114.003 Email Forwarding Rule |

## Data sources required

| Source | Use | Gap to watch |
|---|---|---|
| Firewall / NGFW (`CommonSecurityLog` `SentBytes`, PAN `bytes_out`, CIM `Network_Traffic`) | Bytes out per host/destination | Session vs. interval accounting; NAT hides inner host |
| Zeek `conn.log` (`orig_bytes`, `local_orig`, `local_resp`) | Bytes and ratios, ICMP | `local_orig/local_resp` need `Site::local_nets` configured |
| Proxy / SWG | URL, method, bytes up, user, category | Direct-to-IP and non-proxied tools bypass it |
| EDR process / file events | Tool execution, archive creation, file reads | MDE `DeviceNetworkEvents` has no byte counts |
| Windows Security log | 5140/5145 share access, 4663 object access, 6416 new device | Needs audit policy + SACLs |
| M365 Unified Audit Log (`OfficeActivity`, `CloudAppEvents`) | Inbox rules, forwarding, SharePoint/OneDrive downloads and sharing | Retention by licence; ingestion delay |
| CloudTrail (management + S3 data events) | Policy/ACL/snapshot sharing, `GetObject` volume | Data events are off by default and cost money |
| Azure `StorageBlobLogs`, `AzureActivity` | Blob reads, key listing, public access changes | Diagnostic settings must be enabled per account |
| DLP / CASB alerts | Content-aware signal | Coverage by channel varies |

## Queries

### Outbound volume vs baseline (KQL, firewall in Sentinel)

```kql
// Hosts whose bytes out today exceed 30-day mean + 3 sd (or > 1 GB with no history). Tune: DeviceAction values, thresholds, NAT ranges.
let baseline = CommonSecurityLog
    | where TimeGenerated between (ago(31d) .. ago(1d))
    | where not(ipv4_is_private(DestinationIP))
    | summarize DailyOut = sum(SentBytes) by SourceIP, Day = bin(TimeGenerated, 1d)
    | summarize AvgOut = avg(DailyOut), StdOut = stdev(DailyOut), Days = count() by SourceIP;
CommonSecurityLog
| where TimeGenerated > ago(1d) and not(ipv4_is_private(DestinationIP))
| summarize TodayOut = sum(SentBytes), TopDests = make_set(DestinationIP, 10) by SourceIP
| join kind=leftouter baseline on SourceIP
| extend Z = iff(StdOut > 0, (TodayOut - AvgOut) / StdOut, real(null))
| where (isnotnull(Z) and Z > 3 and TodayOut > 200000000) or (isnull(AvgOut) and TodayOut > 1073741824)
| order by TodayOut desc
```

```kql
// Hourly anomaly detection per host with built-in decomposition. Tune threshold (3.0) and minimum bytes.
CommonSecurityLog
| where TimeGenerated > ago(30d) and not(ipv4_is_private(DestinationIP))
| make-series BytesOut = sum(SentBytes) default = 0 on TimeGenerated step 1h by SourceIP
| extend (Flag, Score, Baseline) = series_decompose_anomalies(BytesOut, 3.0, -1, 'linefit')
| mv-expand TimeGenerated to typeof(datetime), BytesOut to typeof(long), Flag to typeof(int), Score to typeof(double)
| where Flag == 1 and BytesOut > 500000000
```

### Outbound volume (SPL, CIM Network_Traffic)

```spl
| tstats sum(All_Traffic.bytes_out) as bytes_out from datamodel=Network_Traffic where All_Traffic.action=allowed by All_Traffic.src, All_Traffic.dest, _time span=1d ```Daily bytes out per src/dest with z-score per src. Requires accelerated CIM data model; tune thresholds.```
| rename All_Traffic.* as *
| where NOT cidrmatch("10.0.0.0/8", dest) AND NOT cidrmatch("172.16.0.0/12", dest) AND NOT cidrmatch("192.168.0.0/16", dest)
| stats sum(bytes_out) as day_out by src, _time
| eventstats avg(day_out) as avg_out stdev(day_out) as sd_out by src
| eval z=if(sd_out>0, (day_out-avg_out)/sd_out, null())
| where z>3 AND day_out>200000000
| sort - day_out
```

### Outbound volume and upload ratio (bash on Zeek)

```bash
# Top internal senders to external destinations, and pairs where upload >> download (ratio > 10).
zcat conn.*.log.gz | zeek-cut id.orig_h id.resp_h orig_bytes resp_bytes local_orig local_resp \
| awk '$5=="T" && $6=="F" {o[$1" "$2]+=$3; r[$1" "$2]+=$4}
  END{for(k in o) if(o[k]>100000000) printf "%s out=%d in=%d ratio=%.1f\n",k,o[k],r[k],(r[k]>0?o[k]/r[k]:o[k])}' \
| sort -t= -k2,2nr | head -30
```

### Exfil and sync tooling (KQL, MDE)

```kql
// rclone, MEGA, restic, WinSCP etc. by name, original file name or tell-tale arguments (renamed binaries).
// Verify ProcessVersionInfoOriginalFileName values against the real binaries in your estate.
let Tools = dynamic(["rclone.exe","megasync.exe","megacmdserver.exe","mega-put.exe","restic.exe","winscp.exe","pscp.exe","psftp.exe","filezilla.exe"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ (Tools) or ProcessVersionInfoOriginalFileName in~ (Tools)
    or (ProcessCommandLine has_any ("copy","sync","move","copyto")
        and ProcessCommandLine has_any ("--transfers","--multi-thread-streams","--no-check-certificate","--ignore-existing","--max-age","--config","mega:","s3:","sftp:","ftp:"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessVersionInfoOriginalFileName, FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, SHA256
```

```kql
// rclone / MEGA configuration files written (rclone.conf holds remotes and often credentials - collect as evidence).
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName =~ "rclone.conf" or FolderPath has @"\MEGAsync" or FolderPath has @"\.megaCmd"
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, FolderPath, InitiatingProcessFileName
```

Other tools seen in public ransomware reporting worth adding to the list: custom stealers (e.g. StealBit, ExMatter), `curl -T` / `--upload-file`, PowerShell `Invoke-WebRequest -Method Put -InFile`, `bitsadmin /upload`, `scp`/`sftp` from Linux pivots. rclone's default HTTP user-agent starts with `rclone/` - hunt it in proxy logs too.

### Archive staging (KQL, MDE)

```kql
// Archivers run with password, header encryption, split volumes or UNC (share) sources. Tune: sanctioned backup hosts.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("7z.exe","7za.exe","7zr.exe","7zg.exe","rar.exe","winrar.exe","makecab.exe","tar.exe")
    or ProcessVersionInfoOriginalFileName in~ ("7z.exe","7za.exe","rar.exe","winrar.exe")
| extend Password = ProcessCommandLine matches regex @"\s-(p|hp)\S*",
         Split = ProcessCommandLine matches regex @"\s-v\d+[kmgKMG]?",
         HeaderEnc = ProcessCommandLine has "-mhe",
         FromShare = ProcessCommandLine has @"\\"
| where Password or Split or HeaderEnc or FromShare
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
```

```kql
// Large archives created (> 100 MB) - the staging output. FileSize can be empty on some events.
DeviceFileEvents
| where Timestamp > ago(30d) and ActionType in ("FileCreated","FileModified")
| where FileName matches regex @"(?i)\.(7z|rar|zip|tar|gz|cab)(\.\d{3})?$" and FileSize > 104857600
| summarize Files = count(), TotalBytes = sum(FileSize), Paths = make_set(FolderPath, 10) by DeviceName, InitiatingProcessFileName
```

```spl
index=wineventlog source="WinEventLog:Security" EventCode=5145 earliest=-7d ```Mass share reads before staging: one account touching many files on file servers (needs 5145 auditing). Tune thresholds.```
| bin _time span=1h
| stats dc(Relative_Target_Name) as files dc(Share_Name) as shares by _time, Account_Name, Source_Address, host
| where files>1000
```

### DNS and ICMP exfiltration (bash on Zeek)

```bash
# ICMP pairs with large average payloads (default ping payloads are 32 bytes on Windows, 56 on Linux).
zcat conn.*.log.gz | zeek-cut id.orig_h id.resp_h proto orig_bytes orig_pkts \
| awk '$3=="icmp" {b[$1" "$2]+=$4; p[$1" "$2]+=$5}
  END{for(k in b) if(p[k]>20) printf "%s bytes=%d pkts=%d avg=%.0f\n",k,b[k],p[k],b[k]/p[k]}' \
| sort -t= -k4,4nr | head -20

# DNS: total query-name bytes per client and registered domain (exfil encodes data in the name).
zcat dns.*.log.gz | zeek-cut id.orig_h query \
| awk '{n=split($2,p,"."); if(n<3) next; k=$1" "p[n-1]"."p[n]; b[k]+=length($2); q[k]++}
  END{for(k in b) if(b[k]>500000) printf "%s qname_bytes=%d queries=%d\n",k,b[k],q[k]}' | sort -t= -k2,2nr | head
```

For subdomain entropy, TXT ratio and NXDOMAIN maths, reuse the DNS section of `hunt-c2-beaconing`.

### Uploads to personal cloud / file sharing (SPL, CIM Web)

```spl
index=proxy earliest=-30d (http_method=POST OR http_method=PUT) ```Upload volume to file-sharing services per user. Tune: domain list, sanctioned tenants, bytes field name.```
| search url_domain IN ("*dropbox.com","*dropboxapi.com","mega.nz","*.mega.nz","*.mega.co.nz","*wetransfer.com","transfer.sh","file.io","*gofile.io","drive.google.com","*.googleusercontent.com","*.box.com")
| stats sum(bytes_out) as uploaded count as requests values(url_domain) as domains by user, src
| where uploaded>104857600
| sort - uploaded
```

Distinguish corporate tenants from personal ones: OneDrive/SharePoint personal vs. corporate host names, Google Workspace domain restrictions, Box enterprise IDs - most SWGs/CASBs expose a tenant or instance field.

### Mailbox forwarding (KQL, Sentinel OfficeActivity)

```kql
// Inbox rules and mailbox forwarding to external addresses. UpdateInboxRules (Outlook client) keeps details in
// OperationProperties rather than Parameters - inspect both. Tune: accepted domains list.
let Internal = dynamic(["contoso.com"]);   // replace with your accepted domains
OfficeActivity
| where TimeGenerated > ago(90d)
| where Operation in ("New-InboxRule","Set-InboxRule","UpdateInboxRules","Set-Mailbox","New-TransportRule","Set-TransportRule")
| extend Details = strcat(tostring(Parameters), tostring(OperationProperties))
| where Details has_any ("ForwardTo","ForwardAsAttachmentTo","RedirectTo","ForwardingSmtpAddress","ForwardingAddress","BlindCopyTo")
| where not(Details has_any (Internal))
| project TimeGenerated, UserId, Operation, ClientIP, Details
```

Also check the mailbox's current state (`Get-Mailbox | ft ForwardingSmtpAddress,DeliverToMailboxAndForward`, `Get-InboxRule`) - audit gaps happen. Full BEC workflow: `ir-bec-m365`.

### USB mass storage (KQL, MDE / Windows)

```kql
// USB drive mounts and files written to non-system drive letters on the same device within 2 h.
// Verify the AdditionalFields keys and drive-letter format in your tenant.
let Mounts = DeviceEvents
    | where Timestamp > ago(30d) and ActionType == "UsbDriveMounted"
    | extend AF = parse_json(AdditionalFields)
    | project MountTime = Timestamp, DeviceName, DriveLetter = tostring(AF.DriveLetter),
              Product = tostring(AF.ProductName), Serial = tostring(AF.SerialNumber);
Mounts
| join kind=inner (DeviceFileEvents | where Timestamp > ago(30d) and ActionType == "FileCreated" and not(FolderPath startswith @"C:\")
    | project FileTime = Timestamp, DeviceName, FolderPath, FileName, FileSize, InitiatingProcessAccountName) on DeviceName
| where FileTime between (MountTime .. (MountTime + 2h)) and indexof(FolderPath, DriveLetter) == 0
| summarize Files = count(), Bytes = sum(FileSize), Sample = make_set(FileName, 20) by DeviceName, Product, Serial, InitiatingProcessAccountName
```

```spl
index=wineventlog source="WinEventLog:Security" EventCode=6416 earliest=-30d ```New external device recognised (requires Audit PnP Activity). Removable-storage file access is 4663 with Audit Removable Storage.```
| stats count values(DeviceDescription) as devices values(ClassName) as classes by host
```

### Cloud sharing changes (Athena SQL, CloudTrail)

```sql
-- Bucket/object exposure and snapshot/AMI sharing in the last 30 days. Table name/partitions depend on your Athena setup.
-- PutObjectAcl appears only if S3 data events are enabled.
SELECT eventtime, eventname, awsregion, sourceipaddress, useridentity.arn AS actor,
       json_extract_scalar(requestparameters, '$.bucketName') AS bucket, requestparameters
FROM cloudtrail_logs
WHERE eventtime > to_iso8601(current_timestamp - interval '30' day)
  AND errorcode IS NULL
  AND eventname IN ('PutBucketPolicy','DeleteBucketPolicy','PutBucketAcl','PutObjectAcl',
                    'PutBucketPublicAccessBlock','DeleteBucketPublicAccessBlock','PutBucketReplication',
                    'ModifySnapshotAttribute','ModifyDBSnapshotAttribute','ModifyDBClusterSnapshotAttribute',
                    'ModifyImageAttribute')
ORDER BY eventtime DESC;
```

```sql
-- Bulk object reads per principal per hour (S3 data events required). Tune threshold.
SELECT useridentity.arn AS actor, sourceipaddress,
       json_extract_scalar(requestparameters, '$.bucketName') AS bucket,
       date_trunc('hour', from_iso8601_timestamp(eventtime)) AS hr, count(*) AS gets
FROM cloudtrail_logs
WHERE eventname = 'GetObject' AND eventtime > to_iso8601(current_timestamp - interval '7' day)
GROUP BY 1, 2, 3, 4
HAVING count(*) > 5000
ORDER BY gets DESC;
```

### Azure Blob exposure and bulk reads (KQL)

```kql
// Anonymous/SAS reads and large read volumes per caller. Needs Storage diagnostic settings -> StorageBlobLogs.
StorageBlobLogs
| where TimeGenerated > ago(7d) and OperationName == "GetBlob" and StatusCode == 200
| summarize Reads = count(), Bytes = sum(ResponseBodySize), Blobs = dcount(Uri) by AccountName, AuthenticationType, CallerIpAddress
| where AuthenticationType in ("Anonymous","SAS") or Bytes > 5000000000
```

```kql
// Control-plane changes that enable exfil: key listing, container public access, account settings.
AzureActivity
| where TimeGenerated > ago(30d) and ActivityStatusValue =~ "Success"
| where OperationNameValue in~ ("MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION",
      "MICROSOFT.STORAGE/STORAGEACCOUNTS/BLOBSERVICES/CONTAINERS/WRITE","MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE")
| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, _ResourceId
```

### DLP correlation (KQL, Defender XDR)

```kql
// Users with DLP alerts who also show exfil tooling or archive staging on their devices in the same window.
// Verify the ServiceSource / DetectionSource values for Purview DLP in your tenant.
let DlpUsers = AlertInfo
    | where Timestamp > ago(14d) and ServiceSource has "Data Loss Prevention"
    | join kind=inner (AlertEvidence | where EntityType == "User") on AlertId
    | distinct AccountUpn = tolower(AccountUpn);
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ("rclone.exe","7z.exe","rar.exe","winrar.exe","megasync.exe","winscp.exe")
| extend Upn = tolower(InitiatingProcessAccountUpn)
| where Upn in (DlpUsers)
| project Timestamp, DeviceName, Upn, FileName, ProcessCommandLine
```

## Baselining and stacking

- **Per-host daily bytes out**, 30-day mean/sd and hour-of-day profile; separate server roles (backup servers, build agents and CDNs legitimately push terabytes).
- **Per-destination popularity**: one host sending gigabytes to an ASN/domain no other host uses.
- **Tool prevalence**: count devices running each archiver/transfer tool; rare + recent = lead.
- **Per-user upload profile** in the proxy/CASB for the users in scope.
- **Allowlist** backup targets, replication links, sanctioned SaaS tenants - versioned with an owner.

## Verdict and escalation

| Verdict | Evidence that moves it there |
|---|---|
| True Positive (exfiltration) | Staging or tooling artefact + network/cloud record of transfer to an unsanctioned destination, timeline consistent |
| True Positive (attempt / staging only) | Staging/tooling present, no transfer record (blocked, not yet sent, or visibility gap - say which) |
| Benign True Positive | Sanctioned backup, migration project, approved vendor share - confirmed by owner and change record |
| False Positive | Volume spike explained by measurement (NAT aggregation, log duplication, session-accounting artefact) |
| Needs more data | No egress logs for the path, no S3 data events, TLS not inspected, retention expired |

Escalate immediately to the incident commander (`incident-response`, `ir-ransomware`, `ir-insider-threat` as applicable) when any TP is found, when regulated data (personal, health, payment, export-controlled) may be involved, or when the destination is still receiving data. Containment of an active transfer (block destination, disable account/forwarding rule, revoke share) is an approval-gated `/contain` step: preserve the rule/share/config and flow logs first.

## False positives & benign look-alikes

| Look-alike | Why it looks like exfil | How to separate |
|---|---|---|
| Backup agents (Veeam, Commvault, cloud backup) | Large sustained uploads, archives | Known service account, scheduled, sanctioned destination |
| OneDrive Known Folder Move / sync onboarding | Burst of uploads | Corporate tenant, rollout calendar |
| Developers pushing to Git / artifact registries | Big uploads, archives | Corporate org/registry, CI identity |
| IT using 7-Zip for log collection or support bundles | Password archives | Ticket reference, IT admin account, small scope |
| Video conferencing / streaming | High bytes out | Known UDP media ranges, business hours |
| Legitimate external sharing in SharePoint/Drive | Sharing events | Business owner, link expiry, recipient domain is partner |
| Approved mail forwarding (shared mailbox to ticketing system) | Forwarding rule | Destination is sanctioned SaaS, documented |
| USB use by AV / imaging teams | Device mounts | Approved device serials / Device Control policy |

## Pitfalls

- Cloud-to-cloud exfil (OAuth app, sharing link, cross-account snapshot) never crosses your network - check SaaS/cloud audit logs, not only firewalls.
- Compressed + encrypted archives make DLP blind; the archive creation event is the signal.
- Firewalls log bytes at session end; a long upload may appear only after it finishes, or be split across interim logs.
- Exfil throttled to "low and slow" (T1030) defeats daily z-scores - also stack cumulative bytes per destination over 30 days.
- Renamed rclone binaries: hunt arguments, config file and user-agent, not just file names.
- S3 `GetObject` volume needs data events; without them you can only prove exposure, not download.

## Output

Hunt report stub (`cases/<id>/hunts/exfiltration-<date>.md`):

```markdown
# Hunt report - Exfiltration - <date>
- Hypothesis / question: <filled template>
- ATT&CK: <T-IDs>
- Scope: users/hosts/data stores <list>, window <UTC>, authorised by <name> (insider cases)
- Data sources and gaps: <list; e.g. no S3 data events before <date>>
- Findings:
  | Time (UTC) | Host/identity | Staging artefact | Tool/channel | Destination | Bytes (source) | Confidence |
- Estimated data loss: <observed bytes, files/objects, data classes> - observed vs estimated stated
- Verdict: <TP / attempt / BTP / FP / needs data>
- Escalations and containment requests: <IDs, approvals>
- Detection opportunities: <hand-off to detection-engineering>
```

Hand-offs: loss scoping and notification -> `incident-response`, `ir-report-writing`; mailbox -> `ir-bec-m365`; insider -> `ir-insider-threat`; cloud -> `ir-cloud-aws`, `ir-azure-entra`, `hunt-cloud-control-plane`; host artefacts -> `windows-forensics`, `timeline-analysis`; preventive controls -> `hardening-cloud`, `hardening-m365-entra`; rules -> `detection-engineering`, `/detect`.

## References

- MITRE ATT&CK: TA0010 Exfiltration; T1567.002 (https://attack.mitre.org/techniques/T1567/002/), T1048, T1041, T1052.001, T1537, T1560.001, T1074, T1114.003
- CISA #StopRansomware Guide (data exfiltration and double extortion)
- Microsoft Learn: DeviceEvents, DeviceFileEvents, DeviceProcessEvents, OfficeActivity, StorageBlobLogs schemas
- Microsoft Learn: Audit PnP Activity (event 6416), Audit Removable Storage, Detailed File Share (5145)
- AWS documentation: Logging Amazon S3 API calls using CloudTrail (data events); querying CloudTrail logs with Athena
- rclone documentation (flags, config file location, user-agent)
