---
name: ir-insider-threat
description: Insider threat investigation for security teams working with HR and legal. Covers case intake and authorisation, privacy and proportionality (GDPR legitimate interest, works council / employee monitoring rules), departing-employee reviews, data-theft evidence from Microsoft Purview DLP and audit (FileCopiedToRemovableMedia, FileUploadedToCloud, FileDownloaded, FileSyncDownloadedFull, AnonymousLinkCreated), Defender for Endpoint USB and file events, Windows USB artifacts (USBSTOR, setupapi.dev.log, event 6416), personal-email and cloud-upload exfiltration (T1052.001, T1567.002, T1048), sabotage indicators, chain of custody and avoiding tip-off. Use when HR or legal asks to "check what a leaver took", "did they copy files to USB", "investigate an employee", a DLP alert involves a named user, or a manager suspects data theft or sabotage.
---

# Insider threat investigation

Insider cases are investigations of a person, not a host. They can end in
dismissal, litigation or prosecution, so process discipline matters as much as
technical skill. Security supplies facts; HR and legal make decisions.

## When to use

- HR, legal or management request a review of a named employee or contractor.
- Departing-employee (leaver) reviews, routine or triggered.
- DLP, UEBA or Insider Risk Management alerts on a named user.
- Suspected sabotage, fraud, policy violation or data theft by someone with
  legitimate access.

If a compromised account (external attacker) is just as likely, run
`alert-triage` / `incident-response` first; switch to this skill once an
insider is the working hypothesis.

## Ground rules

1. **No investigation without written authorisation** from the designated
   authority (HR and legal, per policy) that names the subject, scope, data
   sources and time period. Work outside that scope needs a new authorisation.
2. **Proportionality.** Collect only what the authorised question needs.
   Content review (reading email, files, chats) needs explicit approval and is
   done by the fewest people possible; metadata first.
3. **Need-to-know.** The case is restricted to named people. No discussion in
   shared SOC channels, no case details in general ticket queues.
4. **No tip-off.** No actions visible to the subject (account changes, device
   collection, interviews) until HR/legal decide, unless active harm requires
   immediate containment and the IC/legal approve.
5. **Chain of custody from the first artifact** (`evidence-handling`): hash,
   time, who, where stored. Assume the evidence will be challenged in a tribunal
   or court.
6. **Facts, not character.** Reports state what the evidence shows, with
   alternatives considered (`defender-mindset`). No speculation about motive.

## Workflow

1. **Intake**: who requests, what is alleged, what triggered it, urgency
   (is data leaving right now?), subject's role, access and status (employed,
   on notice, departed).
2. **Authorise**: written scope from HR/legal; check employment contract,
   acceptable-use policy, monitoring notices, works council / union
   agreements and local law (legal confirms).
3. **Plan collection**: list sources, retention, who pulls what, how to
   avoid tip-off.
4. **Preserve**: litigation hold on mailbox/OneDrive (Purview eDiscovery hold)
   before deletion can occur; export audit and DLP logs; preserve devices on
   return (do not reimage leavers' laptops while a case is open).
5. **Analyse** metadata timelines; escalate to content review only with approval.
6. **Report** to HR/legal: facts, timeline, confidence, gaps.
7. **Support action**: containment at the agreed moment (often aligned with
   an HR meeting), evidence handover, post-case access review.

## Privacy and proportionality

| Principle | Practice |
|---|---|
| Lawful basis | Legal confirms the basis (e.g. GDPR Art. 6(1)(f) legitimate interest with a documented balancing test, or contractual/legal obligation) |
| Transparency | Monitoring policy and notices exist; covert monitoring only where law allows and legal approves |
| Data minimisation | Time window and data types limited to the allegation |
| Purpose limitation | Evidence used only for the authorised purpose |
| Special category data | Health, union, religion, private life content encountered by accident is not recorded beyond necessity |
| Retention | Case data retained per legal's instruction, then deleted |
| Employee representatives | Some jurisdictions require works council involvement for monitoring tools or investigations; legal confirms |

## Data sources and evidence

### Microsoft 365 / Purview

| Activity (Purview audit / Endpoint DLP) | Meaning | ATT&CK |
|---|---|---|
| `FileCopiedToRemovableMedia` | Endpoint DLP: file copied to USB | T1052.001 |
| `FileUploadedToCloud` | Endpoint DLP: file uploaded via browser to a cloud service | T1567.002 |
| `FileCopiedToNetworkShare`, `FilePrinted`, `FileCopiedToClipboard` | Endpoint DLP: other egress paths | T1048 |
| `FileDownloaded`, `FileSyncDownloadedFull` | SharePoint/OneDrive download or full sync to a device | T1530 |
| `AnonymousLinkCreated`, `SharingInvitationCreated`, `CompanyLinkCreated`, `SharingSet` | Sharing outside the organisation | T1567 |
| `FileDeleted`, `FileRecycled`, `FileDeletedFirstStageRecycleBin` | Mass deletion (sabotage or cover-up) | T1485 |
| `Send` (Exchange) with external recipients and attachments | Mail to personal accounts | T1114.003, T1048 |
| `SearchQueryInitiatedSharePoint` / `SearchQueryInitiatedExchange` | What they searched for (if enabled) | T1213 |

Endpoint DLP activities require onboarded devices and DLP policies in place
before the event; activity explorer and audit retention depend on licensing.

### Endpoint (Defender for Endpoint / Windows)

| Source | Artifact |
|---|---|
| `DeviceEvents` ActionType `UsbDriveMounted`, `PnpDeviceConnected` | USB device connections with device/vendor/serial info in `AdditionalFields` |
| `DeviceFileEvents` | Files created on removable drives (`FolderPath` on the mounted drive letter), archive creation, renames |
| `DeviceNetworkEvents` / proxy | Uploads to personal cloud storage, webmail, file-transfer sites |
| Registry `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`, `HKLM\SYSTEM\MountedDevices`, `NTUSER.DAT\...\Explorer\MountPoints2` | USB devices seen, drive letters, which user |
| `C:\Windows\INF\setupapi.dev.log` | First install time of a device |
| Event 6416 (Security, requires "Audit PNP Activity"), `Microsoft-Windows-Partition/Diagnostic` 1006 | Device connection events |
| LNK files, Jump Lists, Shellbags | Files and folders opened from removable or network locations (`windows-forensics`) |
| Browser history | Webmail, personal cloud, file-sharing sites |

### Other

- VPN and badge (physical access) logs for out-of-hours activity, through HR/
  facilities with authorisation.
- SaaS audit logs (CRM exports, source-code platform clones, ticketing).
- Printer/print server logs.
- Source code: mass `git clone`/archive downloads on the code platform.

## Queries

```kql
// Defender XDR: USB mounts by the subject's devices in the review window. Tune: device names, window.
DeviceEvents
| where Timestamp between (datetime(2026-02-01) .. datetime(2026-03-01))
| where DeviceName in~ ("lt-jdoe-01")
| where ActionType in ("UsbDriveMounted", "PnpDeviceConnected")
| extend AF = parse_json(AdditionalFields)
| project Timestamp, DeviceName, ActionType, AF
```

```kql
// Defender XDR: files written to removable drives. Tune: drive letters seen in UsbDriveMounted results.
DeviceFileEvents
| where Timestamp between (datetime(2026-02-01) .. datetime(2026-03-01))
| where DeviceName in~ ("lt-jdoe-01")
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where FolderPath startswith "E:\\" or FolderPath startswith "F:\\"
| summarize Files = count(), Bytes = sum(FileSize), Examples = make_set(FileName, 20) by bin(Timestamp, 1h)
```

```kql
// Sentinel OfficeActivity: SharePoint/OneDrive downloads and external sharing by the subject.
OfficeActivity
| where TimeGenerated > ago(90d)
| where UserId =~ "j.doe@corp.example"
| where Operation in ("FileDownloaded", "FileSyncDownloadedFull", "AnonymousLinkCreated",
                      "SharingInvitationCreated", "CompanyLinkCreated", "FileDeleted")
| summarize Count = count(), Sites = make_set(Site_Url, 10) by Operation, bin(TimeGenerated, 1d)
| order by TimeGenerated asc
```

```kql
// Defender XDR: mail with attachments to personal domains. Tune: list of consumer mail domains.
let personal = dynamic(["gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "icloud.com", "proton.me"]);
EmailEvents
| where Timestamp > ago(90d)
| where SenderFromAddress =~ "j.doe@corp.example" and EmailDirection == "Outbound"
| where tostring(split(RecipientEmailAddress, "@")[1]) in~ (personal)
| where AttachmentCount > 0
| join kind=leftouter (EmailAttachmentInfo | project NetworkMessageId, FileName, FileType, SHA256) on NetworkMessageId
| project Timestamp, RecipientEmailAddress, Subject, FileName, FileType, SHA256
```

~~~spl
```Splunk: proxy uploads (POST, large bytes_out) by the subject to cloud storage. Tune: index, field names, threshold.```
index=proxy user="jdoe" http_method=POST bytes_out>5000000 earliest=-90d
| stats sum(bytes_out) as bytes count by dest, url_domain, date_mday
| sort - bytes
~~~

## Departing-employee review

Trigger: resignation, notice of termination, or move to a competitor (per
policy, some organisations review all leavers in sensitive roles).

| Window | Look for |
|---|---|
| 30-90 days before notice through last day | Download/sync volume vs the user's own baseline, USB use, personal-email forwarding, uploads to personal cloud, printing spikes, access to repositories outside their role, mass `git` clones, CRM/contact exports |
| Last week | Deletion of files or mailboxes, changes to shared systems, scheduled tasks or scripts left behind (sabotage), credential sharing |
| After departure | Any authentication with their accounts, shared/service credentials they knew, VPN, SaaS access not covered by SSO |

Offboarding controls to verify (`hardening-m365-entra`): accounts disabled
on time, sessions revoked, devices returned and preserved if the case is open,
shared secrets rotated, mail forwarding removed, SaaS accounts outside SSO closed.

## Avoiding tip-off

- Use read-only, back-end data sources first (audit logs, EDR telemetry) that
  produce no user-visible change.
- Do not change the subject's permissions, group memberships or device state
  until the agreed time; remote device collection can be noticed (performance,
  prompts) - coordinate timing.
- Restrict EDR/SIEM access to the case; some tools show who viewed a user's
  profile or alerts.
- Managers are often close to the subject; brief them only as HR directs.
- Avoid queries or sharing links that notify the subject (e.g. requesting
  access to their files through normal sharing).

## Containment (with HR/legal timing)

| Action | When | Note |
|---|---|---|
| Litigation / eDiscovery hold | Immediately on authorisation | Invisible to the user; prevents deletion |
| Block USB / upload via DLP policy for the user | When ongoing exfil risk outweighs tip-off risk | Visible as blocks; legal/HR decide |
| Disable account, revoke sessions, collect device | Usually at the HR meeting | Coordinate to the minute; preserve device without reimaging |
| Revoke access to specific repositories/systems | Ongoing high-risk access | |
| Rotate shared secrets the subject knew | At or after departure | Service accounts, vault entries, shared admin passwords |

## Chain of custody

- Device seized: record make, model, serial, condition, who handed it over,
  time, seal number; image with a write blocker or verified acquisition tool;
  hash the image (`evidence-handling`).
- Log exports: hash each export, record query, time range, tool, operator.
- Content reviewed: log who viewed what, when, and under which approval.
- Store in an access-controlled location with an access log.

## False positives & benign look-alikes

- Bulk downloads due to OneDrive sync of a new device, migrations, or a
  legitimate project handover before leaving.
- USB use where it is part of the job (field engineers, media, labs).
- Sending work to a personal address to work from home (policy violation,
  but intent differs from theft; report facts, not intent).
- Shared accounts or devices: confirm attribution (who was logged on, badge
  and VPN records) before naming a person.
- Compromised account: an external attacker using the employee's account
  (check sign-in anomalies first).

## Pitfalls

- Starting technical work on a manager's verbal request without HR/legal authorisation.
- Reimaging a leaver's laptop before the review is complete.
- Over-collecting (whole mailbox read) when metadata answers the question.
- Attributing activity to a person from an account name alone.
- Discussing the case in team channels; tipping off the subject.
- Writing conclusions about motive or character in the report.

## Output

- Authorisation record, collection plan, evidence log with hashes.
- Activity timeline (UTC) of the relevant actions, with volumes and
  destinations, confidence and gaps.
- Factual report for HR/legal (`ir-report-writing`), no recommendations about
  sanctions.
- Control gaps to `hardening-m365-entra`, `logging-coverage` and
  `detection-engineering`; lessons to `post-incident-review`.

## References

- Carnegie Mellon University SEI CERT, Common Sense Guide to Mitigating
  Insider Threats (latest edition).
- CISA, Insider Threat Mitigation Guide.
- NIST SP 800-53 Rev. 5, PM-12 Insider Threat Program; NIST SP 800-61 Rev. 3.
- Regulation (EU) 2016/679 (GDPR) Art. 5, 6, 88; EDPB/Article 29 WP Opinion
  2/2017 on data processing at work.
- Microsoft Learn: Endpoint DLP activities; Purview audit log activities;
  Insider Risk Management; eDiscovery holds.
- MITRE ATT&CK: T1052.001, T1567.002, T1048, T1530, T1485 -
  https://attack.mitre.org/techniques/T1052/001/
