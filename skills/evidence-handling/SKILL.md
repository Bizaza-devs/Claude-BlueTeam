---
name: evidence-handling
description: Digital evidence handling for incident response and forensics. Covers chain of custody form fields, SHA-256 hashing at acquisition and at every transfer, hardware and software write blockers, forensic image formats (E01/EWF, raw/dd, AFF4) and tools (FTK Imager, ewfacquire, dc3dd, guymager, ewfverify), cloud and log evidence preservation, legal hold, privacy and GDPR data minimisation, PII redaction in reports, encrypted evidence storage, retention and destruction, and the evidence-log CSV used by the case scaffolder (item_id, description, source_host, acquired_utc, acquired_by, method, sha256, storage_location, notes). Use when asked to "preserve evidence", "start chain of custody", "image this disk", "hash and log", "legal hold", "can we share this report", "redact PII", or when opening a case with /ir.
---

# Evidence handling

## When to use

- At the start of every incident case (`/ir`), before any collection.
- Whenever an item is acquired, copied, transferred, analysed, returned or
  destroyed.
- When legal, HR, regulators or law enforcement may become involved - assume
  they might until counsel says otherwise.
- Before a report or IOC package leaves the core IR team (redaction,
  minimisation, TLP).

Acquisition technique details live in `windows-forensics`,
`linux-forensics` and `memory-forensics`; this skill is the procedure that
wraps them.

## Ground rules

1. **Hash + acquisition time + who before any analysis.** No item is
   analysed until it has a SHA-256, a UTC acquisition time, the acquirer's
   name and an evidence-log row.
2. **Verify on every move.** Re-hash after each transfer or copy and record
   the result; a mismatch stops work on that copy until explained.
3. **Originals are never analysed.** Keep a master copy (write-protected,
   access-restricted) and analyse working copies.
4. **Every hand-off is recorded** in the chain of custody: from whom, to
   whom, when (UTC), why, and the hash at that moment.
5. **Collect what the question needs, not everything.** Data minimisation is
   both a privacy obligation and a defensibility point; justify broad
   collection in the notes.
6. **Counsel decides legal matters.** Legal hold, law-enforcement referral,
   regulator notification and cross-border transfers go through legal/DPO -
   the analyst documents and advises.

## Workflow

1. **Open the case:** case ID, incident commander, legal contact, data
   protection contact; create the evidence log (CSV below) and custody forms.
2. **Plan collection** per host/source with order of volatility (RFC 3227):
   memory, live state, logs at risk of rotation, disk, cloud/control-plane
   exports. Note retention deadlines (logs that roll in hours/days).
3. **Acquire** with a validated tool and, for physical media, a write
   blocker. Record tool, version, method and any errors.
4. **Hash** at acquisition (tool-computed and independently verified).
5. **Label and store** the master copy; create working copies; verify.
6. **Log every access/transfer** in the custody record.
7. **Analyse** working copies only; derived artefacts (parsed CSVs, plaso
   storage, carved files) get their own evidence-log rows referencing the
   parent item.
8. **Report** with minimised and redacted data; record who received what.
9. **Close:** retention decision, return or destruction with a destruction
   record.

## Chain of custody form

One form per evidence item (physical or digital). Minimum fields:

| Field | Example / notes |
|---|---|
| Case ID | `IR-2025-014` |
| Item ID | `IR-2025-014-E003` (matches evidence log `item_id`) |
| Description | "Samsung 512 GB NVMe SSD, S/N ..., removed from laptop asset LT-0421" or "E01 image of HOST01 C:" |
| Source | Host name, asset tag, owner/custodian, physical location or cloud account |
| Acquisition date/time (UTC) | Start and end |
| Acquired by | Name, role, organisation, signature |
| Method / tool / version | "FTK Imager 4.x, physical, Tableau T35u write blocker" |
| Hashes | SHA-256 (plus MD5/SHA-1 only if a tool or court requires) |
| Seal / bag number | For physical items |
| Storage location | Locker ID or encrypted repository path |
| Transfer log rows | Date/time UTC, released by, received by, purpose, hash verified (Y/N + value), signatures |
| Final disposition | Returned / destroyed / retained; date; authorised by |

## Hashing

```bash
# Linux/macOS: hash and write a manifest next to the evidence
sha256sum host01.E01 host01.E02 > host01.SHA256SUMS
sha256sum -c host01.SHA256SUMS          # verify after transfer
# Verify the internal hashes of an EWF image (acquisition hash stored in the E01)
ewfverify host01.E01
```

```powershell
# Windows
Get-FileHash -Algorithm SHA256 .\host01.E01 | Format-List
Get-ChildItem .\triage\ -Recurse -File | Get-FileHash -Algorithm SHA256 | Export-Csv .\triage_sha256.csv -NoTypeInformation
```

- SHA-256 is the case standard. MD5/SHA-1 may be computed in addition for
  legacy tooling or TI lookups, never alone.
- For live/volatile acquisitions (memory, live triage) the hash proves the
  file has not changed **since acquisition**; it cannot prove it matches the
  source, which kept changing. Say so in reports.
- Hash cloud exports (CloudTrail, UAL, Entra logs) immediately after download
  and record the query/export parameters used.

## Write blockers and acquisition

- **Hardware write blockers** (e.g. Tableau forensic bridges) for any
  physical drive connected to an analysis machine. Test the blocker before
  use per lab procedure; NIST CFTT publishes write-blocker test reports.
- **Software write protection** (Linux `blockdev --setro /dev/sdX` before
  mounting; read-only loop devices; Windows `StorageDevicePolicies\WriteProtect`
  registry setting for USB) is a fallback with documented limitations, not
  equivalent to a validated hardware blocker.
- Live systems cannot be write-blocked: minimise footprint, run tools from
  external media, write output off-host, log every command with UTC time.
- Virtual machines and cloud: snapshot/export the disk (no blocker needed);
  record snapshot IDs, region, account, and who created them.

```bash
# E01 with case metadata, SHA-256 digest and verification (ewfacquire prompts for metadata)
ewfacquire -t /evidence/IR-2025-014-E003 -d sha256 /dev/sdb
# Raw image with on-the-fly hashing and a hash log
dc3dd if=/dev/sdb of=/evidence/IR-2025-014-E003.raw hash=sha256 log=/evidence/IR-2025-014-E003.log
```

Guymager (Linux GUI) and FTK Imager (Windows GUI) are common validated
alternatives. Option names differ between versions - confirm with `--help`.

## Image formats

| Format | Pros | Cons |
|---|---|---|
| Raw / dd (`.raw`, `.dd`, `.001` splits) | Universal, simple, any tool reads it | No embedded metadata or hash; uncompressed; sparse areas take full space |
| E01 / EWF (Ex01 = EWF2) | Compression, embedded case metadata, per-chunk CRC + acquisition hash, segmentable | Proprietary-origin format (libewf open implementation); Ex01 less widely supported |
| AFF4 | Open, supports sparse/discontiguous data, memory images, multiple streams, metadata in RDF | Smaller tool support than E01; check the reader supports the AFF4 variant used |
| Logical containers (AD1, zip/VHDX triage) | Small, fast, targeted | Not a full image: no unallocated space or slack; document scope |

Choose E01 for disks by default, raw when a downstream tool requires it,
and record the choice.

## Legal hold and preservation

- Legal hold is a counsel decision; once issued, **suspend deletion**: log
  retention policies, mailbox retention, backup rotation, ticket purging,
  reimaging of affected assets, cloud object lifecycle rules.
- Microsoft 365: litigation hold / eDiscovery (Purview) holds on mailboxes,
  OneDrive and SharePoint (`ir-bec-m365`). Cloud: extend log retention, copy
  logs to a separate, access-restricted account/bucket with object lock
  (`ir-cloud-aws`, `ir-azure-entra`).
- Preserve before you remediate: reimaging or "cleaning" a host destroys
  evidence - get IR lead sign-off that collection is complete first.
- Third-party data (MSSP, SaaS vendor, ISP) needs a formal preservation
  request; record request date and reference.
- Law-enforcement involvement may change handling (sealing, their custody
  forms) - follow counsel.

## Privacy, GDPR and minimisation

- Lawful basis for processing personal data during security incidents is
  typically legitimate interest (GDPR Art. 6(1)(f); Recital 49 recognises
  network and information security) - confirm with the DPO.
- **Minimise** (Art. 5(1)(c)): targeted collection (triage rather than full
  disk when it answers the question), filter mailbox searches by date and
  sender, avoid copying personal folders unless in scope.
- **Security of processing** (Art. 32): encrypted storage, need-to-know
  access, access logging.
- **Breach notification**: if personal data is affected, the controller may
  need to notify the supervisory authority without undue delay and where
  feasible within 72 hours of becoming aware (Art. 33), and data subjects
  when high risk (Art. 34). The analyst's job is to provide the facts
  (what data, how many subjects, when, confidence) to counsel/DPO quickly.
- Employee monitoring and works-council/union agreements can restrict what
  can be reviewed (e.g. private email content) - check before deep-diving
  user content. Non-EU regimes (state breach laws, sector rules) apply in
  parallel; counsel maps them.

## PII redaction in reports

- Replace names with roles or pseudonyms (`User-A (Finance)`), keep a
  separate access-controlled key file.
- Truncate or mask identifiers not needed by the audience: email local
  parts, phone numbers, IBANs, national IDs, internal IPs if the audience is
  external.
- Never include credentials, session tokens, or full password hashes;
  state "credential material for N accounts was exposed".
- Screenshots: crop and redact; check for names in title bars, tabs,
  notification areas.
- Real redaction removes the underlying data: flatten PDFs or use a true
  redaction tool; black boxes over text layers are reversible. Strip
  document metadata (author, comments, tracked changes).
- Apply TLP (FIRST TLP 2.0) labels to reports and IOC packages; record
  recipients.

## Storage, retention and destruction

- Encrypted at rest (BitLocker, LUKS, VeraCrypt containers, encrypted
  object storage with customer-managed keys); keys stored separately from
  evidence.
- Two copies: master (write-once where possible - WORM, S3 Object Lock in
  compliance mode, offline drive in a locked safe) and working copy.
- Access restricted to named case team; access is logged.
- Physical items: tamper-evident bags, sealed and signed, logged locker.
- Retention per organisational policy and legal requirements; default to
  "until counsel releases" when litigation or regulatory action is possible.
- Destruction: approved by case owner/counsel, method recorded (crypto
  erase, secure wipe, physical destruction), witness, date, item IDs.

## Evidence-log CSV (case scaffolder format)

Header, exactly:

```csv
item_id,description,source_host,acquired_utc,acquired_by,method,sha256,storage_location,notes
IR-2025-014-E001,Memory image HOST01,HOST01,2025-03-01T11:02:10Z,jdoe,"WinPmem (version noted in acquisition log), written to external USB",<sha256>,evidence-store/IR-2025-014/E001/,"Capture 11:02:10-11:09:44Z; host network-contained via EDR at 10:58Z"
IR-2025-014-E002,KAPE triage VHDX HOST01 C:,HOST01,2025-03-01T11:15:30Z,jdoe,"KAPE KapeTriage target with --vss",<sha256>,evidence-store/IR-2025-014/E002/,"Includes VSS from 2025-02-27; KAPE console log stored alongside"
IR-2025-014-E003,Parsed Prefetch CSV (derived from E002),HOST01,2025-03-01T13:40:00Z,asmith,"PECmd (version noted) against working copy of E002",<sha256>,evidence-store/IR-2025-014/derived/,"Parent item E002"
```

| Column | Content |
|---|---|
| `item_id` | `<case-id>-E<nnn>`, never reused; derived items reference the parent in `notes` |
| `description` | What it is, in words a non-specialist understands |
| `source_host` | Host name, device S/N, cloud account/tenant, or mailbox |
| `acquired_utc` | ISO 8601 UTC with `Z` (start of acquisition) |
| `acquired_by` | Person (not team) who performed acquisition |
| `method` | Tool + version + mode (physical/logical/live/snapshot/export) + write-blocker if any |
| `sha256` | Lowercase hex of the acquired file(s); for multi-segment images, the manifest file's hash and manifest location in `notes` |
| `storage_location` | Evidence store path/locker ID of the master copy |
| `notes` | Errors, bad sectors, partial collection, time skew observed, parent item, approvals |

Custody transfers go in the custody form, not as new evidence-log rows
(unless a new derived item is created).

## Decision table: is this evidence usable?

| State | Evidence that moves it |
|---|---|
| Sound | Acquisition hash recorded, verified after each transfer, custody complete, tool/version documented |
| Usable with caveats | Live acquisition, gaps in custody explained in writing, or hash computed after first copy - disclose in report |
| Compromised | Hash mismatch unexplained, analysed on original, unknown handling - do not base key findings on it alone; re-acquire if possible |
| Needs more data | Missing acquisition notes - reconstruct from tool logs, EDR action logs, ticket history before relying on it |

## False positives & benign look-alikes

- Hash "mismatch" because a different file was hashed (E01 vs the raw
  stream inside it, segment vs whole image, zip vs contents).
- Different hashes of live-acquired memory taken twice - expected.
- Timestamp differences between the custody form (local time written by
  hand) and the evidence log (UTC) - annotate the zone on paper forms.

## Pitfalls

- Starting analysis "just to have a quick look" before hashing.
- Storing evidence on the analyst's laptop or a shared drive with broad
  access.
- Collecting entire mailboxes or file shares when a date-bounded search
  would answer the question.
- Mounting an image read-write (journal replay, Windows auto-mount
  writing metadata) - use read-only mounts and write blockers.
- Forgetting derived artefacts are evidence too.
- Sending unredacted reports or IOC packages to wide distribution lists.
- Wiping or reimaging before legal hold questions are answered.

## Output

- Evidence-log CSV and chain-of-custody forms in the case folder, kept
  current for the life of the case.
- Hash manifests next to every evidence item.
- Redacted, TLP-labelled report inputs for `ir-report-writing` / `/report`.
- Preservation and legal-hold records for counsel; facts for breach
  notification decisions (`incident-response`). Used by `/ir` and
  `/forensics`; agent forensic-analyst.

## References

- RFC 3227 Guidelines for Evidence Collection and Archiving.
- NIST SP 800-86 Guide to Integrating Forensic Techniques into Incident Response.
- NIST SP 800-61 Rev. 3 (incident response).
- ISO/IEC 27037 (identification, collection, acquisition and preservation of
  digital evidence); ISO/IEC 27041, 27042, 27043.
- NIST Computer Forensics Tool Testing (CFTT) program reports.
- ACPO Good Practice Guide for Digital Evidence (UK); SWGDE best practice
  documents.
- Regulation (EU) 2016/679 (GDPR): Art. 5, 6, 32, 33, 34; Recital 49.
- FIRST Traffic Light Protocol (TLP) 2.0.
- libewf documentation (ewfacquire, ewfverify, ewfmount).
