---
name: phishing-analysis
description: Analysis and response for reported or detected phishing emails. Covers header parsing (Received chain read bottom-up, Authentication-Results SPF/DKIM/DMARC and compauth, Return-Path vs From alignment, Reply-To, Message-ID, X-Forefront-Antispam-Report SCL/SFV/CAT), URL analysis with defanging, Safe Links decoding and safe detonation, attachment triage (Office macros with oletools, ISO/IMG/LNK, HTML smuggling, SVG, PDF, QR-code quishing, password-protected archives), Microsoft Defender for Office 365 Threat Explorer / Real-time detections and advanced hunting (EmailEvents, EmailUrlInfo, EmailAttachmentInfo, UrlClickEvents, EmailPostDeliveryEvents), campaign scoping, purge (soft delete) across mailboxes, blocking and user notification. Use for "user reported a phish", "is this email malicious", "who else got it", "who clicked", or /phish.
---

# Phishing analysis

Reported emails are the highest-volume triage item in most SOCs and the most
common initial access vector (T1566). The job: verdict, scope the campaign,
find who interacted, remove it, and block the infrastructure.

## When to use

- A user reports a suspicious email (report button, forwarded mail, helpdesk).
- Email security alerts: delivered-then-detected (ZAP), malicious URL click,
  suspicious attachment.
- Investigating the initial access vector of an incident.

For a mailbox already compromised as a result, hand off to `ir-bec-m365`.

## Ground rules

1. **Analyse the original message, not a forward.** Get the `.eml`/`.msg`
   (or the message in Explorer by `NetworkMessageId`); forwarding destroys
   headers and attachments' context.
2. **Never click, open or detonate on a production device or network.** Use an
   isolated sandbox or remote browser isolation with no corporate credentials,
   and a non-attributable egress.
3. **Public scanning services leak.** Submitting a URL with a recipient
   token or a document with internal content to a public service can expose
   data and tip off the actor; use private/unlisted modes or internal tools,
   or submit only hashes.
4. **Verdict needs evidence beyond "looks phishy":** an authentication failure
   or spoof, a malicious URL/attachment behaviour, or a confirmed credential
   harvesting page. Otherwise it is Spam/Graymail or Needs-data.
5. **Purge only after scoping, and soft delete first.** Record the search
   criteria and result count before the purge; IC/SOC lead approves purges
   beyond the reporting user's mailbox per local policy.
6. **Defang every indicator** in notes, tickets and chat
   (`hxxps://login-secure[.]example/path`, `203.0.113[.]10`).

## Workflow

1. Get the original message; record `NetworkMessageId`, `InternetMessageId`,
   sender, recipients, subject, received time (UTC).
2. Check if it is an authorised phishing simulation (simulation vendor
   headers/infrastructure, Attack simulation training records). If yes, close
   as Simulation and thank the user.
3. Parse headers (authentication, origin, routing).
4. Analyse URLs and attachments (static first, detonation second).
5. Verdict (table below).
6. If malicious: scope the campaign, find interactions (clicks, opens,
   attachment execution, credential submissions), purge, block, notify.
7. Hand off any user who clicked and submitted credentials or ran an
   attachment to `incident-response` / `ir-bec-m365`.

## Header analysis

| Header | What to check |
|---|---|
| `Received` | Read **bottom-up**; the lowest is closest to the sender. Only hops added by your own MTAs/EOP are trustworthy; anything below can be forged. Note first external IP, HELO name, timestamps (delays, timezone). |
| `Authentication-Results` (added by your receiving system) | `spf=pass/fail/softfail/neutral/none (smtp.mailfrom=...)`, `dkim=pass/fail (header.d=...)`, `dmarc=pass/fail action=... header.from=...`, Microsoft `compauth=pass/fail/softpass reason=NNN` |
| `Return-Path` | Envelope sender (MAIL FROM) used by SPF. Mismatch with `From` is normal for bulk senders but matters for DMARC alignment |
| `From` | Display name vs address; lookalike domains (homoglyphs, added words, different TLD); free-mail with executive display name |
| `Reply-To` | Different from `From`, especially to free-mail: classic BEC/advance-fee pattern |
| `Message-ID` | Domain should be plausible for the sending platform; tool-generated patterns help cluster campaigns |
| `X-Forefront-Antispam-Report` | `CIP` (connecting IP), `CTRY`, `SFV` (e.g. `SPM`, `NSPM`, `SKA` allowed by policy, `SKN`), `SCL`, `CAT` (e.g. `PHSH`, `HPHSH`, `SPM`, `BULK`), `PTR` |
| `X-Microsoft-Antispam` | `BCL` bulk complaint level |
| `ARC-Seal` / `ARC-Authentication-Results` | Authentication results preserved across forwarders/mailing lists |
| `X-MS-Exchange-Organization-AuthAs` | `Anonymous` (external) vs `Internal` / `Authenticated` |

Interpretation:
- DMARC pass requires SPF or DKIM pass **and** alignment with the `From`
  domain. A message can pass SPF for the attacker's own domain and still be a
  lookalike; authentication proves the domain, not the intent.
- DKIM/SPF pass from a legitimate service (compromised vendor mailbox, SaaS
  sending platform, cloud file-share notifications) is common in modern
  phishing; judge the content and links too.
- `compauth=fail` with a spoofed internal or partner domain is strong evidence.

```bash
# Static header and body extraction from an .eml in the sandbox (no network).
grep -iE "^(Received|Authentication-Results|Return-Path|From|Reply-To|Message-ID|X-Forefront-Antispam-Report|X-Microsoft-Antispam):" -A2 sample.eml
# Extract URLs for analysis (defang before pasting anywhere).
grep -oE "https?://[^\"'<> ]+" sample.eml | sort -u | sed -e 's/http/hxxp/' -e 's/\./[.]/g'
```

## URL analysis

1. **Extract and decode**: Safe Links wraps URLs as
   `https://*.safelinks.protection.outlook.com/?url=<encoded>&data=...`;
   URL-decode the `url` parameter. Also decode other rewriters, redirectors
   and open redirects on reputable domains.
2. **Static checks**: domain age (RDAP/WHOIS), certificate transparency
   first-seen, hosting ASN, lookalike of your brand or IdP, path patterns
   typical of credential harvesting kits, recipient email embedded in the
   URL or fragment (`#` base64 of the address) - that token tells you who was
   targeted but must not be submitted publicly.
3. **Reputation**: TI platform, Defender URL verdicts, your proxy categorisation.
4. **Detonation** in an isolated browser/sandbox:
   - Expect gating: CAPTCHA/Turnstile pages, geo/IP filtering, user-agent
     checks, one-time links. A clean result is not proof of benign.
   - Capture: redirect chain, final landing page screenshot, form actions
     (where credentials are posted), resources loaded, any downloads.
   - Adversary-in-the-middle (AiTM) kits proxy the real Microsoft/IdP page;
     the URL bar shows a non-Microsoft domain while the page looks genuine.
5. Record all domains/IPs in the chain as IOCs (`threat-intel-ioc`).

## Attachment triage

| Type | Technique | Static checks (sandbox) |
|---|---|---|
| Office with macros (`.docm`, `.xlsm`, legacy `.doc`/`.xls`) | T1566.001, T1204.002 | `olevba`, `oleid`, `mraptor` (oletools); auto-exec macros (`AutoOpen`, `Document_Open`, `Workbook_Open`), shell/download calls; XLM 4.0 macros |
| ISO / IMG / VHD(X) containers | T1553.005 | Mount read-only in sandbox; contents often LNK + hidden DLL/script |
| LNK shortcut | T1204.002 | Target and arguments (`LECmd` or `lnkparse`): `cmd`, `powershell`, `mshta`, `rundll32`, `msiexec` with URLs |
| HTML / HTM / SVG attachments | T1027.006 HTML smuggling | Look for JavaScript building a `Blob`, `atob()` base64 payloads, `msSaveOrOpenBlob`, auto-download links, embedded credential forms |
| PDF | T1566.001 | Links and buttons (`pdfid`, `pdf-parser`), embedded files, JavaScript |
| QR codes in images/PDFs ("quishing") | T1566 | Decode offline (e.g. `zbarimg`); treat as URL; users scan on unmanaged phones, outside corporate controls |
| Password-protected ZIP/7z/RAR | T1027.013 | Password usually in the body; extract in sandbox; scanners could not inspect it |
| OneNote, CHM, JS, VBS, HTA, WSF, MSI, `.url` | T1204.002 | File type by magic bytes (`file`), not extension; scripts read statically |

Always record SHA-256, file name, size, true file type, and verdict.
Deeper analysis: `malware-triage`; signatures: `yara-rules`.

## Verdict table

| Verdict | Evidence |
|---|---|
| Malicious - phishing / malware | Credential harvesting page confirmed, malicious attachment behaviour, spoof of internal/partner domain (`compauth=fail`), BEC request with lookalike/free-mail Reply-To |
| Suspicious - Needs-data | Gated URL could not be reached, sandbox inconclusive, new domain with no content yet; keep monitoring, consider pre-emptive block |
| Spam / Graymail | Unsolicited marketing, no malicious payload or credential lure |
| Benign | Legitimate business mail (verified sender, expected content); thank the user |
| Simulation | Authorised phishing test confirmed against simulation records |

## Scoping and interaction (Microsoft Defender for Office 365)

Threat Explorer (Defender for Office 365 Plan 2) or Real-time detections
(Plan 1) in the Defender portal: filter by sender, sender domain, subject,
URL domain, attachment hash, `NetworkMessageId`; view delivery location,
post-delivery actions and clicks. Advanced hunting gives the same with KQL.

```kql
// Campaign scope: all messages from the same sender/domain or subject in 7 days. Tune: indicators.
EmailEvents
| where Timestamp > ago(7d)
| where SenderFromDomain =~ "login-secure.example" or SenderMailFromDomain =~ "login-secure.example"
     or Subject has "Payroll update required"
| project Timestamp, NetworkMessageId, InternetMessageId, SenderFromAddress, SenderMailFromAddress,
          SenderIPv4, RecipientEmailAddress, Subject, DeliveryAction, DeliveryLocation, ThreatTypes, AuthenticationDetails
```

```kql
// Messages carrying a URL domain or attachment hash.
let msgs = union
    (EmailUrlInfo | where Timestamp > ago(7d) | where UrlDomain endswith "login-secure.example" | project NetworkMessageId),
    (EmailAttachmentInfo | where Timestamp > ago(7d) | where SHA256 == "<sha256>" | project NetworkMessageId);
EmailEvents
| where Timestamp > ago(7d)
| where NetworkMessageId in (msgs)
| summarize Recipients = dcount(RecipientEmailAddress), Delivered = countif(DeliveryAction == "Delivered") by Subject, SenderFromAddress
```

```kql
// Who clicked, and whether they clicked through a Safe Links warning.
UrlClickEvents
| where Timestamp > ago(7d)
| where Url has "login-secure.example"
| project Timestamp, AccountUpn, Url, ActionType, IsClickedThrough, IPAddress, NetworkMessageId
```

```kql
// Post-delivery actions (ZAP, admin remediation) on the campaign messages.
EmailPostDeliveryEvents
| where Timestamp > ago(7d)
| where NetworkMessageId in ("<id1>", "<id2>")
| project Timestamp, NetworkMessageId, RecipientEmailAddress, Action, ActionType, ActionResult, DeliveryLocation
```

```kql
// Endpoint follow-up: attachment executed or file written on devices. Tune: hash and file name.
DeviceFileEvents
| where Timestamp > ago(7d)
| where SHA256 == "<sha256>" or FileName =~ "Invoice_0342.iso"
| project Timestamp, DeviceName, ActionType, FolderPath, InitiatingProcessFileName, InitiatingProcessAccountName
```

~~~spl
```Splunk: proxy hits to the phishing domain (users who reached the page). Tune: index, field names.```
index=proxy (url="*login-secure.example*" OR dest="login-secure.example") earliest=-7d
| stats count min(_time) as first_seen values(http_method) as methods by user, src
| convert ctime(first_seen)
~~~

A `POST` to the phishing domain from a user's device suggests credentials were
submitted: treat that user as compromised (`ir-bec-m365`). Also check sign-ins
for clickers in the hours after the click from new IPs/ASNs.

## Purge and block

1. **Purge** the campaign from all mailboxes:
   - Defender portal: Explorer / advanced hunting results -> Take action ->
     Soft delete (recoverable by admins) or Move to junk; Hard delete only when
     required. Track status in the Action center.
   - Purview / Exchange PowerShell alternative: `New-ComplianceSearch` with a
     precise query (sender, subject, received date), check the result count,
     then `New-ComplianceSearchAction -SearchName <name> -Purge -PurgeType SoftDelete`.
     Compliance search purge has per-mailbox item limits per action; check
     current Microsoft Learn limits for large campaigns.
2. **Block** (Tenant Allow/Block List): sender address/domain, URLs/domains,
   file hashes; plus proxy/DNS blocks for the landing domains. Lookalike
   domains of your brand: request takedown via registrar/hosting abuse.
3. **Report** false negatives to Microsoft via Submissions so filtering improves.
4. **Detection follow-up**: new rule or hunt for the lure pattern
   (`detection-engineering`).

## User notification

To the reporter (feedback loop matters for reporting rates):

```
Thank you for reporting "<subject>". It was a phishing email. We have removed it
from all mailboxes and blocked the sender. If you clicked the link or opened the
attachment, please contact <SOC channel> now - no blame, speed helps.
```

To recipients who clicked/entered credentials (via phone or a verified channel
if the mailbox may be compromised):

```
You interacted with a phishing email on <date>. As a precaution we have reset
your sign-in sessions and will help you reset your password and MFA. Please do
not approve unexpected MFA prompts. Contact <channel> with any questions.
```

Org-wide warnings only for large or targeted campaigns; avoid naming individuals.

## False positives & benign look-alikes

- Legitimate services that look like phishing: shared-document notifications
  (SharePoint, Dropbox, DocuSign), password-expiry mails from IT, payroll and
  HR platforms, MFA enrolment campaigns. Verify with the sending team.
- Marketing mail with tracking redirects and failing alignment.
- Authorised phishing simulations (check simulation records before purging).
- Forwarded mail failing SPF due to the forwarder (check ARC).

## Pitfalls

- Analysing a forwarded copy and concluding headers are "internal".
- Declaring a URL benign because the sandbox saw a CAPTCHA or blank page.
- Clicking a URL with the recipient token from a corporate IP (tells the
  actor the lure was analysed, may burn the victim).
- Purging before recording scope, or with a query broad enough to delete
  legitimate mail.
- Stopping at "deleted" without checking who clicked, submitted credentials
  or executed the attachment.
- Uploading confidential attachments to public sandboxes.

## Output

- Verdict with evidence, IOCs (defanged), campaign scope (recipients,
  delivered count), interaction list (clicked / submitted / executed).
- Purge and block actions with counts and approver.
- Hand-offs: `ir-bec-m365` for compromised users, `incident-response` for
  executed payloads, `malware-triage` for attachments, `threat-intel-ioc`
  (`/ioc`), `detection-engineering` for new detections.

## References

- Microsoft Learn: Threat Explorer and Real-time detections; Remediate
  malicious email delivered in Office 365; Anti-spam message headers;
  Advanced hunting schema (EmailEvents, EmailUrlInfo, EmailAttachmentInfo,
  UrlClickEvents, EmailPostDeliveryEvents).
- Microsoft Learn: Search for and delete email messages (compliance search purge).
- RFC 7208 (SPF), RFC 6376 (DKIM), RFC 7489 (DMARC), RFC 8617 (ARC).
- CISA, Phishing Guidance: Stopping the Attack Cycle at Phase One.
- oletools (Philippe Lagadec) for Office files; pdfid and pdf-parser (Didier Stevens) for PDFs.
- MITRE ATT&CK: T1566.001, T1566.002, T1204.002, T1027.006, T1553.005 -
  https://attack.mitre.org/techniques/T1566/
