---
description: "Analyse a reported email safely: headers (SPF/DKIM/DMARC, Received chain), sender and lookalike domains, URLs and attachments (static only, sandbox for detonation), verdict, and org-wide scope. Usage: /phish <path-to-.eml|.msg> | /phish <pasted headers/body> [--case <case-folder>]"
argument-hint: "<file.eml|file.msg> | <pasted headers and body> [--case <case-folder>]"
---

# /phish

Triage a user-reported or gateway-flagged email: is it malicious, who else got it,
who interacted, and what to do. Analysis is static by default; anything that needs
execution or a live fetch goes to an isolated sandbox, never the analyst's machine.

Input: `$ARGUMENTS`

## Usage

```
/phish reported/invoice-overdue.eml
/phish "<paste full headers + body>"
/phish reported/msg-4411.msg --case cases/2026-11-25-payroll-phish
```

Ask for the **original message as an attachment** (`.eml` / `.msg`), not a forward:
forwarding rewrites headers and can strip attachments.

## Skills to load

- Always: `phishing-analysis`, `threat-intel-ioc`
- Attachment present: `malware-triage`, `yara-rules`
- Credential entry, mailbox rules, payment fraud, M365 tenant: `ir-bec-m365`, `ir-azure-entra`
- Org-wide search queries: `kql-sentinel-defender` (`EmailEvents`, `EmailUrlInfo`,
  `EmailAttachmentInfo`, `UrlClickEvents`), `spl-splunk`, `elastic-eql-esql`

## Evidence gate

- "Malicious" needs at least one concrete artefact: a credential-harvest page confirmed
  in a sandbox/reputation record, a malicious attachment verdict with hash, a lookalike
  domain registered recently plus spoofed branding, or a confirmed payment-fraud request.
- "Clean" needs authentication results checked, every URL and attachment accounted for,
  and the sender relationship verified (not just "SPF passed").

## Hard safety rules

- **Never click, open, preview or fetch a live link or attachment outside an isolated
  sandbox.** No `curl`/`WebFetch` to URLs from the email from this machine. Use URL
  reputation lookups by defanged value, or a sandbox/URL-scan service the organisation
  approves (be aware public submissions may be visible to others: check TLP first).
- Do not open Office/PDF/HTML/ISO/LNK/OneNote attachments locally. Hash them, extract
  metadata statically (e.g. `oleid`, `olevba`, `pdfid` in an isolated analysis VM).
- Do not reply to, unsubscribe from, or contact the sender.
- Defang every URL, domain, IP and email address in the output.

## Procedure

1. **Headers.** Parse `From`, `Reply-To`, `Return-Path`, `Sender`, `Message-ID`, `Date`
   (convert to UTC). Walk `Received:` bottom-up to the first external hop; note the
   sending IP and HELO. Read `Authentication-Results` / `ARC-*`: SPF, DKIM (`d=`
   domain), DMARC alignment. A DKIM pass for an unrelated domain is not alignment.
2. **Sender analysis.** Display-name spoofing, lookalike domains (homoglyphs, added
   words, TLD swap), domain age (WHOIS/RDAP, passive DNS), first time this sender wrote to the org.
3. **Body.** Lure type (invoice, MFA reset, shared document, payroll change, voicemail),
   urgency/authority cues, QR codes (decode the image, treat the URL like any other),
   HTML forms, hidden text.
4. **URLs.** Extract all (`href`, text, QR, attachments). Unwrap safe-link rewriters to
   the original URL. Reputation lookup by defanged value; sandbox only if needed.
5. **Attachments.** SHA256, true file type (magic bytes vs extension), macros, embedded
   objects, archives with passwords in the body. Hash reputation; sandbox detonation in
   an isolated environment only.
6. **Verdict** with the table below.
7. **Scope.** Find all recipients of the same campaign (sender, subject, URL domain,
   attachment hash, `NetworkMessageId`), who clicked (`UrlClickEvents` / proxy logs),
   who entered credentials (sign-ins from new IP/ASN shortly after the click), who
   opened the attachment (process events on the endpoint).
8. **Recommend** response: purge, block sender/domain/URL, reset + revoke for users who
   entered credentials, check for new inbox rules and OAuth consents. All via `/contain`
   (approval required).

| Verdict | Evidence |
|---|---|
| Malicious - credential phish | Harvest page / form posting credentials; lookalike sender |
| Malicious - malware delivery | Attachment or download with malicious verdict |
| Malicious - BEC / payment fraud | Payment or banking change request from spoofed/compromised sender |
| Spam / marketing | Bulk sender, unsubscribe works via legitimate ESP, no harmful payload |
| Clean / legitimate | Authenticated, known relationship, all links/attachments benign |
| Simulation | Matches an authorised phishing-simulation campaign (verify with its owner) |

## Output format

```markdown
## Phish analysis: "<subject>"   received <UTC>
**Verdict:** ...    **Confidence:** ...    **Recipients:** N    **Clicked:** N    **Credentials entered:** N
### Header summary
| Field | Value (defanged) | Note |
### Authentication: SPF / DKIM (d=) / DMARC / alignment
### Indicators
| type | value_defanged | role (sender, url, payload, infra) | reputation |
### Attachments: name | true type | SHA256 | verdict | how analysed
### Scope queries (labelled) and results
### Recommended actions -> /contain
```

## Case integration

If a case is active (or the verdict is malicious and an incident is opened via `/ir`):
indicators to `iocs.csv` (`type,value_defanged,first_seen_utc,last_seen_utc,source,confidence,tlp,notes`),
delivery/click/credential events to `timeline.csv`, and the original `.eml` as an
evidence item in `evidence-log.csv` with SHA256.
