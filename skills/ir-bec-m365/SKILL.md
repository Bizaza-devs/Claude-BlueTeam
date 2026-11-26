---
name: ir-bec-m365
description: Business email compromise (BEC) response in Microsoft 365 / Exchange Online. Covers Unified Audit Log operations (New-InboxRule, Set-InboxRule, UpdateInboxRules, Set-Mailbox forwarding, MailItemsAccessed, Send/SendAs, Add-MailboxPermission, Add-RecipientPermission, Consent to application), Entra sign-in log review (SigninLogs, AADNonInteractiveUserSignInLogs), adversary-in-the-middle (AiTM) session cookie theft indicators, OAuth illicit consent grant abuse (T1528), attacker MFA method and device registration, the containment order (disable, revoke sessions, clean rules/grants/methods, reset, MFA re-registration), message trace for fraud mail, and finance-fraud wire recall steps. Use when a mailbox is compromised, a suspicious inbox rule fires, a vendor reports changed bank details, or "someone sent invoices from our CFO's account".
---

# BEC response in Microsoft 365

BEC is identity compromise plus fraud. The mailbox is the crime scene; the
sign-in logs tell you how they got in; the finance team decides how much it costs.

## When to use

- Alert on a suspicious inbox rule, forwarding, or mailbox delegation.
- Risky sign-in / AiTM / anomalous token alert for a mail user.
- A vendor, customer or colleague reports odd mail or changed bank details.
- A payment was sent to a new account after an email request.

Run inside `incident-response` (roles, legal). For tenant-wide identity abuse
(service principals, privileged roles), add `ir-azure-entra`. For the original
phishing email, `phishing-analysis`.

## Ground rules

1. **Export before you clean.** Before removing rules, grants or methods,
   export UAL for the user and time window, current inbox rules (including
   hidden), forwarding settings, mailbox/folder permissions, OAuth grants and
   authentication methods. Cleaning first destroys the scope evidence.
2. **A password reset alone is not containment.** Sessions and refresh tokens
   must be revoked, attacker MFA methods and devices removed, rules and grants
   cleaned. Order matters (see containment sequence).
3. **Mailbox access = data access.** Do not state "no data accessed" without
   reviewing `MailItemsAccessed` (or explaining why it is unavailable) for the
   attacker's sessions.
4. **Fraud is time-critical.** If money moved, the finance recall steps run in
   parallel with the investigation, not after it.
5. **Never contact the affected user or counterparties via the compromised
   mailbox**; use a verified phone number or in-person channel.

## Workflow

1. Confirm the compromise: attacker sign-ins + mailbox manipulation (two sources).
2. Preserve (export list below).
3. Contain in sequence; IC approves account disable.
4. Scope: what the attacker read, sent, changed, consented; other users hit by
   the same infrastructure or lure.
5. Fraud response: identify payment requests sent/received, start recalls.
6. Eradicate and harden; monitor the user and similar users for 30 days.

## Evidence to export first

```powershell
# Exchange Online PowerShell (ExchangeOnlineManagement module). Read-only collection.
$u = "j.doe@corp.example"; $start = (Get-Date).AddDays(-30); $end = Get-Date
Search-UnifiedAuditLog -UserIds $u -StartDate $start -EndDate $end -ResultSize 5000 -SessionCommand ReturnLargeSet |
  Export-Csv ".\ual_$($u).csv" -NoTypeInformation    # repeat with the same SessionId until no more results
Get-InboxRule -Mailbox $u -IncludeHidden | Select-Object * | Export-Clixml ".\inboxrules.xml"
Get-Mailbox $u | Select-Object ForwardingAddress, ForwardingSmtpAddress, DeliverToMailboxAndForward
Get-MailboxPermission $u | Where-Object { $_.User -notlike "NT AUTHORITY\SELF" }
Get-RecipientPermission $u
```

```powershell
# Microsoft Graph PowerShell: auth methods, OAuth grants, registered devices.
$id = (Get-MgUser -UserId "j.doe@corp.example").Id
Get-MgUserAuthenticationMethod -UserId $id | Select-Object Id, AdditionalProperties
Get-MgUserOauth2PermissionGrant -UserId $id
Get-MgUserRegisteredDevice -UserId $id
Get-MgUserAppRoleAssignment -UserId $id
```

UAL retention depends on licensing and audit retention policies; export early.
Also export SigninLogs and AuditLogs for the user (Entra portal, Sentinel or Graph).

## Unified Audit Log operations that matter

| Operation (UAL) | Workload | Meaning in BEC | ATT&CK |
|---|---|---|---|
| `New-InboxRule`, `Set-InboxRule`, `Enable-InboxRule` | Exchange | Rule created/changed via OWA or PowerShell | T1564.008 |
| `UpdateInboxRules` | Exchange | Rule created/changed via Outlook desktop / EWS / Graph | T1564.008 |
| `Set-Mailbox` (ForwardingSmtpAddress, DeliverToMailboxAndForward) | Exchange | Mailbox-level external forwarding | T1114.003 |
| `New-TransportRule`, `Set-TransportRule` | Exchange (admin) | Org-wide forwarding/redirect if an admin is compromised | T1114.003 |
| `MailItemsAccessed` | Exchange | Items read/synced (MailAccessType Bind or Sync) | T1114.002 |
| `Send`, `SendAs`, `SendOnBehalf` | Exchange | Mail sent as/for the user | T1534 |
| `Add-MailboxPermission` (FullAccess), `Add-RecipientPermission` (SendAs), `Add-MailboxFolderPermission` | Exchange | Delegation for persistence | T1098.002 |
| `SoftDelete`, `HardDelete`, `MoveToDeletedItems` | Exchange | Hiding replies and bounces | T1070.008 |
| `SearchQueryInitiatedExchange` / `SearchQueryInitiatedSharePoint` | Exchange / SharePoint | Attacker searching for "invoice", "wire", "payment" (requires audit configuration/licence) | T1114 |
| `FileAccessed`, `FileDownloaded`, `FileSyncDownloadedFull` | SharePoint / OneDrive | Document theft | T1530 |
| `Consent to application.` | AzureActiveDirectory | User or admin consented to an app (UAL names carry a trailing period) | T1528 |
| `Add delegated permission grant.`, `Add app role assignment to service principal.` | AzureActiveDirectory | Permissions granted to an app | T1528, T1098.003 |
| `User registered security info` / `Register device` | Entra audit (AuditLogs) | Attacker adds MFA method or device for persistence | T1098.005 |

Notes:
- `MailItemsAccessed` became available in Audit (Standard) after Microsoft's
  2023-2024 logging expansion; confirm it is enabled for the mailbox
  (`Get-Mailbox | Select AuditOwner`) and that throttling did not suppress events.
- Suspicious rule patterns: names like `.`, `..`, `,` or a single letter;
  conditions on words such as invoice, payment, wire, bank, remittance, the
  CEO/CFO name, or the attacker's lookalike domain; actions `MoveToFolder`
  (RSS Feeds, Conversation History, Archive), `DeleteMessage`, `MarkAsRead`,
  `ForwardTo`/`RedirectTo`/`ForwardAsAttachmentTo` external addresses,
  `StopProcessingRules`.

### KQL (Microsoft Sentinel / Defender XDR)

```kql
// Sentinel OfficeActivity: inbox rule and forwarding changes in 30 days, parameters flattened.
OfficeActivity
| where TimeGenerated > ago(30d)
| where Operation in ("New-InboxRule", "Set-InboxRule", "Enable-InboxRule", "UpdateInboxRules", "Set-Mailbox")
| extend P = parse_json(Parameters)
| mv-apply P on (summarize Params = make_bag(bag_pack(tostring(P.Name), tostring(P.Value))))
| project TimeGenerated, UserId, Operation, ClientIP, Params
| order by TimeGenerated desc
```

```kql
// Defender XDR CloudAppEvents: MailItemsAccessed by the attacker IPs (fill from sign-in review).
let attackerIPs = dynamic(["203.0.113.10", "198.51.100.7"]);
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType == "MailItemsAccessed"
| where IPAddress in (attackerIPs)
| extend Raw = RawEventData
| project Timestamp, AccountDisplayName, IPAddress, MailAccessType = tostring(Raw.OperationProperties), Folders = Raw.Folders
// Field layout of RawEventData varies; inspect one record before relying on paths.
```

## Sign-in review

Tables: `SigninLogs` (interactive), `AADNonInteractiveUserSignInLogs`
(token refresh, background), `AADServicePrincipalSignInLogs`, risk tables
`AADUserRiskEvents` / `AADRiskyUsers`.

Look for:
- Successful sign-ins from hosting/VPS/anonymiser ASNs or new countries,
  with a user agent unlike the user's (headless browsers, `python-requests`,
  unusual OS/browser combos).
- Non-interactive sign-ins from a new IP that share a session with an
  interactive sign-in from the user's normal IP (token replay).
- `AuthenticationRequirement` = `multiFactorAuthentication` satisfied with
  "MFA requirement satisfied by claim in the token" from an IP the user never
  used interactively.
- Legacy protocols (`ClientAppUsed` such as IMAP4, POP3, Authenticated SMTP)
  if still allowed.
- Entra ID Protection risk detections such as anomalous token, attacker in
  the middle, unfamiliar sign-in properties, anonymous IP address.

```kql
// Sentinel: sign-ins for the user, interactive + non-interactive, grouped by IP and session.
// SessionId column availability varies by schema version; drop it if absent.
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(14d)
| where UserPrincipalName =~ "j.doe@corp.example"
| extend Country = tostring(parse_json(tostring(LocationDetails)).countryOrRegion)
| summarize First = min(TimeGenerated), Last = max(TimeGenerated), Count = count(),
            Apps = make_set(AppDisplayName, 10), UAs = make_set(UserAgent, 5), Results = make_set(ResultType, 10)
    by IPAddress, Country, Type, SessionId
| order by First asc
```

## AiTM token theft indicators

Adversary-in-the-middle phishing kits proxy the real Microsoft sign-in page and
steal the session cookie after MFA (T1557, T1539, T1550.004).

| Indicator | Where |
|---|---|
| Click on a phishing URL shortly before a sign-in from a new IP | `UrlClickEvents` / proxy + SigninLogs |
| Interactive sign-in from the phishing proxy's IP (often hosting ASN) followed by token use from another attacker IP | SigninLogs + non-interactive logs |
| Sign-in to OfficeHome / Office web apps, then rapid mailbox access and rule creation | SigninLogs (`AppDisplayName`), UAL |
| Attacker registers a new MFA method or device within minutes | AuditLogs |
| Risk detections: attacker in the middle, anomalous token | `AADUserRiskEvents` |
| Phishing sent internally / to partners from the compromised mailbox | UAL `Send`, message trace |

Mitigations to recommend afterwards (`hardening-m365-entra`): phishing-resistant
MFA (FIDO2 / Windows Hello for Business / certificate-based) for at least
privileged and finance users, compliant/managed-device Conditional Access,
token protection where supported, sign-in risk policies.

## OAuth illicit consent grant

- Find consents: AuditLogs `OperationName == "Consent to application"`,
  `Add delegated permission grant`, `Add app role assignment to service principal`.
- Review the app: publisher verification, reply URLs, requested scopes (`Mail.Read`,
  `Mail.ReadWrite`, `Mail.Send`, `offline_access`, `Files.ReadWrite.All`), creation
  date, number of consenting users.
- Contain: remove the grant (`Remove-MgOauth2PermissionGrant`), disable the
  service principal (`Update-MgServicePrincipal -AccountEnabled:$false`); keep a
  config export first. Tenant-wide app issues: `ir-azure-entra`.

## Containment sequence

Each step logged in `decisions.md`; account disable approved by IC.

1. **Block sign-in** (disable account) to stop re-entry during cleanup:
   `Update-MgUser -UserId $id -AccountEnabled:$false`.
2. **Revoke sessions / refresh tokens**: `Revoke-MgUserSignInSession -UserId $id`
   (or "Revoke sessions" in the Entra admin center). CAE-capable apps
   (Exchange Online, SharePoint, Teams) enforce revocation near real time;
   others may honour access tokens until expiry (typically about an hour).
3. **Remove persistence**: malicious inbox rules (`Remove-InboxRule`),
   forwarding (`Set-Mailbox -ForwardingSmtpAddress $null -DeliverToMailboxAndForward $false`),
   delegations, OAuth grants, attacker-registered devices, app passwords.
4. **Remove attacker MFA methods and require re-registration** after verifying
   the user's identity out-of-band.
5. **Reset password** (admin-initiated; deliver via verified channel).
6. **Re-enable** the account; user re-registers MFA with helpdesk verification.
7. **Block attacker infrastructure**: IPs in named locations / CA, sender and
   lookalike domains in Tenant Allow/Block List, purge the phishing mail
   (`phishing-analysis`).
8. **Monitor** for 30 days: new rules, new methods, sign-ins from the same ASNs.

## Fraud and finance response

1. Identify all payment-related mail sent from or received by the mailbox in
   the attacker window: UAL `Send`, message trace (`Get-MessageTraceV2` in
   Exchange Online; older tenants `Get-MessageTrace`), Sent Items and Deleted Items.
2. Finance contacts **its bank immediately** to request a recall of any
   fraudulent transfer (speed is the main factor in recovery).
3. Report to law enforcement via legal: in the US, file with the FBI IC3
   (ic3.gov) promptly; elsewhere, national police cybercrime/fraud units.
4. Warn counterparties (vendors/customers who received fraudulent mail) using
   phone numbers from your records, not from the emails.
5. Check for lookalike domains used in the thread and report them for takedown.
6. Hold payment-detail changes for affected vendors until verified by call-back.

## False positives & benign look-alikes

- Users' own rules (newsletters to folders, "move all mail from boss to
  folder"). Check rule creation IP/user agent against the user's normal pattern.
- Legitimate forwarding to approved partners or archiving services.
- Delegate access set by helpdesk for assistants (verify ticket).
- Travel and mobile carrier IPs triggering atypical-location alerts.
- Third-party mail apps (legitimate OAuth consents) - verify publisher and scopes.

## Pitfalls

- Resetting the password first and leaving the attacker's session, rules and
  MFA method in place.
- Deleting the malicious rule before exporting it (rule content is scope evidence).
- Ignoring non-interactive sign-ins, where token replay shows.
- Missing other users who clicked the same lure or received internal phishing
  from the compromised account.
- Assuming MFA prevents BEC; AiTM bypasses non-phishing-resistant MFA.
- Concluding "no data accessed" without `MailItemsAccessed`.

## Output

- Scope: attacker sign-ins (IPs, times, apps), mailbox actions, data
  accessed (with confidence), mail sent, consents, other affected users.
- Containment record and fraud response status.
- Detections to add (`detection-engineering`, `kql-sentinel-defender`): inbox
  rule heuristics, AiTM session anomalies, new MFA method after risky sign-in.
- Hand-offs: `incident-response` (notification: mailbox contents often include
  personal data), `phishing-analysis`, `ir-azure-entra`, `hardening-m365-entra`,
  `ir-report-writing`.

## References

- Microsoft Learn: Responding to a compromised email account (Microsoft 365).
- Microsoft Learn: Audit log activities (Microsoft Purview) and
  Search-UnifiedAuditLog; Use MailItemsAccessed to investigate compromised accounts.
- Microsoft Learn: Detect and remediate illicit consent grants.
- Microsoft Learn: Revoke user access in Microsoft Entra ID; Continuous access evaluation.
- Microsoft Security blog (2022): From cookie theft to BEC - AiTM phishing campaigns.
- FBI IC3 public service announcements on Business Email Compromise.
- MITRE ATT&CK: T1564.008, T1114.002, T1114.003, T1528, T1557, T1539,
  T1550.004, T1098.005 - https://attack.mitre.org/techniques/T1564/008/
