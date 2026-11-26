---
name: hardening-m365-entra
description: Hardening review for Microsoft 365 and Entra ID tenants. Covers a Conditional Access baseline (block legacy auth, MFA for all users, phishing-resistant authentication strengths for admins, device compliance, sign-in and user risk, device code flow), authentication methods policy, PIM for directory roles, break-glass accounts, user consent and the admin consent workflow, guest and external sharing (SharePoint/OneDrive/Teams), mailbox auditing and Unified Audit Log, blocking external auto-forwarding via the outbound spam policy, SMTP AUTH, Defender for Office 365 Standard/Strict preset policies, Secure Score, CISA SCuBA/ScubaGear, Maester, Monkey365 and CIS M365 benchmark checks. Use when asked to "harden the tenant", "/harden M365", review Conditional Access, prepare after a BEC incident, or interpret ScubaGear/Maester/Secure Score output.
---

# Microsoft 365 & Entra ID hardening

## When to use

- New or inherited tenant needs a baseline; an audit (ScubaGear, Maester, Secure
  Score, CIS M365 benchmark) needs turning into a change plan.
- After `ir-bec-m365` or `ir-azure-entra`: close the path that was used (legacy auth,
  token theft, illicit consent, forwarding rule, over-privileged admin).
- Someone wants to change Conditional Access (CA) and needs to know who gets locked out.

Not for: on-prem AD (use `hardening-windows-ad`), Azure resource configuration
(use `hardening-cloud`), or investigating a live compromise (use `ir-bec-m365`).

## Ground rules

- **Never lock out the tenant.** Two working break-glass accounts exist, are
  excluded from the policy being changed, and were test-signed-in this quarter,
  before any CA change.
- **Report-only first.** Every new CA policy runs in report-only for at least 7 days
  (14-30 for "all users" policies) and its impact is read in the sign-in logs /
  CA insights workbook before it is switched on.
- **Evidence = tenant data.** A finding cites the setting value (Graph/PowerShell
  output, portal screenshot, ScubaGear/Maester result ID), not a best-practice list.
- **Changes to CA, authentication methods, PIM settings, consent settings and
  sharing defaults need change approval** and an owner; they affect every user.
- **Licensing is a fact to check, not assume.** Risk-based CA and PIM need Entra ID
  P2 (or Entra ID Governance for some PIM features); Defender for Office 365 features
  need Plan 1/2. State which licence a recommendation needs.

## Workflow

1. **Inventory**: licences, global admin count, privileged role assignments,
   existing CA policies (exported as JSON), security defaults state, authentication
   methods policy, federated domains, app registrations/enterprise apps with high
   privileges.
2. **Run automated baselines** read-only: ScubaGear, Maester, Secure Score export,
   Defender for Office configuration analyzer / ORCA. Save reports to the case folder.
3. **Fix identity first**: break-glass, admin roles + PIM, phishing-resistant MFA for
   admins, block legacy auth, MFA for all.
4. **Then app/consent and data exposure**: user consent, app registration, guest
   settings, external sharing.
5. **Then mail**: audit, forwarding, SMTP AUTH, presets, DMARC.
6. **Monitoring**: confirm audit/sign-in logs flow to the SIEM (`logging-coverage`),
   alerts on break-glass use, CA changes, consent grants.
7. **Re-run** the baselines and record the delta.

## Prioritised checklist

| # | Control | Impact | Break risk | Licence |
|---|---|---|---|---|
| 1 | 2 break-glass accounts, monitored | Prevents lockout | None | Any |
| 2 | Block legacy authentication (CA) | Very high | Med (old MFPs/scripts using IMAP/POP/SMTP AUTH) | P1 (or security defaults) |
| 3 | MFA for all users (CA) | Very high | Low-Med | P1 |
| 4 | Phishing-resistant auth strength for admin roles | Very high | Med (admins need keys/WHfB) | P1 |
| 5 | Fewer than 5 Global Admins, PIM eligible not permanent | High | Low | P2 / Governance |
| 6 | User consent restricted + admin consent workflow | High | Low-Med (users request apps) | Any |
| 7 | Block external auto-forwarding | High | Low (some business forwards) | Any |
| 8 | Mailbox audit on, UAL on, logs to SIEM | High (for IR) | None | Any (retention varies) |
| 9 | Risk-based CA (sign-in risk, user risk) | High | Low-Med | P2 |
| 10 | Device compliance / hybrid join for sensitive apps | High | Med | P1 + Intune |
| 11 | Defender for Office Standard/Strict presets | High | Low | MDO P1/P2 |
| 12 | Block device code flow where not needed | Med-High | Low | P1 |
| 13 | Restrict guests and external sharing defaults | Med-High | Med (collaboration) | Any |
| 14 | Disable SMTP AUTH tenant-wide | Med | Med (devices/apps sending mail) | Any |

## Conditional Access baseline

Naming convention helps reviews, e.g. `CA001-Global-BlockLegacyAuth`. Every policy
excludes the break-glass group; avoid other exclusions or document each one.

| Policy | Users | Target | Conditions | Grant / session |
|---|---|---|---|---|
| Block legacy auth | All | All resources | Client apps: Exchange ActiveSync, Other clients | Block |
| MFA all users | All (exclude break-glass, sync service account if any) | All resources | Any | Require auth strength "Multifactor authentication" |
| Admins phishing-resistant | Directory roles (GA, Privileged Role/Auth Admin, Security, Exchange, SharePoint, CA Admin, Application/Cloud App Admin, User Admin, Helpdesk, Hybrid Identity Admin) | All resources | Any | Auth strength "Phishing-resistant MFA" |
| Sign-in risk | All | All resources | Sign-in risk Medium+ | Require MFA (sign-in frequency every time) |
| User risk | All | All resources | User risk High | Require password change + MFA (or block, then remediate) |
| Device compliance | All (or pilot) | Sensitive apps / all | Platforms | Require compliant or hybrid joined device |
| Block device code flow | All (exclude justified) | All resources | Authentication flows: device code flow | Block |
| Guests MFA | Guest/external users | All resources | Any | Require MFA |
| Admin portals | All | "Microsoft Admin Portals" | Any | Require MFA / phishing-resistant |

- Prefer **authentication strengths** over the legacy "Require MFA" grant: built-ins
  are *Multifactor authentication*, *Passwordless MFA*, *Phishing-resistant MFA*
  (FIDO2 security keys/passkeys, Windows Hello for Business, certificate-based
  multifactor).
- Security defaults and CA are mutually exclusive; moving to CA means rebuilding what
  defaults gave you.
- Consider token protection (where supported) and Continuous Access Evaluation for
  token theft; test client compatibility.
- Use the CA **What If** tool and the *Conditional Access insights and reporting*
  workbook to read report-only impact.

```kql
// Sentinel/Log Analytics: legacy auth sign-ins in last 30 days (who breaks when you block)
SigninLogs
| where TimeGenerated > ago(30d)
| where ClientAppUsed !in ("Browser", "Mobile Apps and Desktop clients")
| summarize Count=count(), LastSeen=max(TimeGenerated) by UserPrincipalName, ClientAppUsed, AppDisplayName, ResultType
| order by Count desc
```

```kql
// Report-only impact of a specific CA policy (replace the name). Shows who would be blocked/challenged
SigninLogs
| where TimeGenerated > ago(14d)
| mv-expand cap = ConditionalAccessPolicies
| where tostring(cap.displayName) == "CA003-Admins-PhishingResistant"
| summarize Count=count() by Result = tostring(cap.result), UserPrincipalName, AppDisplayName
// result values include reportOnlySuccess, reportOnlyFailure, reportOnlyInterrupted, reportOnlyNotApplied
```

## Authentication methods

- Manage methods in the **Authentication methods policy** (the legacy per-user MFA and
  SSPR method settings are being retired); migrate and confirm with the migration
  control.
- Enable passkeys/FIDO2, Microsoft Authenticator with number matching (default) and
  additional context; restrict or disable SMS and voice where possible, at least for
  admins. Temporary Access Pass for onboarding/recovery, short lifetime, one-time use.
- Run an Authenticator registration campaign; check *Authentication methods >
  User registration details* for users with no MFA registered (these are takeover
  candidates if an attacker registers first). Restrict MFA registration with a CA
  policy on the *Register security information* user action (trusted location or
  compliant device).
- Turn off per-user MFA once CA covers it (mixing both confuses troubleshooting).

## Privileged roles and PIM

- Fewer than five Global Administrators (Microsoft's guidance), at least two.
  Daily-use accounts never hold privileged roles; admins use separate cloud-only
  accounts (not synced from AD, so an AD compromise does not become a tenant compromise).
- **PIM**: roles *eligible*, not active; activation requires MFA (or auth context
  with phishing-resistant strength), justification, ticket number, approval for GA
  and Privileged Role Administrator; max activation 1-8 h; notifications on activation.
- Quarterly **access reviews** of privileged roles and of service principals with
  Graph application permissions like `RoleManagement.ReadWrite.Directory`,
  `AppRoleAssignment.ReadWrite.All`, `Application.ReadWrite.All`, `Mail.ReadWrite`.

```powershell
# Microsoft Graph PowerShell: permanent (active) role assignments to review
Connect-MgGraph -Scopes "RoleManagement.Read.Directory","Directory.Read.All"
Get-MgRoleManagementDirectoryRoleAssignment -All -ExpandProperty Principal |
  Select-Object RoleDefinitionId, @{n='Principal';e={$_.Principal.AdditionalProperties.userPrincipalName}}
```

## Break-glass accounts

- Two cloud-only accounts on the `*.onmicrosoft.com` domain, permanent Global
  Administrator, not tied to a person's phone; protected with FIDO2 security keys
  (Microsoft's mandatory MFA for admin portals applies to them too) stored in
  separate physical safes.
- Excluded from CA policies via a dedicated group (or covered by one policy that only
  requires phishing-resistant MFA). Do not exclude them from *everything* without
  monitoring.
- Alert on every sign-in; test each quarter and record the test.

```kql
// Alert: any break-glass sign-in (replace UPNs). Severity high, page on-call
SigninLogs
| where UserPrincipalName in~ ("bg-01@contoso.onmicrosoft.com", "bg-02@contoso.onmicrosoft.com")
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, ResultType, ConditionalAccessStatus
```

## Consent and app governance

- *Enterprise applications > Consent and permissions*: set user consent to **Do not
  allow** or **Allow for apps from verified publishers, for selected (low-impact)
  permissions**. Enable the **admin consent workflow** with named reviewers.
- *Users can register applications* = No for most tenants.
- Review existing grants: high-privilege delegated grants to unverified apps,
  multi-tenant apps with Mail/Files permissions, service principals with new
  credentials.
- Audit operations to monitor (Entra AuditLogs `OperationName`): `Consent to
  application`, `Add delegated permission grant`, `Add app role assignment to service
  principal`, `Add service principal credentials`, `Update application – Certificates
  and secrets management`, `Add owner to application`.

```kql
// New consents in the last 7 days with the permissions granted (tune: allowlist approved apps)
AuditLogs
| where TimeGenerated > ago(7d) and OperationName == "Consent to application"
| extend App = tostring(TargetResources[0].displayName), By = tostring(InitiatedBy.user.userPrincipalName)
| extend Props = tostring(TargetResources[0].modifiedProperties)
| project TimeGenerated, By, App, Props
```

## Guests and external sharing

- Entra *External collaboration settings*: guest user access restricted to their own
  directory objects; guest invites limited to specific admin roles or members (not
  "anyone including guests"); allow/deny list of collaboration domains if needed.
- SharePoint/OneDrive (`Set-SPOTenant`): `SharingCapability` no broader than
  `ExternalUserSharingOnly` (or `ExistingExternalUserSharingOnly`); if *Anyone* links
  are allowed, set `RequireAnonymousLinksExpireInDays` and view-only defaults;
  `DefaultSharingLinkType` = `Internal` or `Direct`.
- Teams external access and guest access: allow-list partner domains if practical;
  block unmanaged Teams accounts if not needed (a known phishing vector).
- Review sites shared with "Everyone except external users" containing sensitive data.

## Mail: auditing, forwarding, transport

```powershell
# Exchange Online PowerShell
Get-AdminAuditLogConfig | Select UnifiedAuditLogIngestionEnabled          # must be True
Get-OrganizationConfig  | Select AuditDisabled                            # must be False
Get-Mailbox -ResultSize Unlimited | ? {$_.AuditEnabled -eq $false} | Select UserPrincipalName
Get-HostedOutboundSpamFilterPolicy | Select Name, AutoForwardingMode      # target: Off
Get-RemoteDomain Default | Select AutoForwardEnabled                      # target: False
Get-TransportConfig | Select SmtpClientAuthenticationDisabled             # target: True (exceptions per mailbox)
Get-Mailbox -ResultSize Unlimited | ? {$_.ForwardingSmtpAddress -or $_.ForwardingAddress} | Select UserPrincipalName,ForwardingSmtpAddress,ForwardingAddress
```

- **Block external auto-forwarding**: outbound spam filter policy
  `Set-HostedOutboundSpamFilterPolicy -Identity Default -AutoForwardingMode Off`.
  Create a scoped custom policy for approved exceptions instead of leaving it on for
  everyone. The policy covers inbox-rule and mailbox (SMTP) forwarding.
- Mailbox auditing is on by default; verify it was not disabled org-wide or per
  mailbox, and that the actions you need (incl. `MailItemsAccessed`, `Send`,
  `SearchQueryInitiated` where licensed) are logged. Retention depends on Audit
  (Standard) vs (Premium) licensing; export to the SIEM for longer retention.
- Disable SMTP AUTH tenant-wide, enable per mailbox only for named devices/apps;
  inventory first with the SMTP AUTH clients report.
- Email authentication: SPF, DKIM signing for custom domains, DMARC moving to
  `p=quarantine`/`p=reject` after monitoring aggregate reports.

## Defender for Office 365

- Apply the **Standard** preset to everyone and **Strict** to high-value targets
  (executives, finance, admins). Presets get Microsoft's updated values automatically.
- Ensure Safe Links (incl. Teams/Office apps, no click-through), Safe Attachments,
  impersonation protection (users and domains), mailbox intelligence, zero-hour auto
  purge are on.
- Use *Configuration analyzer* (or the ORCA module) to find policies weaker than
  Standard; custom policies with higher priority silently override presets.
- Users report via the built-in Report button; route submissions to the SOC
  (`phishing-analysis`).

## Baseline and audit tools

| Tool | How | Output |
|---|---|---|
| Secure Score | Defender portal; export recommendations | Score + per-control status; do not chase points over risk |
| CISA ScubaGear | `Install-Module ScubaGear`; `Initialize-SCuBA`; `Invoke-SCuBA -ProductNames aad,exo,defender,sharepoint,teams` | HTML/JSON report vs SCuBA secure configuration baselines (mandated for US federal agencies by BOD 25-01) |
| Maester | `Install-Module Maester`; `Install-MaesterTests`; `Connect-Maester`; `Invoke-Maester` | Pester-based tests incl. EIDSCA and CISA checks; can run in CI for drift |
| Monkey365 | PowerShell module, read-only collection | Findings mapped to CIS M365 / Azure benchmarks |
| CIS Microsoft 365 Foundations Benchmark | Manual / tool-mapped | L1/L2 recommendations |

Run them with a read-only (Global Reader + Security Reader) account where the tool
supports it, and keep the JSON outputs to diff over time.

## False positives & benign look-alikes

- Legacy-auth sign-ins listed as "Other clients" can be failed password-spray
  attempts (ResultType non-zero), not real dependencies; count only successful
  ones as users who will break.
- `ConditionalAccessStatus == notApplied` is normal for some first-party/service
  sign-ins; it is not by itself a gap.
- A "risky user" in ID Protection may be a leaked-credential match for a password
  already changed; check the risk detail and timestamp.
- External forwarding to a known partner or a personal archive approved by HR is a
  business exception, not an incident; document it in a scoped policy.
- Admin consent to a well-known first-party Microsoft app is normal; unverified
  publisher + broad mail/file scopes is not.

## Pitfalls

- Enabling a block policy for "All users" without excluding break-glass, or excluding
  so many groups that the policy covers nobody that matters.
- Excluding the directory sync account from MFA but not restricting it by location.
- Forgetting service principals and workload identities: CA for users does not cover
  app-only access with client secrets/certificates.
- Relying on security defaults and adding CA later (defaults turn off when CA is used).
- Assuming mailbox auditing is on because it is "default" in a tenant migrated years ago.
- Counting Secure Score points instead of closing the attack path seen in the last incident.
- Long-lived app secrets with no owner; rotate and prefer certificates or managed identity.

## Output

- Findings table: setting, current value (evidence), target, impact, break risk,
  licence needed, owner, change ticket, rollback.
- CA policy set as JSON/Graph export with report-only impact summary per policy.
- Monitoring hand-off: alerts for break-glass sign-in, CA policy changes
  (`Update conditional access policy`), new consents, new forwarding rules, PIM
  activations outside hours, written with `detection-engineering` /
  `kql-sentinel-defender`.
- Post-BEC hardening goes back into the `ir-bec-m365` case. Start reviews with `/harden`.

## References

- MITRE ATT&CK: T1078.004 Cloud Accounts, T1110.003 Password Spraying, T1528 Steal
  Application Access Token, T1114.003 Email Forwarding Rule, T1098.001/T1098.003
  Additional Cloud Credentials/Roles, T1621 MFA Request Generation, T1566 Phishing.
- Microsoft Learn: Conditional Access deployment and common policies; Authentication
  strengths; Manage emergency access accounts in Microsoft Entra ID; Microsoft Entra
  Privileged Identity Management; Configure how users consent to applications;
  Configure outbound spam policies (automatic forwarding); Preset security policies
  in EOP and Defender for Office 365; Microsoft Secure Score.
- CISA: Secure Cloud Business Applications (SCuBA) M365 baselines; BOD 25-01.
- CIS Microsoft 365 Foundations Benchmark.
