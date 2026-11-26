---
name: ir-azure-entra
description: Incident response for Microsoft Entra ID (Azure AD) and Azure subscriptions. Covers SigninLogs, AADNonInteractiveUserSignInLogs, AADServicePrincipalSignInLogs, AuditLogs and AzureActivity in Microsoft Sentinel / Log Analytics; service principal and application credential additions (T1098.001), app role assignments and consent grants, privileged role assignment and PIM activation, Conditional Access policy changes, domain federation changes (T1484.002), token theft, Primary Refresh Token (PRT) abuse and device code phishing, Azure RBAC role assignments and VM Run Command, plus revocation (Revoke-MgUserSignInSession, CAE, device disable) and KQL queries. Use for "Global Admin compromised", "suspicious app credential added", "someone changed Conditional Access", "token theft", "PRT", or "Azure subscription abuse".
---

# Azure and Entra ID incident response

Entra ID is the control plane for M365 and Azure. An attacker with a
privileged role, an over-permissioned application or a stolen token can act
across the whole tenant without touching an endpoint.

## When to use

- Privileged role or PIM activity you cannot explain.
- New credentials on an application or service principal; new consents or app
  role assignments with high-privilege Graph permissions.
- Conditional Access, authentication methods policy, or federation changes.
- Token theft / PRT / device code phishing alerts, risky users and sign-ins.
- Azure subscription abuse: role assignments, Run Command, key listing,
  disk/snapshot export, crypto-mining VMs.

For a single compromised mailbox start with `ir-bec-m365`. For the hunt
version of these questions, `hunt-cloud-control-plane`.

## Ground rules

1. **Export logs before acting.** Entra sign-in and audit logs have short
   default retention in the portal (commonly 7-30 days depending on licence);
   if they are not already streamed to Log Analytics / Sentinel / a SIEM,
   export now (portal download or Graph) and configure diagnostic settings.
2. **Identify the actor type** for every change: user, service principal,
   managed identity or Microsoft first-party service (`InitiatedBy.user` vs
   `InitiatedBy.app`). Do not attribute an app's action to a user.
3. **Workload identities are first-class suspects.** Scope service principals
   and their credentials as carefully as users.
4. **Revocation is multi-layer.** User sessions, refresh tokens, device (PRT),
   app credentials and Azure RBAC must each be addressed; one does not imply
   the others.
5. **Tenant-wide changes (CA, federation, auth methods) need IC approval**
   and a rollback plan; a wrong change can lock out the whole organisation.
   Keep break-glass accounts verified and monitored.

## Workflow

1. Confirm: anomalous sign-in or change, corroborated by a second source.
2. Preserve: export SigninLogs (all four sign-in tables), AuditLogs,
   AzureActivity, risk events for the window.
3. Identify all compromised identities (users, SPs, devices) and their roles.
4. Contain: revoke sessions, disable accounts/devices/SPs, remove credentials,
   with approvals.
5. Scope: every change made by attacker-controlled identities, every
   permission they granted, every resource they touched.
6. Eradicate: remove persistence (credentials, consents, role assignments,
   federation, CA exclusions, MFA methods, devices).
7. Recover and harden (`hardening-m365-entra`, `hardening-cloud`); monitor.

## Log sources

| Table (Sentinel / Log Analytics) | Contents | Key fields |
|---|---|---|
| `SigninLogs` | Interactive user sign-ins | `UserPrincipalName`, `IPAddress`, `AppDisplayName`, `ResourceDisplayName`, `ResultType`, `ConditionalAccessStatus`, `AuthenticationRequirement`, `AuthenticationProtocol`, `DeviceDetail`, `UserAgent`, `RiskLevelDuringSignIn`, `UniqueTokenIdentifier` |
| `AADNonInteractiveUserSignInLogs` | Token refreshes and background sign-ins | as above; high volume; token replay shows here |
| `AADServicePrincipalSignInLogs` | App-only sign-ins of service principals | `ServicePrincipalId`, `ServicePrincipalName`, `IPAddress`, `ResourceDisplayName` |
| `AADManagedIdentitySignInLogs` | Managed identity token requests | |
| `AuditLogs` | Directory changes | `OperationName`, `Category`, `InitiatedBy`, `TargetResources` (with `modifiedProperties`), `Result` |
| `AADUserRiskEvents`, `AADRiskyUsers` | Entra ID Protection detections and user risk | `RiskEventType`, `RiskLevel`, `DetectionTimingType` |
| `AzureActivity` | Azure Resource Manager control plane | `OperationNameValue`, `Caller`, `CallerIpAddress`, `ActivityStatusValue`, `ResourceGroup`, `_ResourceId` |
| `MicrosoftGraphActivityLogs` (if enabled) | Graph API requests per token | `RequestUri`, `AppId`, `IPAddress`, `UserId`/`ServicePrincipalId` |

Field names and availability change over time; check the Microsoft Learn
table reference for your workspace if a column is missing.

## High-signal AuditLogs operations

| OperationName | Why it matters | ATT&CK |
|---|---|---|
| `Add service principal credentials` | New secret/cert on a service principal (persistence, app-only access) | T1098.001 |
| `Update application – Certificates and secrets management ` (note en dash and trailing space) | New secret/cert on an app registration | T1098.001 |
| `Add owner to application`, `Add owner to service principal` | Control over an app's credentials | T1098 |
| `Add app role assignment to service principal` | Application permissions (e.g. Graph `Mail.Read`, `RoleManagement.ReadWrite.Directory`) granted | T1098.003 |
| `Add delegated permission grant`, `Consent to application` | Delegated permissions / user or admin consent | T1528 |
| `Add member to role`, `Add eligible member to role`, PIM `... (PIM activation)` operations | Privileged role assignment/activation | T1098.003 |
| `Add conditional access policy`, `Update conditional access policy`, `Delete conditional access policy` | Weakening CA, adding exclusions | T1556.009 |
| `Set domain authentication`, `Set federation settings on domain` | Federation backdoor (attacker IdP trusted) | T1484.002 |
| `Add unverified domain to company`, `Verify domain` | Precursor to federation abuse | T1484.002 |
| `User registered security info`, `User deleted security info`, `Reset user password`, `Update user` | MFA method or account changes | T1098.005 |
| `Register device`, `Add registered owner to device` | Attacker device for PRT / CA bypass | T1098.005 |
| `Update authorization policy`, authentication methods policy changes | Tenant-wide weakening (e.g. who can consent/register apps) | T1556 |

## Queries

```kql
// Sentinel: credential additions to apps/service principals in 30 days, with actor and target.
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName has_any ("Add service principal credentials", "Certificates and secrets management")
| extend Actor = coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName)),
         ActorIP = tostring(InitiatedBy.user.ipAddress),
         Target = tostring(TargetResources[0].displayName), TargetId = tostring(TargetResources[0].id)
| project TimeGenerated, OperationName, Actor, ActorIP, Target, TargetId, Result
```

```kql
// Sentinel: privileged role assignments and PIM activations. Tune: role list to your tier-0 roles.
AuditLogs
| where TimeGenerated > ago(30d)
| where Category == "RoleManagement"
| where OperationName has "Add member to role" or OperationName has "Add eligible member to role"
| mv-expand TR = TargetResources
| mv-expand MP = TR.modifiedProperties
| where tostring(MP.displayName) == "Role.DisplayName"
| extend Role = trim('"', tostring(MP.newValue))
| where Role in ("Global Administrator", "Privileged Role Administrator", "Application Administrator",
                 "Cloud Application Administrator", "Privileged Authentication Administrator",
                 "Exchange Administrator", "Security Administrator", "Hybrid Identity Administrator")
| extend Actor = coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
| project TimeGenerated, OperationName, Actor, Role, Target = tostring(TargetResources[0].userPrincipalName)
```

```kql
// Sentinel: Conditional Access and federation changes. Every hit deserves review.
AuditLogs
| where TimeGenerated > ago(90d)
| where OperationName has "conditional access policy"
     or OperationName in ("Set domain authentication", "Set federation settings on domain", "Verify domain")
| extend Actor = coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
| project TimeGenerated, OperationName, Actor, Target = tostring(TargetResources[0].displayName),
          Changes = TargetResources[0].modifiedProperties
```

```kql
// Sentinel: device code flow sign-ins (common phishing vector). Tune: exclude known kiosk/IoT users.
SigninLogs
| where TimeGenerated > ago(14d)
| where AuthenticationProtocol =~ "deviceCode"
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, ResultType, UserAgent,
          Country = tostring(LocationDetails.countryOrRegion)
```

```kql
// Sentinel: service principal sign-ins from new IPs vs a 30-day baseline. Tune: lookback windows.
let baseline = AADServicePrincipalSignInLogs
    | where TimeGenerated between (ago(30d) .. ago(1d))
    | distinct ServicePrincipalId, IPAddress;
AADServicePrincipalSignInLogs
| where TimeGenerated > ago(1d)
| join kind=leftanti baseline on ServicePrincipalId, IPAddress
| summarize Count = count(), Resources = make_set(ResourceDisplayName, 10)
    by ServicePrincipalName, ServicePrincipalId, IPAddress
```

```kql
// Sentinel: Azure control-plane actions often used post-compromise.
AzureActivity
| where TimeGenerated > ago(30d)
| where OperationNameValue in~ (
    "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE",
    "MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION",
    "MICROSOFT.COMPUTE/VIRTUALMACHINES/EXTENSIONS/WRITE",
    "MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION",
    "MICROSOFT.COMPUTE/DISKS/BEGINGETACCESS/ACTION",
    "MICROSOFT.COMPUTE/SNAPSHOTS/BEGINGETACCESS/ACTION",
    "MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE")
| where ActivityStatusValue in~ ("Success", "Succeeded", "Start", "Started")
| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, ActivityStatusValue, _ResourceId
```

## Token theft and PRT

| Scenario | Indicators | Notes |
|---|---|---|
| AiTM session cookie theft | Sign-in from attacker IP right after phishing click; non-interactive refreshes from a different IP; MFA "satisfied by claim in token" | See `ir-bec-m365` |
| Refresh/access token replay from malware (infostealer) | Same `UniqueTokenIdentifier` lineage or session used from a new IP/ASN; no matching interactive sign-in; endpoint has infostealer detections | Correlate with EDR on the user's devices |
| PRT theft from a device | Sign-ins showing the user's joined/compliant device ID from an unexpected IP; EDR alerts on access to PRT/browser cookie stores; tools touching `BrowserCore.exe` or LSASS CloudAP | Defender for Endpoint has alerts for possible PRT access attempts |
| Device code phishing | `AuthenticationProtocol == deviceCode` for users who never use it; sign-in IP differs from the user's normal | T1528; restrict with CA authentication flows policy |
| Rogue device registration | `Register device` by user shortly after risky sign-in; device used to satisfy CA | Disable/delete the device |

Entra ID Protection risk detection types relevant here include anomalous
token, token issuer anomaly, attacker in the middle, unfamiliar sign-in
properties, anonymous IP address and Microsoft Entra threat intelligence
(names as shown in `RiskEventType` may differ in casing; check your data).

## Containment and revocation

All tenant-level steps need IC approval; preserve the object's configuration
(export JSON via Graph) before changing it.

| Target | Action | Command / location | Caveat |
|---|---|---|---|
| User | Block sign-in | `Update-MgUser -UserId <id> -AccountEnabled:$false` | Hybrid users: also disable on-prem AD or sync will revert |
| User | Revoke refresh tokens and session cookies | `Revoke-MgUserSignInSession -UserId <id>` / "Revoke sessions" | Access tokens may live ~1 h; CAE-capable resources (Exchange, SharePoint, Teams, Graph for supported clients) enforce faster |
| User | Remove attacker MFA methods, require re-registration | Authentication methods blade / Graph `Remove-MgUserAuthentication*Method` | Verify user identity out-of-band |
| Device | Disable device (invalidates its PRT) | `Update-MgDevice -DeviceId <objectId> -AccountEnabled:$false` | Device-bound sign-ins for the real user break too |
| Service principal | Remove credentials | `Remove-MgServicePrincipalPassword`, `Remove-MgApplicationPassword`, key credential removal | Breaks the integration; coordinate with app owner |
| Service principal | Disable | `Update-MgServicePrincipal -ServicePrincipalId <id> -AccountEnabled:$false` | Existing tokens valid until expiry |
| Consent grant | Remove | `Remove-MgOauth2PermissionGrant`, `Remove-MgServicePrincipalAppRoleAssignment` | |
| Role | Remove assignment / eligibility | Entra roles / PIM | Check both active and eligible assignments |
| CA / federation | Revert change | From exported config; `Set domain authentication` back to Managed if federation was hijacked | Can lock out users if wrong; test with break-glass |
| Azure RBAC | Remove role assignments at all scopes, including management groups and root (`/`) | Azure portal / `Remove-AzRoleAssignment` | Global Admins can elevate to User Access Administrator at root; check for `elevateAccess` use |
| Azure secrets | Rotate storage account keys, Key Vault secrets, SAS tokens the attacker could list | Per resource | Breaks dependants |

Hybrid: if on-prem AD is compromised, Entra is too (and vice versa via
Entra Connect, pass-through authentication agents, AD FS signing certificates
- Golden SAML, T1606.002). Bring in `hunt-ad-identity-attacks`.

## False positives & benign look-alikes

- Credential rotation by automation (Key Vault-integrated rotation, CI/CD,
  vendor-managed apps); confirm the actor is the expected pipeline identity.
- PIM activations by on-call admins (check justification and ticket).
- Microsoft first-party service principals performing changes (actor is an
  app such as "Microsoft Azure AD Internal..." or similar service names);
  verify against documentation before discounting.
- Device code flow used legitimately on shared devices, Teams Rooms, CLI tools
  (`az login --use-device-code`).
- CA policy edits during planned rollouts; check change tickets and the diff.

## Pitfalls

- Disabling the cloud account of a synced user without disabling on-prem AD.
- Revoking user sessions but leaving a malicious app with application
  permissions that never needed the user.
- Reviewing only active role assignments and missing PIM-eligible ones.
- Missing secrets added to the **application** object vs the **service
  principal** object (both can hold credentials).
- Ignoring Azure RBAC at management-group/root scope.
- Logs not exported in time, and retention expiring during the investigation.

## Output

- Inventory of compromised users, devices, service principals, apps, roles.
- Change timeline (UTC) of attacker actions with before/after values.
- Containment record with approvals; exported configs of changed objects.
- Detections to add (`kql-sentinel-defender`, `detection-engineering`).
- Hand-offs: `ir-bec-m365`, `hunt-cloud-control-plane`, `hardening-m365-entra`,
  `hardening-cloud`, `hunt-ad-identity-attacks`, `incident-response`, `ir-report-writing`.

## References

- Microsoft Learn: Azure Monitor Logs table reference (SigninLogs,
  AADNonInteractiveUserSignInLogs, AADServicePrincipalSignInLogs, AuditLogs, AzureActivity).
- Microsoft Learn: Microsoft Entra audit log activity reference.
- Microsoft Learn: Revoke user access in an emergency in Microsoft Entra ID;
  Continuous access evaluation; What is a Primary Refresh Token.
- Microsoft Learn: Microsoft Entra ID Protection risk detections.
- Microsoft incident response playbooks: App consent grant, Compromised and
  malicious applications investigation.
- MITRE ATT&CK: T1098.001, T1098.003, T1528, T1484.002, T1556.009, T1606.002,
  T1550.001 - https://attack.mitre.org/techniques/T1098/001/
