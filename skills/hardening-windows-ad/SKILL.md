---
name: hardening-windows-ad
description: Hardening review and remediation plan for Windows endpoints, servers and Active Directory. Covers the AD tier model / Microsoft Enterprise Access Model, PAWs, Protected Users, Windows LAPS, NTLMv1/LM removal and NTLM auditing (Event 4624 package name, 8001-8004), SMB signing and SMBv1 removal, LDAP signing and channel binding (Events 2887/2889, 3039-3041), Kerberos AES and RC4 removal (4769 ticket encryption 0x17), krbtgt rotation, ADCS ESC1-ESC8 hardening and KB5014754 strong mapping, ASR rules, Credential Guard, LSA protection (RunAsPPL), WDAC/App Control and AppLocker, PowerShell script block logging and Constrained Language Mode, local admin cleanup, PingCastle / Purple Knight / BloodHound attack-path review. Use when asked to harden AD, "run /harden on the domain", interpret a PingCastle report, plan a tier-0 cleanup, or decide which change might break legacy apps.
---

# Windows & Active Directory hardening

## When to use

- A domain or Windows fleet needs a hardening review, a post-incident "never again"
  plan, or an audit finding (PingCastle, Purple Knight, Defender for Identity posture
  assessments, Secure Score) needs turning into a change plan.
- Someone asks "is it safe to turn on X?" (LDAP signing, SMB signing, RC4 removal,
  Credential Guard) and needs the blast radius before a change window.
- After `ir-ransomware` or `hunt-ad-identity-attacks` found an attack path that must be
  closed (Kerberoastable admin, ESC1 template, unconstrained delegation, shared local
  admin password).

Not for: detecting attacks in progress (use `hunt-ad-identity-attacks`,
`hunt-credential-access`, `hunt-lateral-movement`) or Entra ID tenant settings
(use `hardening-m365-entra`).

## Ground rules

- **Audit before enforce, always.** Every control below that can break authentication
  (NTLM restrictions, LDAP signing/CBT, SMB signing, RC4 removal, Protected Users,
  WDAC, LSA protection) has an audit mode or audit events. No enforcement change
  without at least 14-30 days of audit data showing who would break.
- **No change without an owner, a ticket and a rollback.** Changes to DCs, Default
  Domain (Controller) Policy, krbtgt, ADCS or tier-0 groups need change approval.
  Write the rollback (GPO unlink, registry value, group removal) before the change.
- **Evidence for every finding.** A finding is the command/report output that shows
  it (PingCastle rule ID, attribute value, event count), not "probably misconfigured".
- **Never test a hardening change on all DCs at once.** One DC / one pilot OU first,
  then rings.
- **Tier 0 is defined by control, not by job title.** Anything that can control a DC
  (ADCS, Entra Connect sync server, backup of DCs, hypervisor hosting DCs, SCCM with
  DC clients, GPO editors) is tier 0 and is hardened as such.

## Workflow

1. **Inventory and baseline.** Domain/forest functional level, DC OS versions,
   number of domains/trusts, ADCS CAs, Entra Connect servers, tier-0 group membership.
2. **Run the audits** (read-only): PingCastle healthcheck, Purple Knight, BloodHound
   CE collection for attack paths, Locksmith or PSPKIAudit for ADCS. Store reports in
   the case folder with date and operator.
3. **Turn on the audit telemetry** you need to measure blast radius: NTLM auditing,
   LDAP interface diagnostics on DCs, SMB1 access auditing, Kerberos 4769 on DCs,
   ASR in audit mode, WDAC/AppLocker in audit mode. Confirm with `logging-coverage`.
4. **Fix tier 0 first** (privileged groups, attack paths into Domain Admins, ADCS,
   krbtgt, DC hygiene). An attacker with DA makes every other control moot.
5. **Kill credential theft and relay paths** (LAPS, local admin cleanup, NTLM/SMB/LDAP
   hardening, Credential Guard, LSA protection, Protected Users).
6. **Reduce execution surface** (ASR, WDAC/AppLocker, PowerShell logging + CLM,
   remove PowerShell v2, Office macro policy).
7. **Re-run the audits**, record score deltas and residual risk, hand detections for
   anything you cannot fix to `detection-engineering`.

## Prioritised checklist

Impact = risk reduction. Break risk = how likely it is to break something when enforced.

| # | Control | Impact | Break risk | Measure first with |
|---|---|---|---|---|
| 1 | Empty/clean tier-0 groups (DA, EA, Schema Admins, Administrators, Account/Server/Print/Backup Operators, DnsAdmins) | Very high | Low | `Get-ADGroupMember -Recursive`, PingCastle P-* rules |
| 2 | Remove attack paths to DA (ACLs, delegation, GPO edit rights, Kerberoastable admins) | Very high | Low-Med | BloodHound CE "shortest paths to Domain Admins" |
| 3 | Windows LAPS on all workstations and member servers | Very high | Low | LAPS event log, `Get-LapsADPassword` |
| 4 | ADCS: fix ESC1/ESC2/ESC3/ESC4/ESC6/ESC8, enable CA auditing | Very high | Low-Med | Locksmith / PSPKIAudit |
| 5 | Deny tier-0 logon to lower tiers (user rights assignment) | High | Med | 4624 for admin accounts on non-T0 hosts |
| 6 | Disable SMBv1; require SMB signing | High | Med (old NAS/printers/scanners) | SMBServer Audit 3000 |
| 7 | LM/NTLMv1 off (LmCompatibilityLevel 5), no LM hashes | High | Med (old appliances) | 4624 `Package Name (NTLM only)` |
| 8 | LDAP signing + channel binding on DCs | High | Med (apps doing simple binds over 389) | DC events 2887/2889, 3039-3041 |
| 9 | Credential Guard + LSA protection on clients | High | Low-Med (MSCHAPv2 Wi-Fi/VPN, LSA plug-ins) | CodeIntegrity 3065/3066 audit |
| 10 | Protected Users for human admins | High | Med (NTLM/RC4/delegation dependent tools) | Test with one admin first |
| 11 | ASR rules (audit, then block) | High | Med (line-of-business macros, mgmt tools) | Defender 1122 / DeviceEvents `Asr*Audited` |
| 12 | Kerberos AES-only, retire RC4 | Med-High | Med-High (old service accounts, non-Windows keytabs) | 4769 TicketEncryptionType 0x17 |
| 13 | krbtgt rotation (routine and after compromise) | High after compromise | Low if done correctly | Replication health, `repadmin` |
| 14 | PowerShell SBL/module logging, remove PSv2, CLM via WDAC | Med-High | Low (logging) / High (CLM) | 4104 volume |
| 15 | WDAC / AppLocker allowlisting | Very high | High | CodeIntegrity 3076, AppLocker 8003/8006 |
| 16 | `ms-DS-MachineAccountQuota` = 0, Print Spooler off on DCs | Med | Low | Who joins machines today |

## Tier model / Enterprise Access Model

- Microsoft's current guidance is the **Enterprise Access Model** (control plane,
  management plane, data/workload plane, user and app access). The classic AD
  **tier 0 / 1 / 2** model is still the practical way to implement the control
  plane on-prem.
- Tier 0: DCs, ADCS CAs, ADFS, Entra Connect sync servers, PAM/identity tools with
  write access to AD, DC backup systems, virtualisation hosts and storage of DCs.
- Separate admin accounts per tier (`adm-t0-…`, `adm-t1-…`), admin work only from a
  **PAW** (privileged access workstation) for tier 0.
- Enforce with GPO user rights on lower tiers: *Deny log on locally*, *Deny log on
  through Remote Desktop Services*, *Deny access to this computer from the network*,
  *Deny log on as a batch job*, *Deny log on as a service* for tier-0 groups.
- Stronger enforcement: **Authentication Policies and Silos** (DFL 2012 R2+) restrict
  where tier-0 accounts may obtain a TGT.
- Mark admin accounts **"Account is sensitive and cannot be delegated"**; find
  unconstrained delegation on non-DCs and remove it.

```powershell
# Find computers (non-DC) and users trusted for unconstrained delegation
Get-ADComputer -Filter {TrustedForDelegation -eq $true -and PrimaryGroupID -ne 516} -Properties TrustedForDelegation | Select Name
Get-ADUser -Filter {TrustedForDelegation -eq $true} | Select SamAccountName
# Kerberoastable privileged users (SPN set + adminCount=1)
Get-ADUser -Filter {ServicePrincipalName -like "*" -and AdminCount -eq 1} -Properties ServicePrincipalName,PasswordLastSet | Select SamAccountName,PasswordLastSet
```

Service accounts: move to **gMSA** where the app supports it; otherwise 25+ character
random passwords, AES-only, not in privileged groups.

## Protected Users

Effects for members (DC-side protections need DFL 2012 R2+): no NTLM authentication,
no DES/RC4 in Kerberos pre-auth, no delegation, TGT lifetime 4 hours, no cached
logon verifier (no offline logon), no WDigest/CredSSP plaintext caching.

- Add **human tier-0/tier-1 admins**. Do **not** add service accounts, computer
  accounts, or break-glass accounts (offline logon may be needed in a DR scenario).
- Pilot with one admin for a week; things that break: tools using NTLM (IP-address
  connections, some legacy MMC/RDP-by-IP), anything needing delegation.

## Windows LAPS

- Built into supported Windows 10/11 and Server 2019+ since the April 2023 updates;
  replaces legacy LAPS (`ms-Mcs-AdmPwd`). Backs up to AD or Entra ID.
- AD setup: `Update-LapsADSchema`, `Set-LapsADComputerSelfPermission -Identity "OU=..."`,
  then GPO/Intune policy (backup directory, password age, complexity, post-auth
  actions). Enable **password encryption** (DFL 2016+) and restrict decryptors to a
  tier-appropriate group.
- Verify: `Get-LapsADPassword -Identity PC01 -AsPlainText` (by an authorised reader
  only); event log `Microsoft-Windows-LAPS/Operational`.
- Audit who can read passwords: `Find-LapsADExtendedRights -Identity "OU=..."`.
- Consider Windows LAPS for DSRM password on DCs.

## NTLM, LM and SMB

```powershell
# Current LM compatibility level (target 5 = send NTLMv2 only, refuse LM & NTLM)
Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name LmCompatibilityLevel,NoLMHash -ErrorAction SilentlyContinue
# SMB posture
Get-SmbServerConfiguration | Select EnableSMB1Protocol,RequireSecuritySignature,EncryptData
Get-SmbClientConfiguration | Select RequireSecuritySignature
Set-SmbServerConfiguration -AuditSmb1Access $true   # then watch Microsoft-Windows-SMBServer/Audit event 3000
```

- GPO: *Network security: LAN Manager authentication level* = "Send NTLMv2 response
  only. Refuse LM & NTLM"; *Do not store LAN Manager hash value on next password
  change* = Enabled.
- Find NTLMv1 users before enforcing: Security 4624 field `Package Name (NTLM only)`
  = `NTLM V1`. Enable *Network security: Restrict NTLM: Audit NTLM authentication in
  this domain* and *Audit incoming NTLM traffic*; read
  `Microsoft-Windows-NTLM/Operational` (8001-8004).
- Microsoft has deprecated NTLM and removed NTLMv1 from the newest releases
  (Windows 11 24H2 / Server 2025); check Microsoft Learn's deprecated features list
  for your build. Long term: reduce NTLM, not only v1.
- **SMB signing** defeats NTLM relay to SMB: *Microsoft network server/client:
  Digitally sign communications (always)* = Enabled. Newer Windows releases require
  signing by default; older NAS/scanners may fail. Disable SMBv1 (`Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol`).

```kql
// Defender XDR: NTLMv1 / NTLM logons by source in last 14 days (tune: exclude known appliances)
IdentityLogonEvents
| where Timestamp > ago(14d) and Protocol == "Ntlm"
| summarize Logons=count(), Accounts=dcount(AccountName) by DeviceName, DestinationDeviceName
| order by Logons desc
```

~~~spl
```Splunk: NTLMv1 logons from Windows Security 4624 (index/sourcetype are local)```
index=wineventlog EventCode=4624 Package_Name__NTLM_only_="NTLM V1"
| stats count values(Account_Name) by Workstation_Name, Source_Network_Address
~~~

## LDAP signing and channel binding (DCs)

- *Domain controller: LDAP server signing requirements* = Require signing
  (`HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity` = 2).
- *Domain controller: LDAP server channel binding token requirements*
  (`LdapEnforceChannelBinding`: 1 = when supported, 2 = always). Start at 1.
- Measure first on every DC (Directory Service log):
  - **2887** daily count of unsigned/simple binds; **2889** per-client detail (enable
    with `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics\"16 LDAP Interface Events"` = 2).
  - **3039-3041** channel-binding related events.
- Typical breakers: Linux/Java apps, printers/scanners doing LDAP simple bind on 389,
  old VPN/Wi-Fi appliances. Fix by moving them to LDAPS (636) with SASL/signing.

## Kerberos: AES and RC4 removal

- RC4 tickets enable cheap Kerberoasting cracking. Find RC4 use on DCs: Security
  4769/4768 `Ticket Encryption Type` 0x17 (RC4-HMAC); AES is 0x11/0x12.
- Accounts whose password was last set before the domain gained AES support (DFL
  2008) have no AES keys: reset their password (service accounts in a change window).
- Set `msDS-SupportedEncryptionTypes` on service accounts to AES (0x18 = AES128+AES256).
- GPO *Network security: Configure encryption types allowed for Kerberos*: AES128,
  AES256 (+ Future types). Leave RC4 in place until 4769 shows zero RC4 for 30 days.
- Non-Windows keytabs (Linux, Java, appliances) must be regenerated with AES.

```kql
// Sentinel: RC4 Kerberos service tickets (SecurityEvent from DCs). Tune: exclude known legacy SPNs
SecurityEvent
| where EventID == 4769 and TimeGenerated > ago(30d)
| extend EncType = extract(@'TicketEncryptionType">([^<]+)<', 1, EventData),
         Svc = extract(@'ServiceName">([^<]+)<', 1, EventData)
| where EncType == "0x17"
| summarize Count=count() by Svc, IpAddress
```

## krbtgt rotation

- Routine: rotate on a schedule (many orgs use 180 days) and when a tier-0 admin with
  DC access leaves.
- After suspected Golden Ticket / DC compromise / NTDS.dit theft: reset **twice**,
  waiting at least the maximum TGT lifetime (default 10 h) plus full replication
  between resets. Resetting twice back-to-back invalidates legitimate tickets and
  causes outages; one reset alone leaves the old key valid as the "previous" key.
- Use Microsoft's published `New-KrbtgtKeys.ps1` (simulation mode first) and check
  replication (`repadmin /replsummary`) before and after. RODCs have their own
  `krbtgt_<number>` accounts.
- krbtgt rotation does not evict an attacker who still has DA, a backdoored account,
  or ADCS certificates: do it as part of an eradication plan from `incident-response`.

## ADCS hardening

Reference: SpecterOps "Certified Pre-Owned" (ESC classes). Audit with Locksmith or
PSPKIAudit; Certify `find /vulnerable` is read-only enumeration but is also an attack
tool, so run it only with approval and expect EDR alerts.

| Class | Condition | Fix |
|---|---|---|
| ESC1 | Template: enrollee supplies subject + client-auth EKU + low-priv enroll + no manager approval | Remove "Supply in the request" or restrict enroll rights; require manager approval |
| ESC2/ESC3 | Any-purpose / no EKU, or enrollment agent templates broadly enrollable | Restrict enroll rights, set issuance requirements |
| ESC4 | Low-priv users can write template ACL | Fix template ACLs (only tier-0 PKI admins) |
| ESC6 | CA flag `EDITF_ATTRIBUTESUBJECTALTNAME2` | `certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2`, restart CertSvc |
| ESC7 | Low-priv ManageCA / ManageCertificates | Remove those rights |
| ESC8 | NTLM relay to HTTP web enrollment | Remove web enrollment or require HTTPS + EPA, disable NTLM on that IIS |

- Strong certificate mapping (KB5014754): move DCs to full enforcement
  (`StrongCertificateBindingEnforcement` under `HKLM\SYSTEM\CurrentControlSet\Services\Kdc`)
  after reviewing the KDC weak-mapping events in the System log.
- Enable CA auditing (`certutil -setreg CA\AuditFilter 127`) and the
  *Audit Certification Services* subcategory: 4886/4887/4888 (request / issued /
  denied), 4898/4899/4900 (template changes).
- Treat CA servers and their backups/keys as tier 0; protect CA private keys (HSM
  where possible).

## Endpoint credential protection

- **Credential Guard** (VBS-isolated LSA secrets). On by default on qualifying
  Windows 11 22H2+ Enterprise/Education devices. Check:
  `(Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard).SecurityServicesRunning`
  (1 = Credential Guard, 2 = HVCI). Breaks: NTLMv1, MS-CHAPv2 saved creds
  (PEAP-MSCHAPv2 Wi-Fi/VPN), unconstrained delegation, DES. Not meaningful on DCs.
- **LSA protection (RunAsPPL)**: `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL`
  = 1 (UEFI-locked) or 2 (no UEFI lock, Windows 11 22H2+). Audit first with
  `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe\AuditLevel`
  = 8 and look for CodeIntegrity 3065/3066 (plug-ins/drivers that would fail to load).
  Confirm with System event 12 (Wininit) showing LSASS started as protected.
- Disable WDigest plaintext caching (`UseLogonCredential` = 0 under
  `...\SecurityProviders\WDigest`); default on modern Windows but attackers re-enable it,
  so also alert on changes (`hunt-credential-access`).

## ASR rules

Modes: 0 Off, 1 Block, 2 Audit, 6 Warn. Events: `Microsoft-Windows-Windows Defender/Operational`
1121 (block), 1122 (audit); in Defender XDR, `DeviceEvents | where ActionType startswith "Asr"`.

High-value rules to start in audit (GUIDs from the Microsoft Learn "Attack surface
reduction rules reference"; verify against that page before deploying):

| Rule | GUID |
|---|---|
| Block credential stealing from the Windows local security authority subsystem (lsass.exe) | 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 |
| Block all Office applications from creating child processes | d4f940ab-401b-4efc-aadc-ad5f3c50688a |
| Block executable content from email client and webmail | be9ba2d9-53ea-4cdc-84e5-9b1eeee46550 |
| Block abuse of exploited vulnerable signed drivers | 56a863a9-875e-4185-98a7-b882c64b5ce5 |
| Block persistence through WMI event subscription | e6db77e5-3df2-4cf1-b95a-636979351e5b |
| Block process creations originating from PSExec and WMI commands | d1e49aac-8f56-4280-b9ba-993a6d77406c |

Also by name: *Block Office applications from creating executable content*, *Block
Office applications from injecting code into other processes*, *Block JavaScript or
VBScript from launching downloaded executable content*, *Block execution of
potentially obfuscated scripts*, *Block Win32 API calls from Office macros*, *Use
advanced protection against ransomware*. The PSExec/WMI rule breaks SCCM/ConfigMgr
client operations; check vendor compatibility before blocking.

```powershell
# What is configured locally (IDs and actions are parallel arrays)
$p = Get-MpPreference; 0..($p.AttackSurfaceReductionRules_Ids.Count-1) | % { "{0} -> {1}" -f $p.AttackSurfaceReductionRules_Ids[$_], $p.AttackSurfaceReductionRules_Actions[$_] }
```

## Application control and PowerShell

- **WDAC / App Control for Business** (preferred; also enforces PowerShell CLM) or
  **AppLocker** (needs the Application Identity service). Start with Microsoft's
  recommended block rules and vulnerable driver blocklist, audit mode first.
  Audit events: CodeIntegrity 3076 (would block) / 3077 (blocked); AppLocker 8003
  (EXE/DLL would block), 8004 (blocked), 8006/8007 (script/MSI).
- **PowerShell logging** (GPO *Windows Components > Windows PowerShell*): Script Block
  Logging (4104 in `Microsoft-Windows-PowerShell/Operational`), Module Logging (4103),
  optional transcription to a write-only share. Check SIEM volume first.
- Remove PowerShell 2.0 (bypasses logging):
  `Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root`.
- **Constrained Language Mode** is only reliable when enforced by WDAC/AppLocker; the
  `__PSLockdownPolicy` environment variable is not a security boundary. Check with
  `$ExecutionContext.SessionState.LanguageMode`. Use JEA for delegated admin tasks.

## Local admin cleanup and DC hygiene

- Inventory local Administrators membership fleet-wide (Intune/ConfigMgr/Defender
  `DeviceLogonEvents` with `IsLocalAdmin`); remove domain users and broad groups.
- Enforce membership with GPO Restricted Groups / Group Policy Preferences or Intune
  *Account protection* policy; one LAPS-managed local admin only.
- Block lateral movement with local accounts: *Deny access to this computer from the
  network* and *Deny log on through Remote Desktop Services* for
  `Local account and member of Administrators group` (S-1-5-114); keep
  `LocalAccountTokenFilterPolicy` = 0.
- Domain: set `ms-DS-MachineAccountQuota` = 0, disable Print Spooler on DCs, empty
  *Pre-Windows 2000 Compatible Access* of Anonymous/Everyone, review AdminSDHolder
  ACL, stale accounts (`lastLogonTimestamp` > 90 days), passwords that never expire,
  `DONT_REQ_PREAUTH` (AS-REP roastable) accounts.

```powershell
Get-ADObject -Identity ((Get-ADDomain).DistinguishedName) -Properties ms-DS-MachineAccountQuota | Select ms-DS-MachineAccountQuota
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} | Select SamAccountName
```

## Audit tools

| Tool | Use | Note |
|---|---|---|
| PingCastle | `PingCastle.exe --healthcheck --server <domain>`; HTML report scored by Stale Objects, Privileged Accounts, Trusts, Anomalies | Fix by rule ID; re-run monthly |
| Purple Knight (Semperis) | Indicators of exposure across AD and Entra ID | Free community tool |
| BloodHound CE | Attack paths to tier 0 | Collection is noisy LDAP; tell the SOC first |
| Locksmith / PSPKIAudit | ADCS misconfigurations | Locksmith can also suggest fixes |
| Defender for Identity | Posture assessments in Secure Score | Needs sensors on DCs/ADCS/ADFS/Entra Connect |

## False positives & benign look-alikes

- PingCastle "admin accounts with SPN" may be a gMSA or a disabled account: check
  `Enabled` and `PasswordLastSet` before ranking it.
- NTLM from a host is often a name-resolution issue (connecting by IP, missing SPN,
  CNAME without SPN), not a legacy app; fix the SPN rather than allow NTLMv1.
- RC4 4769 events from accounts with AES keys can come from clients that only
  request RC4 (old Java/Samba); fix the client, not the account.
- ASR audit hits for management agents (ConfigMgr, backup, RMM) are benign; exclude by
  path only after confirming signer and path integrity, never by folder like `C:\Temp`.
- BloodHound shows theoretical paths: confirm an edge (e.g. GenericAll) in the actual
  ACL before reporting it as exploitable.

## Pitfalls

- Enforcing LDAP signing/CBT, SMB signing or NTLM restrictions without reading audit
  events first: outages on printers, scanners, VPN and Linux apps.
- Resetting krbtgt twice in quick succession, or resetting while replication is broken.
- Putting service accounts or computer objects in Protected Users.
- Treating tier 0 as "DCs only" and leaving Entra Connect, ADCS or the backup server
  administered from normal workstations.
- AppLocker/WDAC path rules on user-writable folders; publisher rules are safer.
- Turning on PowerShell transcription to a share users can read (it contains secrets).
- Counting GPO "configured" as "applied": verify with `gpresult /h` or registry on
  sampled hosts.

## Output

- Findings table: control, current state (with evidence), target, impact, break risk,
  owner, change ticket, rollback, due date.
- Phased rollout plan (audit -> pilot -> rings -> enforce) with the event IDs used to
  measure each phase.
- Residual-risk list handed to `detection-engineering` (e.g. "RC4 still needed for
  SPN X until Q3: detect 4769 RC4 from other accounts") and coverage check via
  `logging-coverage` / `/coverage`.
- For attack paths found during an incident, link back to `incident-response`
  eradication steps. Use `/harden` to start a review.

## References

- MITRE ATT&CK: T1558.003 Kerberoasting, T1558.001 Golden Ticket, T1003.001 LSASS
  Memory, T1003.006 DCSync, T1557.001 LLMNR/NBT-NS Poisoning and SMB Relay,
  T1649 Steal or Forge Authentication Certificates, T1078.002 Domain Accounts.
- Microsoft Learn: Enterprise access model; Securing privileged access; Protected
  Users security group; Windows LAPS overview; Attack surface reduction rules
  reference; Configure Credential Guard; Configure added LSA protection; App Control
  for Business; KB5014754 certificate-based authentication changes on DCs.
- SpecterOps: "Certified Pre-Owned: Abusing Active Directory Certificate Services".
- CIS Microsoft Windows Server / Windows 11 Benchmarks; DISA STIGs for Windows and AD.
- ANSSI: Active Directory security recommendations / PingCastle rule documentation.
