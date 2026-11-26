---
name: hunt-ad-identity-attacks
description: Threat hunt for Active Directory and hybrid-identity attacks: Kerberoasting (4769 RC4 0x17, ticket volume), AS-REP roasting (4768 PreAuthType 0), DCSync (4662 with replication GUIDs 1131f6aa-/1131f6ad-/89e95b76- from non-DC accounts), Golden/Silver ticket indicators, DCShadow, AdminSDHolder and ACL abuse (5136), ADCS abuse ESC1-ESC8 (4886/4887, SAN in requests, PKINIT 4768), Shadow Credentials (msDS-KeyCredentialLink), RBCD, GPO abuse, BloodHound for defensive attack-path management, and Entra Connect sync accounts (MSOL_, Sync_). KQL, SPL and Sigma per behaviour. Use when asked to "hunt Kerberoasting", "DCSync", "golden ticket", "ADCS ESC1", "shadow credentials", "T1558.003", "T1003.006", "T1649" or "attack paths to Domain Admin".
---

# Hunt: AD and identity attacks

These attacks abuse the directory itself: ticket requests, replication rights,
ACLs, certificate templates and delegation attributes. Most evidence lives on
domain controllers and CAs, so DC/CA log completeness decides whether a hunt
can conclude anything. Host-level credential theft is in
`hunt-credential-access`; movement with the results is in `hunt-lateral-movement`.

## When to use

- Intel mentions Rubeus, Impacket (GetUserSPNs, GetNPUsers, secretsdump),
  Certipy/Certify, Whisker/pyWhisker, BloodHound/SharpHound, mimikatz `lsadump::dcsync`.
- A tier-0 change nobody owns (ACL on the domain root, new SPN, template edit).
- After any domain compromise: is there persistence in AD (AdminSDHolder,
  shadow credentials, rogue certificates, krbtgt-forged tickets)?
- Quarterly attack-path review of tier 0.

## Ground rules

1. **All DCs or no conclusion.** Ticket and replication hunts need logs from
   every DC (and every CA for ADCS) for the whole window. List DCs from AD
   and compare against log sources before trusting a zero.
2. **Directory changes are proven from the directory.** A 5136 lead is
   confirmed by reading the current object (ACL, attribute, metadata via
   `repadmin /showobjmeta`) and identifying the writer; event text alone is
   not enough for a tier-0 verdict.
3. **No tier-0 remediation from a hunt.** krbtgt double-reset, certificate
   revocation, ACL rollback and account disables are `incident-response`
   actions with incident-commander approval; done early they alert the actor
   and can break authentication estate-wide.
4. **BloodHound collection is authorised work.** Run collectors only with
   written approval and treat the output as tier-0 sensitive data.

## Workflow

1. Hypothesis and scope via `hunt-dispatch`; scope = all DCs, CAs, Entra Connect.
2. Data check: DC advanced audit policy (Kerberos Service Ticket Operations,
   Kerberos Authentication Service, Directory Service Access + SACL, Directory
   Service Changes), CA auditing, MDI if present.
3. Ticket abuse: Kerberoasting, AS-REP roasting, forged ticket heuristics.
4. Replication abuse: DCSync, DCShadow.
5. Object abuse: 5136 sweep for the attribute list below; ADCS requests.
6. Attack-path view: BloodHound, then check whether found paths were used.
7. Conclude, report, convert detections; structural fixes to `hardening-windows-ad`.

## ATT&CK sub-technique map

| Behaviour | ATT&CK | Primary evidence |
|---|---|---|
| Kerberoasting | T1558.003 | 4769 RC4, many SPNs per requester |
| AS-REP roasting | T1558.004 | 4768 PreAuthType 0 |
| DCSync | T1003.006 | 4662 replication GUIDs by non-DC; DRSUAPI from non-DC IP |
| Golden ticket / Silver ticket | T1558.001 / T1558.002 | 4769 without 4768; service logons without 4769 |
| DCShadow | T1207 | 5136/5137 nTDSDSA and DRS SPNs on a non-DC |
| ACL / AdminSDHolder / group changes | T1098, T1222.001 | 5136 nTSecurityDescriptor, 4728/4732/4756 |
| GPO abuse | T1484.001 | 5136 on groupPolicyContainer, SYSVOL writes |
| ADCS abuse (ESC1-ESC8) | T1649 | 4886/4887/4899/4900, 4768 with certificate fields |
| Shadow Credentials / RBCD | T1098 / T1556 (no dedicated sub-technique; mapping varies) | 5136 msDS-KeyCredentialLink / msDS-AllowedToActOnBehalfOfOtherIdentity |
| AD reconnaissance (BloodHound) | T1087.002, T1069.002, T1482 | LDAP query volume, SAMR, 1644, MDI |

## Data sources required

| Source | Needed for | Enable / check |
|---|---|---|
| DC Security 4768, 4769, 4771 | Ticket attacks | Audit Kerberos Authentication Service / Service Ticket Operations (Success+Failure) |
| DC Security 4662 | DCSync | Audit Directory Service Access + SACL on the domain root for replication rights |
| DC Security 5136, 5137, 5141 | Object changes | Audit Directory Service Changes + SACLs (domain root, AdminSDHolder, CN=Configuration, templates) |
| DC Security 4741, 4742, 4738, 4728/4732/4756 | Accounts/groups | Audit Computer/User/Security Group Management |
| CA Security 4886, 4887, 4888, 4898-4900 | ADCS | Audit Certification Services + CA audit filter enabled (`certutil -setreg CA\AuditFilter 127`) |
| DC System log, source Kerberos-Key-Distribution-Center | Weak certificate mapping (KB5014754) | Events 39/40/41 (verify on your DC build) |
| MDI (IdentityDirectoryEvents, IdentityLogonEvents, IdentityQueryEvents) | Replication, recon, ticket anomalies | If licensed |
| Network (Zeek dce_rpc / kerberos) | DRSUAPI from non-DC, RC4 tickets | East-west sensors near DCs |

Field names below follow the Security event XML (`TargetUserName`,
`ServiceName`, `TicketEncryptionType`, `Properties`, `AttributeLDAPDisplayName`).
For Sentinel `SecurityEvent`, values are pulled from `EventData` to avoid
relying on parsed columns.

## Behaviours and queries

### 1. Kerberoasting

```kql
// Sentinel: RC4 service tickets for user-account SPNs, stacked by requester. Tune: legacy apps that really need RC4.
SecurityEvent
| where TimeGenerated > ago(30d) and EventID == 4769
| extend Svc = extract(@"<Data Name=""ServiceName"">([^<]+)<", 1, EventData),
         Enc = extract(@"<Data Name=""TicketEncryptionType"">([^<]+)<", 1, EventData),
         Req = extract(@"<Data Name=""TargetUserName"">([^<]+)<", 1, EventData),
         Status = extract(@"<Data Name=""Status"">([^<]+)<", 1, EventData)
| where Enc == "0x17" and Status == "0x0" and not(Svc endswith "$") and Svc !~ "krbtgt"
| summarize SPNs = dcount(Svc), Services = make_set(Svc, 25), First = min(TimeGenerated) by Req, IpAddress, bin(TimeGenerated, 1h)
| where SPNs >= 3        // single RC4 requests for a legacy app are normal; volume across SPNs is the signal
| order by SPNs desc
```

```spl
index=wineventlog source="XmlWinEventLog:Security" EventCode=4769 TicketEncryptionType=0x17 Status=0x0 NOT ServiceName="*$" NOT ServiceName=krbtgt
| bin _time span=1h
| stats dc(ServiceName) as spns values(ServiceName) as services by TargetUserName IpAddress _time
| where spns>=3
```

```yaml
title: Kerberos Service Ticket Requested With RC4 For User SPN
status: experimental
logsource: {product: windows, service: security}
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17'
    Status: '0x0'
  filter_machine:
    ServiceName|endswith: '$'
  filter_krbtgt:
    ServiceName: 'krbtgt'
  condition: selection and not 1 of filter_*
falsepositives: [Legacy applications and service accounts without AES keys - inventory them and allowlist by ServiceName]
level: medium
tags: [attack.credential_access, attack.t1558.003]
```

AES-only roasting (`0x12`) evades the RC4 signal; keep the volume stack
(many SPNs per requester per hour) without the encryption filter as a second
pass. Honeypot SPN accounts (never used legitimately) make any 4769 for them a
high-fidelity alert.

### 2. AS-REP roasting

```kql
// Sentinel: TGTs issued without pre-authentication, and accounts recently set to DONT_REQ_PREAUTH (UAC 0x400000).
SecurityEvent
| where TimeGenerated > ago(30d)
| where (EventID == 4768 and EventData has @"<Data Name=""PreAuthType"">0<" and EventData has @"<Data Name=""Status"">0x0<")
     or (EventID == 4738 and EventData has "'Don't Require Preauth' - Enabled")   // rendered text; raw XML may carry a %% code - verify
| extend Account = extract(@"<Data Name=""TargetUserName"">([^<]+)<", 1, EventData)
| summarize Count = count(), Sources = make_set(IpAddress, 10) by EventID, Account
```

```spl
index=wineventlog source="XmlWinEventLog:Security" EventCode=4768 PreAuthType=0 Status=0x0
| stats count values(IpAddress) as sources values(TicketEncryptionType) as enc by TargetUserName
```

```yaml
title: Kerberos TGT Issued Without Pre-Authentication
status: experimental
logsource: {product: windows, service: security}
detection:
  selection:
    EventID: 4768
    PreAuthType: '0'
    Status: '0x0'
  condition: selection
falsepositives: [Legacy/Unix integrations that genuinely need pre-auth disabled - should be an explicit, short list]
level: medium
tags: [attack.credential_access, attack.t1558.004]
```

Inventory: `Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true'`. Every
account on that list should have an owner and a reason.

### 3. DCSync

```kql
// Sentinel: replication extended rights exercised by a non-DC account. DC machine accounts and the sync account are expected; list them.
let ReplGuids = dynamic(["1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2", "89e95b76-444d-4c62-991a-0facbeda640c"]);
let ExpectedRepl = dynamic(["MSOL_0123456789ab"]);   // replace with your Entra Connect / sanctioned replication accounts
SecurityEvent
| where TimeGenerated > ago(90d) and EventID == 4662 and EventData has_any (ReplGuids) and EventData has "0x100"
| extend Subject = extract(@"<Data Name=""SubjectUserName"">([^<]+)<", 1, EventData)
| where not(Subject endswith "$") and Subject !in~ (ExpectedRepl)
| summarize Count = count(), DCs = make_set(Computer), First = min(TimeGenerated) by Subject
```

```spl
index=wineventlog source="XmlWinEventLog:Security" EventCode=4662 AccessMask=0x100
  (Properties="*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*" OR Properties="*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*" OR Properties="*89e95b76-444d-4c62-991a-0facbeda640c*")
  NOT SubjectUserName="*$"
| stats count values(host) as dcs min(_time) as first by SubjectUserName SubjectDomainName
```

```yaml
title: Directory Replication Rights Used By Non-Machine Account (DCSync)
status: experimental
logsource: {product: windows, service: security}
detection:
  selection:
    EventID: 4662
    AccessMask: '0x100'
    Properties|contains: ['1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2', '89e95b76-444d-4c62-991a-0facbeda640c']
  filter_dc:
    SubjectUserName|endswith: '$'
  condition: selection and not filter_dc
falsepositives: [Entra Connect AD DS connector account (MSOL_*), sanctioned identity-sync or AD audit tools]
level: high
tags: [attack.credential_access, attack.t1003.006]
```

Machine-account DCSync is also possible (a compromised DC or a computer
granted rights): verify the source IP of replication traffic is a DC (MDI
"Directory Services replication" activity in `IdentityDirectoryEvents`, or
Zeek `dce_rpc` operation `DRSGetNCChanges` from a non-DC IP). Also audit who
*holds* these rights: `(Get-Acl "AD:DC=corp,DC=example").Access` filtered on
the three GUIDs.

### 4. Directory object abuse (5136 sweep)

| Attribute / object | Attack | Expected writers |
|---|---|---|
| `nTSecurityDescriptor` on domain root, `CN=AdminSDHolder,CN=System,...`, tier-0 objects | ACL abuse / AdminSDHolder persistence (SDProp re-applies the AdminSDHolder ACL to protected objects about every 60 min) | Change-managed admin work only |
| `msDS-KeyCredentialLink` | Shadow Credentials | Windows Hello for Business provisioning, device registration, Entra Connect writeback |
| `msDS-AllowedToActOnBehalfOfOtherIdentity` | RBCD | Rare; specific delegation designs |
| `servicePrincipalName` on users | Targeted Kerberoasting (set SPN, roast, remove) | App onboarding |
| `servicePrincipalName` starting `GC/` or `E3514235-4B06-11D1-AB04-00C04FC2DCD2` on a non-DC computer | DCShadow | DC promotion only |
| `nTDSDSA` objects created/deleted under `CN=Sites,CN=Configuration` (5137/5141) | DCShadow | DC promotion/demotion |
| `groupPolicyContainer` (`gPCMachineExtensionNames`, `versionNumber`, `gPCFileSysPath`) | GPO abuse | GPO admins via GPMC |
| `msPKI-Certificate-Name-Flag`, `pKIExtendedKeyUsage`, template ACLs | ADCS ESC4 | PKI admins |
| `userAccountControl` (DONT_REQ_PREAUTH, TRUSTED_TO_AUTH_FOR_DELEGATION) | Roasting / delegation abuse | Rare |

```kql
// Sentinel: 5136 changes to high-risk attributes and objects; review every row with the writer's owner.
let RiskyAttrs = dynamic(["nTSecurityDescriptor", "msDS-KeyCredentialLink", "msDS-AllowedToActOnBehalfOfOtherIdentity", "servicePrincipalName",
  "gPCMachineExtensionNames", "gPCUserExtensionNames", "gPCFileSysPath", "msPKI-Certificate-Name-Flag", "pKIExtendedKeyUsage", "userAccountControl"]);
SecurityEvent
| where TimeGenerated > ago(90d) and EventID in (5136, 5137, 5141)
| extend Attr = extract(@"<Data Name=""AttributeLDAPDisplayName"">([^<]+)<", 1, EventData),
         ObjDN = extract(@"<Data Name=""ObjectDN"">([^<]+)<", 1, EventData),
         Value = extract(@"<Data Name=""AttributeValue"">([^<]*)<", 1, EventData),
         Writer = extract(@"<Data Name=""SubjectUserName"">([^<]+)<", 1, EventData)
| where Attr in (RiskyAttrs) or ObjDN has "CN=AdminSDHolder" or (EventID != 5136 and ObjDN has "CN=NTDS Settings")
| project TimeGenerated, Computer, EventID, Writer, ObjDN, Attr, Value
```

```spl
index=wineventlog source="XmlWinEventLog:Security" EventCode=5136
  AttributeLDAPDisplayName IN ("nTSecurityDescriptor","msDS-KeyCredentialLink","msDS-AllowedToActOnBehalfOfOtherIdentity","servicePrincipalName","gPCMachineExtensionNames","msPKI-Certificate-Name-Flag")
| stats count values(ObjectDN) as objects values(AttributeValue) as values by SubjectUserName AttributeLDAPDisplayName
```

```yaml
title: Shadow Credentials Or RBCD Attribute Written
status: experimental
logsource: {product: windows, service: security}
detection:
  selection:
    EventID: 5136
    AttributeLDAPDisplayName: ['msDS-KeyCredentialLink', 'msDS-AllowedToActOnBehalfOfOtherIdentity']
  filter_whfb:
    SubjectUserName|startswith: 'MSOL_'
  condition: selection and not filter_whfb
falsepositives: [Windows Hello for Business key provisioning, device registration and the Entra Connect account - verify your own writer list]
level: high
tags: [attack.persistence, attack.privilege_escalation, attack.t1098, attack.t1556]
```

Follow-ups: Shadow Credentials are used via PKINIT - look for 4768 with
`PreAuthType 16` and certificate fields for the same account shortly after
the write. RBCD often follows creation of a computer account by a normal user
(4741; default `ms-DS-MachineAccountQuota` is 10) and leads to S4U 4769 events
with a `TransmittedServices` value. GPO abuse continues on disk: 5145 writes
under `\SYSVOL\<domain>\Policies\{GUID}\` (e.g. `ScheduledTasks.xml`,
`Scripts\`), then `hunt-windows-persistence` on the targeted hosts.

### 5. ADCS abuse (ESC1-ESC8)

| ESC | Misconfiguration | What to hunt |
|---|---|---|
| ESC1 | Template lets enrollee supply subject/SAN + client-auth EKU + low-priv enroll | Requests where subject/SAN identity != requester (CA database) |
| ESC2 / ESC3 | Any Purpose or no EKU / Certificate Request Agent templates | Enrollment-agent requests on behalf of privileged users |
| ESC4 | Writable template ACL | 4899/4900 template changes, 5136 on template objects |
| ESC5 | Writable PKI objects (CA computer, NTAuthCertificates, containers) | 5136 under `CN=Public Key Services,CN=Services,CN=Configuration` |
| ESC6 | `EDITF_ATTRIBUTESUBJECTALTNAME2` on the CA | 4886/4887 `Attributes` containing `SAN:` |
| ESC7 | ManageCA / ManageCertificates granted to low-priv | 4882/4890 CA security/settings changes, denied-then-issued requests |
| ESC8 | NTLM relay to web enrollment (`/certsrv`) | IIS logs on CA, NTLM auth from DC machine accounts to the CA |

```kql
// Sentinel: CA requests with SAN attributes (ESC6) and certificates issued for privileged-looking subjects to other requesters (ESC1 lead).
SecurityEvent
| where TimeGenerated > ago(90d) and EventID in (4886, 4887)
| extend Requester = extract(@"<Data Name=""Requester"">([^<]+)<", 1, EventData),
         Attributes = extract(@"<Data Name=""Attributes"">([^<]*)<", 1, EventData),
         Subject = extract(@"<Data Name=""Subject"">([^<]*)<", 1, EventData)
| where Attributes has "SAN:" or Subject has_any ("admin", "CN=Administrator", "krbtgt")   // tune to your privileged naming
| project TimeGenerated, Computer, EventID, Requester, Subject, Attributes
```

```spl
index=wineventlog source="XmlWinEventLog:Security" EventCode IN (4886,4887) (Attributes="*SAN:*" OR Attributes="*upn=*")
| table _time host EventCode RequestId Requester Subject Attributes
```

```yaml
title: Certificate Request With Subject Alternative Name In Request Attributes
status: experimental
logsource: {product: windows, service: security}
detection:
  selection:
    EventID: [4886, 4887]
    Attributes|contains: ['SAN:', 'upn=', 'dns=']
  condition: selection
falsepositives: [Templates and workflows that legitimately pass SAN as an attribute - rare when EDITF_ATTRIBUTESUBJECTALTNAME2 is off]
level: high
tags: [attack.credential_access, attack.privilege_escalation, attack.t1649]
```

SAN supplied inside the CSR (ESC1) is not shown in 4887 attributes: compare
requester vs. issued identity in the CA database (`certutil -view -restrict
"Disposition=20" -out "RequestID,RequesterName,CommonName,CertificateTemplate"`)
and on DCs correlate 4768 with populated `CertIssuerName`/`CertSerialNumber`
fields where the account rarely uses certificates. Inventory with
Certify/Certipy `find` (authorised) or PKI health tools.

### 6. Forged tickets (Golden / Silver) and Diamond/Sapphire variants

Heuristics, each weak alone: TGS requests (4769) for an account/IP with no
TGT (4768) issued by any DC in the prior 10 hours; 4769/4624 for account names
that do not exist or whose SID does not match; RC4 TGT usage where AES is
standard; service logons (4624 Kerberos) on a server with no matching 4769 on
any DC (Silver). Diamond/Sapphire tickets modify real tickets and defeat most
of these; MDI and PAC validation help. krbtgt password age is the
control: if older than the compromise, assume forged tickets remain possible.

```kql
// Sentinel: service tickets from an IP that received no TGT for that account in the prior 10h. Needs all DCs; expensive - scope it.
let TGT = SecurityEvent | where TimeGenerated > ago(8d) and EventID == 4768
| extend Acct = tolower(extract(@"<Data Name=""TargetUserName"">([^<@]+)", 1, EventData)) | project TgtTime = TimeGenerated, Acct, IpAddress;
SecurityEvent
| where TimeGenerated > ago(7d) and EventID == 4769
| extend Acct = tolower(extract(@"<Data Name=""TargetUserName"">([^<@]+)", 1, EventData))
| where not(Acct endswith "$")
| join kind=leftouter TGT on Acct, IpAddress
| summarize LastTgt = maxif(TgtTime, TgtTime between ((TimeGenerated - 10h) .. TimeGenerated)) by Acct, IpAddress, TgsTime = bin(TimeGenerated, 1h)
| where isnull(LastTgt)
```

### 7. Entra Connect sync accounts

On-prem, the AD DS connector account (`MSOL_<id>` with express settings) holds
replication rights: it is the expected DCSync look-alike, and also a
tier-0 target. Hunt its use from any host other than the Entra Connect server
(4624/4662 with a different source IP). In the cloud, the sync identity
(`Sync_<server>_<id>@<tenant>.onmicrosoft.com`, Directory Synchronization
Accounts role; newer Connect versions may use an application identity -
verify for your version) should sign in only from the Connect server's egress
IP; any interactive sign-in, new IP or use outside sync APIs is a lead. Treat
the Connect server itself as tier 0 (hand to `hardening-windows-ad`).

```kql
// Sentinel: sign-ins by the directory sync account from unexpected IPs. Replace the IP list.
SigninLogs
| union AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(30d) and UserPrincipalName startswith "Sync_"
| where IPAddress !in ("203.0.113.10")      // your Entra Connect egress IP(s)
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, ResultType, UserAgent
```

## BloodHound for defenders (attack-path management)

- Collect (approved) with SharpHound/BloodHound CE for AD and AzureHound for
  Entra; snapshot monthly; diff paths to Domain Admins, Enterprise Admins,
  DCs, ADCS CAs and Entra Connect.
- Fix choke points first (one ACL or group that many paths cross), not
  individual users. Track "users with a path to tier 0" as a metric.
- Turn each path edge into a hunt: GenericAll/WriteDacl edges -> 5136 sweeps;
  HasSession edges -> `hunt-lateral-movement`; ADCS edges -> section 5.
- Detect hostile collection: bursty LDAP queries from a workstation (MDI
  `IdentityQueryEvents`, DC Directory Service 1644 with expensive-search
  logging enabled), SAMR/NetSessionEnum sweeps to many hosts.

## Baselining and stacking

- 4769: stack per requester the count of distinct SPNs per hour and the
  encryption-type mix; baseline per service account.
- 4662/5136: list writers per attribute over 90 days; new writers are leads.
- 4887: stack templates x requesters; a user enrolling in a template they never
  used, especially with client-auth EKU, is a lead.

## False positives & benign look-alikes

| Look-alike | Resembles | How to tell |
|---|---|---|
| Entra Connect `MSOL_` account | DCSync | Source IP = Connect server, expected account |
| Legacy apps with RC4 | Kerberoasting | Same SPN, same clients, steady volume |
| Vulnerability/AD audit tools (PingCastle, Purple Knight) | Recon, roasting, replication checks | Scheduled, owned, known host |
| WHfB / device registration | Shadow Credentials | Writer is the device/sync/enrollment identity, key source metadata |
| DC promotion | DCShadow artefacts | Change record, server remains a DC |
| GPO admins in GPMC | GPO abuse | Change record; edits match intended settings |

## Pitfalls

- Missing one DC breaks "4769 without 4768" logic and DCSync coverage.
- 4662 without a SACL on the domain root logs nothing; test with a positive
  control in a lab (`purple-team-validation`).
- Treating `0x12` (AES) as safe: AES roasting exists, only slower to crack.
- Reading 5136 without the before-value: operations come as delete + add pairs
  (`%%14675` / `%%14674`); pair them by `OpCorrelationID`.
- Forgetting the CA: ADCS persistence (stolen CA key, rogue templates)
  survives password resets and krbtgt rotation.

## Escalation criteria

- DCSync by any account not on the expected list; any DCShadow artefact.
- Unowned change to AdminSDHolder, domain-root ACL, `msDS-KeyCredentialLink`
  on a privileged account, RBCD on a tier-0 computer, or GPO linked to DCs.
- Kerberoasting burst followed by a logon of a roasted service account from a
  new host; any ticket for a honeypot SPN.
- Certificate issued with a SAN or subject for a privileged identity to a
  different requester; 4768 PKINIT for an account that has never used it.

| Verdict | Evidence that moves it |
|---|---|
| True Positive | Unowned tier-0 change or rights use + follow-on use (logon, ticket, cert) |
| Benign True Positive | Change record, expected writer/tool, documented owner |
| False Positive | Mis-parsed GUIDs/attributes, expected sync identity |
| Needs more data | Missing DC/CA logs, no SACL, need `repadmin /showobjmeta` or CA DB |

## Output

```markdown
## Hunt report - AD & identity attacks - <HUNT-ID>
- Hypothesis / status: <supported | refuted | inconclusive>
- Coverage: DCs <n/total>, CAs <n/total>, SACLs verified <yes/no>, MDI <yes/no>
- Behaviours covered: <Kerberoast, AS-REP, DCSync, DCShadow, ACL, GPO, ADCS ESCn, shadow creds, RBCD, forged tickets, sync accounts>
- Findings: | Time (UTC) | DC/CA | Actor account | Object/SPN/template | Behaviour | Evidence | Verdict |
- Attack paths: <n> users with path to tier 0 (was <n>); choke points: <list>
- Detections proposed: <titles>; hardening items: <RC4 removal, preauth, ESC fixes, MAQ=0, tiering>
```

Hand-offs: confirmed domain compromise to `incident-response` (krbtgt/CA
actions are IC-approved), credential use to `hunt-lateral-movement`, Entra side
to `ir-azure-entra` and `hardening-m365-entra`, structural fixes to
`hardening-windows-ad`, detections to `detection-engineering`, lab validation
to `purple-team-validation`.

## References

- MITRE ATT&CK: T1558.001-.004, T1003.006, T1207, T1484.001, T1649, T1098:
  https://attack.mitre.org/techniques/T1558/
- Microsoft Learn: 4662, 4768, 4769, 5136 event documentation; Control Access Rights (DS-Replication-Get-Changes*).
- SpecterOps, "Certified Pre-Owned: Abusing Active Directory Certificate Services" (Schroeder, Christensen) - ESC1-ESC8.
- Microsoft KB5014754: Certificate-based authentication changes on Windows domain controllers.
- Microsoft Learn: Microsoft Entra Connect accounts and permissions.
- BloodHound Community Edition documentation (SpecterOps); ANSSI AD security checks.
