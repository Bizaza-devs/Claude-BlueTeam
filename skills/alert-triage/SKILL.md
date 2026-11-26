---
name: alert-triage
description: SOC tier-1/tier-2 alert triage with a fast 7-question gate that ends in one verdict - True Positive, Benign True Positive, False Positive, Needs-data or Escalate. Includes enrichment checklists per entity (user, host, IP, domain, hash, process), common EDR/SIEM alert families (LSASS access T1003.001, encoded PowerShell T1059.001, Office child process, impossible travel, password spray T1110.003, PsExec/service install 7045, RMM tools, beaconing) with their typical false positives, Microsoft Defender XDR / Sentinel KQL and Splunk SPL enrichment snippets (DeviceProcessEvents, SigninLogs, EventCode 4624/4625/4688), and a ticket note template. Use when a defender says "triage this alert", "is this a true positive", "close or escalate", "enrich this IP/hash/user", or runs /triage.
---

# Alert triage

Fast, consistent verdicts on single alerts. Goal: a defensible decision in
minutes for most alerts, and a clean hand-off for the rest.

## When to use

- Any new alert from EDR, SIEM, identity protection, email security, cloud
  security tooling or a user report routed to the SOC.
- Re-triage of an alert that was closed and has re-fired.
- Building a triage runbook for a specific detection rule.

For reported emails use `phishing-analysis`; for anything that passes the gate
as a confirmed incident, hand off to `incident-response`.

## Ground rules

1. **No TP verdict on a single alert without a corroborating second source**
   (a second log source, the raw event, a host artifact or the user/owner
   confirming). The alert itself does not count as its own corroboration.
2. **No FP verdict without naming the benign cause and the evidence for it.**
   "Looks normal" is not a reason. If you cannot name it, the verdict is
   Needs-data.
3. **"Authorised" must be verified out-of-band** (change ticket, scanner
   inventory, owner confirmation via a known channel), never on the word of the
   account that triggered the alert.
4. **Triage does not contain.** Tier-1 may request isolation per local policy;
   destructive actions go through `incident-response` / `/contain` with approval.
5. **Timebox.** Tier-1: ~15-30 min per alert, then escalate as Needs-data or
   Escalate with what you have. Adjust to your SLAs.

## Workflow

1. Open the raw event(s) behind the alert. Rewrite what happened in one
   sentence in your own words (anchoring guard, see `defender-mindset`).
2. Run the 7-question gate.
3. Enrich every entity in the alert with the checklist below; record queries.
4. Assign verdict with the decision table, write the ticket note.
5. If TP or Escalate: set provisional severity (`blueteam-methodology`), hand
   off. If FP/BTP: propose a tuning change to `detection-engineering` with
   the exact exclusion and its risk.

## The 7-question gate

| # | Question | If "no / unknown" |
|---|---|---|
| 1 | Is the alert real? Can I see the raw event, and is it not a parsing, clock or duplicate artifact? | FP (tooling) or Needs-data |
| 2 | What exactly happened: who, what, on which asset, when (UTC), from where? | Needs-data |
| 3 | Is it explained by verified authorised activity (change, admin task, scanner, red team, known software)? | Continue; if yes -> Benign TP or FP |
| 4 | Is there a corroborating second source for the malicious reading? | Needs-data (not TP yet) |
| 5 | Did it succeed (executed vs blocked, auth success vs failure, mail delivered vs quarantined)? | Blocked + no follow-on -> often TP-low, close with note |
| 6 | What is the blast radius: asset tier, account privilege, number of entities sharing the indicator? | Tier-0 or privileged -> Escalate regardless |
| 7 | Is it ongoing or time-critical (active session, fraud, encryption, exfil)? | Ongoing -> Escalate now, enrich in parallel |

### Verdict decision table

| Verdict | Definition | Evidence that moves you here |
|---|---|---|
| True Positive (TP) | Malicious or unauthorised activity occurred | Q4 corroborated, Q3 ruled out, behaviour matches a technique with no benign explanation |
| Benign True Positive (BTP) | Detection logic worked; activity is real but authorised/expected | Q3 verified (ticket, owner, scanner inventory), activity matches the authorisation in scope and time |
| False Positive (FP) | Detection fired on something that does not match its intent | Logic or data error, misparsed field, rule too broad; benign cause named |
| Needs-data | Cannot decide within the timebox | Missing telemetry, owner unreachable, sandbox pending; list exactly what is missing |
| Escalate | Likely TP with significant impact, or beyond tier authority | Q6 tier-0/privileged, Q7 ongoing, multiple entities, ransomware/BEC/fraud indicators |

## Enrichment checklist per entity

### User / account
- Identity: department, manager, role, privileged group membership (Domain
  Admins, Global Administrator, cloud admin roles), service vs human account.
- Recent auth: sign-in locations/ASNs/devices in last 30 days, MFA method
  changes, password resets, risky-user state (Entra ID Protection).
- Recent changes to the account: group adds (4728/4732/4756), role
  assignments, new app consents, mailbox rules (`ir-bec-m365`).
- HR status: leaver, on notice, on leave, travelling (via the agreed channel).

### Host
- Owner, asset tier, OS, business function, internet-facing or not.
- EDR health: sensor active during the window? Isolation state?
- Process tree around the alert time (+/- 30 min), new services (7045),
  scheduled tasks (4698), logons (4624 types 3/10), network connections.
- Other alerts on the host in the last 30 days.

### IP address
- Internal: which host held it at that time (DHCP/VPN logs; IPs move).
- External: ASN/owner, hosting vs residential vs mobile vs VPN/anonymiser,
  geolocation (low confidence), reputation (TI platform), first-seen in your
  logs, how many of your users/hosts talked to it.

### Domain / URL
- Registration age (WHOIS/RDAP), registrar, DNS history, certificate
  transparency first-seen, categorisation, lookalike of your brand.
- Who in the org resolved/visited it (proxy, DNS, `DeviceNetworkEvents`).
- Always defang in notes: `hxxps://login-portal[.]example`.

### File hash
- Prevalence in your estate (count of devices), first-seen in your estate.
- Signer and signature validity, file name/path, global prevalence.
- Reputation lookups by hash only (do not upload customer files to public
  sandboxes without approval; see `malware-triage`).

### Process
- Image path vs expected path (e.g. `svchost.exe` outside `System32`).
- Parent and grandparent, command line, integrity level, user.
- Children, network connections, files written, registry changes.
- Is the binary a LOLBin being used unusually (`hunt-lolbins`)?

## Enrichment queries

### KQL (Microsoft Defender XDR advanced hunting)

```kql
// Process context on a host +/- 30 min around the alert. Tune: host name, time.
let t = datetime(2026-03-02T09:15:00Z);
DeviceProcessEvents
| where DeviceName startswith "ws-114"
| where Timestamp between ((t - 30m) .. (t + 30m))
| project Timestamp, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine,
          FileName, ProcessCommandLine, SHA256, ProcessIntegrityLevel
| order by Timestamp asc
```

```kql
// Hash prevalence and first-seen in the estate, plus global profile.
// FileProfile() enriches with GlobalPrevalence, Signer, IsCertificateValid.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where SHA256 == "<sha256>"
| summarize Devices = dcount(DeviceId), FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            Paths = make_set(FolderPath, 10) by SHA256
| invoke FileProfile(SHA256, 100)
| project SHA256, Devices, FirstSeen, LastSeen, Paths, GlobalPrevalence, Signer, IsCertificateValid
```

```kql
// Which devices talked to an external IP or domain in 7 days. Tune: indicator.
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIP == "203.0.113.10" or RemoteUrl has "login-portal.example"
| summarize Connections = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            Processes = make_set(InitiatingProcessFileName, 10) by DeviceName
```

### KQL (Microsoft Sentinel)

```kql
// 30-day sign-in baseline for a user: IPs, countries, apps, result codes.
// ResultType 0 = success; other values are Entra error codes.
SigninLogs
| where TimeGenerated > ago(30d)
| where UserPrincipalName =~ "j.doe@corp.example"
| summarize Count = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    by IPAddress, Country = tostring(LocationDetails.countryOrRegion), AppDisplayName,
       ResultType, ClientAppUsed
| order by LastSeen desc
```

```kql
// Password spray shape: one IP, many users, failures. Tune threshold per tenant size.
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType in ("50126", "50053")   // invalid credentials, account locked
| summarize Users = dcount(UserPrincipalName), Attempts = count() by IPAddress, bin(TimeGenerated, 1h)
| where Users > 10
```

### SPL (Splunk)

~~~spl
```Windows logons for a user, by source and logon type. Tune: index, sourcetype, field names (TA-dependent).```
index=wineventlog EventCode IN (4624, 4625) user="jdoe" earliest=-7d
| stats count min(_time) as first max(_time) as last by EventCode, Logon_Type, src, dest
| convert ctime(first) ctime(last)
~~~

~~~spl
```Process creation context on a host (Sysmon EID 1). Tune: index, host, time.```
index=sysmon EventCode=1 host="WS-114" earliest="03/02/2026:09:00:00" latest="03/02/2026:09:45:00"
| table _time, User, ParentImage, ParentCommandLine, Image, CommandLine, Hashes
| sort _time
~~~

~~~spl
```CIM-based: authentication by user across all sources (requires accelerated Authentication data model).```
| tstats count from datamodel=Authentication
    where Authentication.user="jdoe" by Authentication.src, Authentication.dest, Authentication.action, _time span=1h
~~~

~~~spl
```Who visited a domain (proxy). Tune: index, sourcetype, url field per your proxy TA.```
index=proxy url="*login-portal.example*" earliest=-7d
| stats count min(_time) as first by user, src, url, action
~~~

## Common alert families

| Alert family | ATT&CK | First checks | Typical false positives / benign look-alikes |
|---|---|---|---|
| LSASS memory access / dump | T1003.001 | Accessing process, GrantedAccess mask (Sysmon 10), dump file written, `comsvcs.dll MiniDump`, `procdump -ma lsass` | AV/EDR, backup agents, WerFault crash dumps, admin troubleshooting with ProcDump (verify ticket) |
| Encoded / obfuscated PowerShell | T1059.001, T1027 | Decode `-enc` base64 (UTF-16LE), parent process, network after, 4104 script block | SCCM/Intune, monitoring agents, vendor installers, admin scripts |
| Office app spawns shell/LOLBin | T1566.001, T1204.002 | Document origin (email, download, MOTW), child command line, network | Add-ins, legitimate macros in finance workbooks, document management integrations |
| New service install / PsExec | T1569.002, T1021.002 | 7045 service name/path, source host, account, `PSEXESVC`, admin share access 5145 | IT admin deployment, software distribution, vendor support |
| Scheduled task created | T1053.005 | 4698 task XML, action path, author, user writable path | Updaters (browsers, Adobe, OEM tools), GPO deployments |
| RMM / remote access tool | T1219 | Is the tool sanctioned? Installer origin, who initiated, session logs | Sanctioned IT/helpdesk tooling, vendor support sessions |
| Impossible travel / atypical location | T1078 | ASN type, device ID, user agent, MFA detail, session continuity | Corporate VPN/SASE egress, mobile carrier NAT, travel, cloud proxies |
| Password spray / brute force | T1110.003 / T1110.001 | Source IPs, number of users, any success afterwards | Service with stale password, misconfigured app, user with old phone mail client |
| MFA fatigue / repeated prompts | T1621 | Number of prompts, then approval, sign-in after | User re-trying a broken app, sync issues |
| Beaconing / C2 | T1071 | Interval regularity, destination age/reputation, process | Update checks, telemetry, NTP, EDR cloud, chat apps (see `hunt-c2-beaconing`) |
| Mass file download / exfil | T1567, T1048 | Volume vs baseline, destination, user HR status | Backups, sync clients, legitimate migrations |
| Suspicious inbox rule | T1564.008 | Rule conditions (keywords like invoice, payment), forward/delete actions | User's own organisation rules (see `ir-bec-m365`) |
| Defense evasion (AV disabled, log cleared) | T1562.001, T1070.001 | 5001 (Defender RTP off), 1102, 104, who did it | Maintenance by admins, golden image builds |

## Ticket note template

```
Verdict: <TP | BTP | FP | Needs-data | Escalate>   Confidence: <high|moderate|low>
Alert: <rule name> | <tool> | alert id <id> | fired <UTC>
Summary (own words): <who did what, on which asset, when, from where>
Gate:
 1 real: <yes - raw event ref>
 2 what: <...>
 3 authorised: <verified how / not>
 4 corroboration: <second source + ref>
 5 succeeded: <yes/no/unknown>
 6 blast radius: <asset tier, privilege, other entities>
 7 ongoing: <yes/no>
Entities: user=<>, host=<>, ip=<defanged>, hash=<sha256>, domain=<defanged>
Queries run: <refs / saved links, time ranges>
Benign cause (BTP/FP only): <named cause + evidence>
Actions taken: <none | isolation requested (approved by) | ...>
Next: <hand-off to IR / tuning request / closed>
ATT&CK: <Txxxx.xxx>
```

## False positives & benign look-alikes

- Covered per family in the table above. Recurring causes: sanctioned admin
  tools, software updaters, security tools touching each other (EDR vs AV vs
  backup), VPN/SASE egress IPs, test accounts, and lab hosts outside the
  documented lab range.
- A BTP is still useful signal: record it so the rule can be tuned with a
  narrow, expiring exclusion (by host + signer + path, not by "process name").

## Pitfalls

- Closing on the vendor's severity or title instead of the raw event.
- Excluding by process name (`powershell.exe`) instead of a narrow combination.
- Missing that a "blocked" alert was one of several attempts and a later one
  succeeded; always check for follow-on activity.
- Treating geolocation as fact; it is a low-confidence enrichment.
- Not checking whether the IP was a NAT/VPN egress shared by many users.
- Uploading a customer document to a public sandbox (data leak).

## Output

- One verdict per alert with the ticket note above.
- For TP / Escalate: hand-off to `incident-response` (`/ir`) with provisional
  severity; for deep entity work, `/investigate`.
- For FP / BTP: tuning request to `detection-engineering` with the exact
  proposed exclusion.
- IOCs to `threat-intel-ioc` (`/ioc`).

## References

- MITRE ATT&CK: https://attack.mitre.org/ (techniques cited above).
- Microsoft Learn: Advanced hunting schema reference (DeviceProcessEvents,
  DeviceNetworkEvents, FileProfile() function).
- Microsoft Learn: SigninLogs table reference; Microsoft Entra authentication
  and authorization error codes.
- Splunk Common Information Model (CIM): Authentication and Endpoint data models.
- NIST SP 800-61 Rev. 3 (Detect / Respond functions).
