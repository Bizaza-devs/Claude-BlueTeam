---
name: incident-response
description: End-to-end incident response playbook aligned to NIST SP 800-61 Rev. 3 and PICERL. Covers incident declaration criteria, roles (incident commander, scribe, comms lead, technical/forensics/identity leads, legal), the first-hour checklist, scoping, a containment options table with blast radius and approval level (host isolation, account disable, token revocation, firewall/DNS block, krbtgt reset), eradication, recovery and monitoring, legal/regulatory notification triggers (GDPR Art. 33 72h, NIS2 24h early warning / 72h notification / one-month final report, SEC Form 8-K Item 1.05 four business days) and status/exec/notification templates. Use when declaring or running an incident, when asked "we have an incident, what now", "who needs to know", "do we have to notify", "contain this host", or with /ir and /contain.
---

# Incident response

The generic playbook. Specialised playbooks (`ir-ransomware`, `ir-bec-m365`,
`ir-cloud-aws`, `ir-azure-entra`, `ir-insider-threat`) plug into the phases
below; this skill owns declaration, roles, coordination, containment
approvals, notification and comms.

## When to use

- A triaged alert, report or hunt finding meets the declaration criteria.
- A third party (customer, law enforcement, CERT, vendor, researcher) reports
  a compromise.
- You need a containment plan with approvals (`/contain`).
- You need to decide whether legal or regulatory notification may apply.

## Ground rules

1. **Declared means owned.** An incident has a named incident commander (IC)
   from the moment of declaration. No IC, no incident.
2. **Preserve before you change.** Before containment that destroys state,
   capture what it destroys (memory, volatile network state, cloud snapshots,
   mailbox audit data), or record the IC's decision to accept the loss.
3. **Every containment action has an approver, a blast-radius statement and a
   rollback** in `decisions.md`.
4. **Legal decides notification.** Responders identify triggers and preserve
   facts; legal counsel determines whether and when to notify. Do not send
   external notifications on your own.
5. **Assume the attacker can read normal channels.** Coordinate SEV1/SEV2 on
   an out-of-band channel until identity and mail are proven clean.

## Workflow

1. **Declare** (criteria below), assign IC, open the case with `/ir`.
2. **Mobilise roles**, open the out-of-band bridge, start the timeline.
3. **First-hour checklist.**
4. **Scope**: entities, techniques, time window, data at risk.
5. **Contain** (short-term, then long-term) with approvals.
6. **Eradicate** all footholds; verify by hunt.
7. **Recover** from known-good; heightened monitoring window.
8. **Notify** as legal directs; **report** (`/report`); **review** (`/postmortem`).

## Declaration criteria

Declare an incident when any of the following is supported by evidence
(TP from `alert-triage` or equivalent):

- Unauthorised access to a system, account, or data has occurred or is likely.
- Malware executed (not just delivered) on a production system.
- Any tier-0 asset or privileged identity shows unexplained activity.
- Possible exposure, alteration or loss of personal, regulated, customer or
  confidential data.
- Fraud attempt using a compromised internal account (BEC).
- Availability impact caused by malicious activity (ransomware, DDoS, wiper).
- A credible third-party notification of compromise.

When in doubt, declare at a lower severity and downgrade later.

## Roles

| Role | Responsibilities | Not responsible for |
|---|---|---|
| Incident Commander (IC) | Owns the incident, sets objectives and severity, approves containment, runs the cadence, decides escalation to execs | Doing hands-on analysis |
| Scribe | Maintains timeline, decisions log, action tracker, attendance | Decisions |
| Comms lead | Internal updates, exec briefs, coordinates with PR/legal on external wording | Technical findings |
| Technical lead(s) | Investigation workstreams: endpoint, identity, cloud, network | Approving destructive actions |
| Forensics lead | Evidence acquisition, chain of custody (`evidence-handling`) | Containment timing |
| Identity lead | AD/Entra/IdP actions: resets, revocations, privileged access | |
| Legal counsel | Privilege, notification obligations, law enforcement, insurer, contracts | |
| Business owner | Impact assessment, acceptance of business disruption | |
| Liaisons | Cyber insurer, external IR firm, MSSP, law enforcement, regulators (via legal) | |

Small teams combine roles, but the IC and the scribe should not be the same
person as the lead doing hands-on work during a SEV1.

## First-hour checklist

- [ ] IC named; severity set (`blueteam-methodology` matrix); case ID created.
- [ ] Out-of-band bridge and chat opened; participants verified.
- [ ] Legal counsel informed if data, fraud or SEV1/SEV2 (consider
      privilege: in many jurisdictions counsel directs the investigation).
- [ ] Cyber insurer notification requirements checked (many policies require
      early notice and use of panel IR firms; check before engaging vendors).
- [ ] Timeline started from first known event; all clocks noted in UTC.
- [ ] Logging verified and retention extended: EDR, SIEM, M365 audit,
      CloudTrail, VPN, firewall, DNS, proxy. Export at-risk logs now.
- [ ] Volatile evidence captured on key hosts (memory, then triage collection).
- [ ] Initial scope: known affected users, hosts, cloud principals, data stores.
- [ ] Immediate harm stopped where clear (e.g. revoke an active attacker
      session, block a payment), with IC approval and evidence preserved.
- [ ] Attacker-observable actions minimised until scope is understood
      (no mass password reset announcements on the compromised mail system).
- [ ] Next update time announced.

## Scoping

Answer, with evidence and confidence:

| Question | Typical sources | Skills |
|---|---|---|
| Initial access: how and when? | Mail, VPN, web/WAF logs, sign-ins, EDR | `phishing-analysis`, `hunt-webshells` |
| Which identities are compromised? | SigninLogs, 4624/4625/4768/4769, CloudTrail | `hunt-ad-identity-attacks`, `ir-azure-entra`, `ir-cloud-aws` |
| Which hosts were touched? | EDR, 4624 type 3/10, 7045, 5145, RDP logs | `hunt-lateral-movement` |
| Persistence? | Services, tasks, Run keys, WMI, app consents, keys | `hunt-windows-persistence`, `hunt-linux-persistence` |
| What data was accessed or taken? | File audit, SharePoint/OneDrive audit, S3 data events, proxy, NetFlow | `hunt-exfiltration` |
| Is the attacker still active? | Live sessions, recent beacons, new logons | `hunt-c2-beaconing` |
| What is the earliest evidence? | Full retention search on every IOC | `timeline-analysis` |

Iterate: every new IOC or technique is searched estate-wide, which may expand scope.

## Containment options

Approval levels are a default; set them in your IR policy.

| Action | Effect | Blast radius / evidence risk | Rollback | Approval |
|---|---|---|---|---|
| EDR network isolation of a host | Cuts network except EDR channel | User/service down; keeps memory and disk intact (preferred over power-off) | Release isolation | IC (workstation: SOC lead per policy) |
| Power off / reboot | Stops execution | **Destroys memory evidence**; may trigger encryption-on-boot or lose ransomware keys in memory | None | IC, only after memory capture or explicit acceptance |
| Disable user account | Blocks new auth | Existing sessions/tokens may stay valid until revoked; business impact for the user | Re-enable | IC |
| Revoke sessions / refresh tokens (Entra, Okta, Google) | Forces re-auth | Low; user re-signs in; attacker with password + MFA method can return | N/A | IC / identity lead |
| Password reset | Invalidates password | Does not revoke existing tokens alone; resetting via compromised mail tips off attacker | N/A | Identity lead |
| Remove MFA methods / require re-registration | Removes attacker-registered methods | User must re-register; verify user identity out-of-band | N/A | Identity lead |
| Disable / delete OAuth app or service principal | Stops app access | May break integrations; preserve app config first | Re-enable (delete is harder) | IC + app owner |
| Rotate cloud access keys / secrets | Invalidates stolen keys | Breaks workloads using them; coordinate | New key | IC + service owner |
| Block IP/domain at firewall, proxy, DNS | Cuts known C2 | Attacker may switch infrastructure; shared hosting collateral; tips off | Remove rule | SOC lead / change process |
| Segment / isolate a VLAN or site | Stops lateral spread | Major business impact | Revert ACL | IC + business owner |
| Disable VPN / remote access for a group | Cuts external access | Major workforce impact | Re-enable | IC + exec sponsor |
| Reset krbtgt (twice, with replication wait between) | Invalidates forged/existing Kerberos tickets | Service disruption if done wrongly; follow Microsoft guidance | None | IC + AD owner, change window |
| Take systems or services offline | Stops impact | Business outage | Restore | Exec sponsor |

Short-term containment stops spread now; long-term containment keeps the
business running safely while eradication is prepared (e.g. rebuilt jump host,
temporary allowlists). For hands-on-keyboard intrusions, plan a coordinated
eviction (all footholds, accounts and keys in one window) rather than
piecemeal removal that alerts the actor.

## Eradication

- Remove persistence found during scoping; re-hunt for each technique class.
- Reset credentials in scope: user, service, privileged, and keys/secrets
  exposed on compromised hosts (browser stores, config files, scripts).
- For AD compromise with domain admin: krbtgt double reset, review AdminSDHolder,
  GPOs, delegation, trusts (`hunt-ad-identity-attacks`, `hardening-windows-ad`).
- Patch or mitigate the initial access vector.
- Rebuild rather than clean hosts where an attacker had admin rights.
- Verification: hunts for each known TTP return clean over a defined window.

## Recovery

- Restore from backups verified to predate the earliest attacker activity,
  scanned before reconnecting.
- Rejoin in order of dependency (identity, core infra, business apps, users).
- Heightened monitoring window (commonly 30+ days) with specific detections
  for the actor's TTPs and IOCs.
- Business owner signs off on return to normal operations.

## Legal and regulatory notification triggers

Responders flag triggers and preserve facts; **legal counsel confirms
applicability, timing and content.** The summaries below are orientation,
not legal advice; national transpositions and sector rules differ.

| Regime | Trigger (summary) | Timing (summary) |
|---|---|---|
| EU GDPR Art. 33 | Personal data breach likely to result in a risk to individuals' rights and freedoms (controller notifies supervisory authority) | Without undue delay and, where feasible, not later than 72 hours after becoming aware; reasons required if later |
| EU GDPR Art. 34 | Breach likely to result in a high risk to individuals | Communicate to data subjects without undue delay |
| GDPR Art. 33(2) | Processor becomes aware of a breach | Notify the controller without undue delay (contracts often set hours) |
| EU NIS2 Art. 23 | Significant incident at an essential or important entity | Early warning within 24 hours of becoming aware; incident notification within 72 hours; intermediate reports on request; final report within one month of the incident notification (to the CSIRT or competent authority per national law) |
| US SEC Form 8-K Item 1.05 | Registrant determines a cybersecurity incident is material | Within four business days after the materiality determination, which must be made without unreasonable delay; limited delay possible only on US Attorney General determination |
| Sector / other | e.g. EU DORA (financial entities), HIPAA (US health), PCI DSS (card brands/acquirer), US state breach laws, national CSIRT rules, contractual customer clauses | Varies; legal to confirm |

Responder actions to support legal:
- Record the time the organisation "became aware" and the evidence then held.
- Maintain a data inventory of affected systems and data categories.
- Keep facts separate from speculation in anything legal may disclose.
- Route regulator, law enforcement and customer contact through legal/comms.

## Communication templates

### Internal status update

```
[SEV<n>] <case id> - Update #<n> - <UTC time>
Status: <Investigating | Contained | Eradicating | Recovering | Monitoring>
Since last update: <2-4 bullets of facts>
Current assessment: <what we believe> (<likelihood>, <confidence> confidence)
Impact: <systems / users / data, known vs suspected>
Actions in progress: <action - owner - ETA>
Decisions needed: <decision - from whom - by when>
Next update: <UTC time>
```

### Executive brief (keep to one screen)

```
What happened: <one sentence, plain language>
Business impact now: <operations, customers, data>
What we are doing: <containment state, key next steps>
What we need from you: <decisions, approvals, resources>
Risks and unknowns: <top 3>
Notification status: <legal reviewing / not applicable / submitted on <date>>
Next brief: <time>
```

### User-facing notice (internal, e.g. forced password reset)

```
Subject: Action required: security reset of your account
As part of a security response, we have reset your sign-in. You will be asked to
sign in again and re-register your MFA method. IT will never ask for your
password or MFA codes. If you receive unexpected prompts, contact <channel>.
```

External, customer and regulator notifications: drafted by legal/comms from
the case facts; the IR team reviews only for technical accuracy.

## False positives & benign look-alikes

- "Incidents" that are authorised tests: red team, pentest, BAS tools. Keep a
  deconfliction contact list; verify with the test owner before standing down.
- Outages misattributed to attacks (expired certificate, failed update).
  Keep the hypothesis open but do not declare on availability alone.
- Duplicate incidents across teams; merge by entity overlap.

## Pitfalls

- Resetting the compromised user's password and emailing them the news on a
  mailbox the attacker controls.
- Disabling an account but leaving refresh tokens, app passwords, OAuth
  grants, SSH keys and cloud access keys active.
- Rebooting "to be safe" and losing the only memory evidence.
- Engaging an IR vendor before checking insurer requirements and privilege.
- Losing log data to default retention during a long investigation.
- Announcing eradication before verification hunts complete.

## Output

- Case folder with timeline, decisions, evidence log (`blueteam-methodology`).
- Containment plan with approvals and rollbacks (`/contain`).
- Notification trigger memo for legal (facts, awareness time, data categories).
- Hand-offs: specialised `ir-*` playbooks, forensics skills, `ir-report-writing`
  (`/report`), `post-incident-review` (`/postmortem`), `detection-engineering`.

## References

- NIST SP 800-61 Rev. 3 (2025) and NIST CSF 2.0.
- SANS Incident Handler's Handbook (PICERL).
- CISA Federal Government Cybersecurity Incident and Vulnerability Response Playbooks.
- Regulation (EU) 2016/679 (GDPR), Articles 33 and 34; EDPB Guidelines 9/2022
  on personal data breach notification.
- Directive (EU) 2022/2555 (NIS2), Article 23.
- US SEC, Cybersecurity Risk Management, Strategy, Governance, and Incident
  Disclosure final rule (2023), Form 8-K Item 1.05.
- Microsoft Learn: AD Forest Recovery - resetting the krbtgt password.
- MITRE ATT&CK: https://attack.mitre.org/
