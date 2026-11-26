---
name: ir-ransomware
description: Ransomware incident playbook aligned with the CISA #StopRansomware Guide. Covers early indicators (vssadmin/wmic shadow copy deletion, wbadmin delete catalog, bcdedit recoveryenabled No, T1490; mass file rename T1486; backup console tampering; service stops T1489; ESXi vim-cmd/esxcli VM kills, SSH enablement, ESX Admins group), first actions (isolate, do not power off, capture memory), patient zero and initial access, pre-encryption exfiltration (rclone, MEGA), Active Directory and backup integrity checks (DCSync 4662, krbtgt), decryptor check via No More Ransom, the do-not-pay-without-legal/OFAC note, and the rebuild sequence. Use when files are encrypted, a ransom note appears, shadow copies are deleted, VMs are powered off on ESXi, or someone says "we're hit by ransomware".
---

# Ransomware incident response

Ransomware is usually the last stage of a hands-on intrusion that began days or
weeks earlier. Treat it as two problems: stop the encryption now, and find and
evict the intrusion that delivered it.

## When to use

- Ransom notes, encrypted/renamed files, or extortion contact.
- Precursor alerts: shadow copy deletion, backup deletion, AV tampering,
  mass service stops, ESXi VMs killed.
- A leak-site listing or extortion email naming the organisation (data theft
  without encryption is still in scope).

Run under `incident-response` (roles, approvals, notification). This is SEV1
by default until scope proves otherwise.

## Ground rules

1. **Isolate, do not power off.** Network-isolate affected hosts (EDR
   isolation, switch port, VLAN, hypervisor vNIC disconnect). Powering off
   destroys memory that may hold keys, process evidence and attacker tooling.
   Power off only when isolation is impossible and spread is ongoing, and
   record the decision.
2. **Capture memory from a sample of affected hosts before any reboot**
   (`memory-forensics`), and image at least one encrypted host.
3. **Do not delete ransom notes, encrypted files or attacker binaries.** They
   identify the family and may be needed for decryption.
4. **No contact with the threat actor and no payment discussion without IC,
   executive, legal counsel and (where applicable) insurer involvement.**
5. **Do not restore anything until the backup's integrity and the restore
   environment are verified clean.**

## Workflow

1. Declare SEV1, mobilise IR roles, open out-of-band comms (`incident-response`).
2. Contain spread: isolate affected hosts and, if spreading, the segments,
   remote access and admin paths the actor is using.
3. Protect backups: disconnect/lock backup infrastructure, verify immutable
   and offline copies exist.
4. Preserve: memory, triage collections, logs (export before they roll).
5. Identify the family and check for decryptors.
6. Scope: patient zero, initial access, credentials, persistence, exfiltration.
7. Eradicate as a coordinated eviction; rebuild identity first.
8. Recover in dependency order; monitor; notify via legal; review.

## Early indicators

| Indicator | ATT&CK | Where to see it |
|---|---|---|
| `vssadmin delete shadows /all /quiet`, `vssadmin resize shadowstorage ... /maxsize=401MB` | T1490 | Process creation (4688, Sysmon 1, `DeviceProcessEvents`) |
| `wmic shadowcopy delete`, `Get-WmiObject Win32_ShadowCopy` + `.Delete()`, `Get-CimInstance Win32_ShadowCopy \| Remove-CimInstance` | T1490 | Process creation, PowerShell 4104 |
| `wbadmin delete catalog -quiet`, `wbadmin delete systemstatebackup` | T1490 | Process creation; Microsoft-Windows-Backup event 524 (catalog deleted) |
| `bcdedit /set {default} recoveryenabled No`, `bootstatuspolicy ignoreallfailures` | T1490 | Process creation |
| Mass `net stop` / `sc config ... start= disabled` / `taskkill` of SQL, Exchange, backup, AV services | T1489 | 7036/7040 service events, process creation |
| Defender / AV disabled, exclusions added | T1562.001 | Defender 5001, 5007; registry `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` |
| Event logs cleared | T1070.001 | Security 1102, System 104 |
| Bursts of file renames with a new extension, ransom notes (`README`, `HOW_TO_DECRYPT` style) in many folders | T1486 | `DeviceFileEvents` (`FileRenamed`, `FileCreated`), Sysmon 11, file server audit 4663 |
| Backup console: jobs deleted, retention reduced, repositories removed, immutability changes | T1490 | Backup application audit log |
| Exfil tooling: `rclone`, `MEGAsync`/`MEGAcmd`, `WinSCP`, `restic`, `FileZilla` on servers | T1567.002, T1048 | Process creation, network egress volume |
| Mass deployment: PsExec, GPO scheduled tasks, WMI, `wmic /node:` | T1569.002, T1484.001, T1047 | 7045, 5136 (GPO changes), 4698 |
| ESXi: SSH enabled, `esxcli vm process kill`, `vim-cmd vmsvc/power.off`, `vim-cmd vmsvc/snapshot.removeall`, `execInstalledOnly` disabled, files with `.vmdk`/`.vmx` renamed | T1486, T1529 | `/var/log/shell.log`, `/var/log/hostd.log`, `/var/log/auth.log`, vCenter events |
| AD group `ESX Admins` created or populated (domain-joined ESXi grant admin to it by default in affected versions; CVE-2024-37085) | T1098 | 4727/4728/4731/4732, 5136 |

### Detection queries

```kql
// Defender XDR: inhibit-system-recovery commands in the last 7 days.
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (FileName =~ "vssadmin.exe" and ProcessCommandLine has_any ("delete shadows", "resize shadowstorage"))
     or (FileName =~ "wmic.exe" and ProcessCommandLine has "shadowcopy" and ProcessCommandLine has "delete")
     or (FileName =~ "wbadmin.exe" and ProcessCommandLine has "delete")
     or (FileName =~ "bcdedit.exe" and ProcessCommandLine has_any ("recoveryenabled", "ignoreallfailures"))
     or (ProcessCommandLine has "Win32_ShadowCopy" and ProcessCommandLine has_any ("Delete", "Remove-CimInstance"))
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
```

```kql
// Defender XDR: rename bursts per device per 5 minutes. Tune threshold to your file servers' baseline.
DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType == "FileRenamed"
| summarize Renames = count(), Extensions = make_set(tostring(split(FileName, ".")[-1]), 20),
            Procs = make_set(InitiatingProcessFileName, 5) by DeviceName, bin(Timestamp, 5m)
| where Renames > 500
```

~~~spl
```Splunk / Sysmon: shadow copy and backup deletion. Tune: index, sourcetype.```
index=sysmon EventCode=1
  ((Image="*\\vssadmin.exe" CommandLine="*delete*shadows*")
   OR (Image="*\\wmic.exe" CommandLine="*shadowcopy*delete*")
   OR (Image="*\\wbadmin.exe" CommandLine="*delete*")
   OR (Image="*\\bcdedit.exe" (CommandLine="*recoveryenabled*" OR CommandLine="*ignoreallfailures*")))
| table _time, host, User, ParentImage, CommandLine
~~~

```bash
# ESXi (read-only review on the host or on exported logs): VM kills, SSH, setting changes.
grep -E "vim-cmd|esxcli|vmsvc/power.off|process kill|execInstalledOnly|enable_ssh|firewall" /var/log/shell.log
grep -iE "Accepted|Failed|root" /var/log/auth.log | tail -200
```

## First actions (first 60 minutes)

1. **Stop the spread**: EDR-isolate encrypting hosts; if hypervisors are
   targeted, isolate management networks (vCenter/ESXi management, iDRAC/iLO).
2. **Cut attacker access paths** with IC approval: VPN for affected accounts
   or entirely, RMM tools not under IT control, exposed RDP, compromised
   admin accounts (disable, revoke sessions).
3. **Protect backups**: disconnect backup servers from the domain network,
   change backup console credentials from a clean device, confirm offline /
   immutable copies and their latest clean restore point.
4. **Preserve**: memory from a sample of encrypting hosts and from suspected
   patient zero; triage collection (`windows-forensics`); export EDR telemetry,
   firewall, VPN, DNS and domain controller logs.
5. **Do not wipe or reimage yet**; do not run "cleanup" tools that delete
   artifacts.
6. **Notify** legal, insurer (per policy terms), and consider law enforcement
   via legal (in the US, CISA / FBI field office / IC3; in the EU, the
   national CSIRT and police cybercrime unit).

## Identify the family and check for decryptors

- Collect: ransom note text, encrypted file extension, a few encrypted
  sample files plus originals if available, contact/leak-site references.
- Check **No More Ransom** (nomoreransom.org, Europol/NHTCU and partners) for
  a free decryptor; also security-vendor decryptor pages. Uploading samples to
  public identification services sends data off-site: get legal approval and
  avoid files with sensitive content.
- Test any decryptor on copies, never on the only copy.

## Patient zero and initial access

- Encryption start host is rarely patient zero. Build a timeline backwards
  (`timeline-analysis`): earliest note creation -> deployment mechanism ->
  credential theft -> lateral movement -> first foothold.
- Common initial access to test: exposed or unpatched edge devices (VPN,
  firewall, file transfer appliances), VPN without MFA or with valid stolen
  credentials (T1133, T1078), exposed RDP (T1021.001), phishing loaders
  (T1566), compromised RMM/third-party access (T1199).
- Look for staging: recon tools (AdFind, SharpHound, network scanners),
  credential dumping (`hunt-credential-access`), remote access tools
  (`hunt-lolbins`), data staging archives (`.7z`, `.rar`) and exfil tools.
- Exfiltration check is mandatory: double extortion is common. Review egress
  volumes by host, cloud storage destinations, `rclone` configs
  (`rclone.conf`), and proxy logs (`hunt-exfiltration`).

## Active Directory and identity integrity

- Changes to privileged groups (4728, 4732, 4756), new accounts (4720),
  GPO modifications (5136 on `groupPolicyContainer`), new scheduled tasks via GPO.
- DCSync: 4662 on the domain object with replication rights GUIDs
  `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` (DS-Replication-Get-Changes) and
  `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` (DS-Replication-Get-Changes-All) from
  non-DC accounts (`hunt-ad-identity-attacks`).
- NTDS.dit theft: `ntdsutil "ac i ntds" "ifm"`, VSS copy of `ntds.dit` on DCs.
- If domain admin was obtained, assume all domain credentials are compromised:
  plan krbtgt double reset, all privileged and service account resets, and
  consider AD forest recovery from a pre-compromise backup.
- Cloud identity: check Entra Connect / sync server and federation
  (`ir-azure-entra`); hybrid attackers pivot to cloud.

## Backup integrity

| Check | Why |
|---|---|
| Backup server and console were not domain-joined or used compromised credentials | Attackers target backup admin credentials to delete restore points |
| Backup audit log for deletions, retention changes, encryption key changes | Silent tampering before encryption |
| Restore point predates earliest attacker activity (not just encryption) | Restoring a backdoored system re-infects |
| Restore tested in an isolated network and scanned (AV + YARA from the case, `yara-rules`) | Confirms data and absence of known tooling |
| Offline / immutable copy confirmed | Last line if online backups are gone |

## Paying a ransom

The bundle does not advise on whether to pay. Ensure the decision involves
executives, legal counsel, the insurer and, where appropriate, law enforcement.
Legal must assess sanctions exposure (for example the US Treasury OFAC advisory
on potential sanctions risks of facilitating ransomware payments) and any
reporting duties. CISA and the FBI publicly discourage payment. Payment does not
guarantee decryption, deletion of stolen data, or no re-attack, and does not
remove the need to eradicate the intrusion.

## Rebuild sequence

1. **Clean enclave**: new admin workstations, out-of-band management network,
   fresh credentials created from clean devices.
2. **Identity**: recover or rebuild domain controllers (pre-compromise backup or
   forest recovery), krbtgt double reset, all privileged accounts reset, tiered
   admin model enforced (`hardening-windows-ad`).
3. **Core services**: DNS, DHCP, PKI (check for rogue templates / CA abuse),
   time, Entra Connect.
4. **Security tooling**: EDR on everything before reconnect, logging to SIEM
   verified (`logging-coverage`).
5. **Backup infrastructure** rebuilt hardened, immutable copies enabled.
6. **Business-critical applications** in order of the business impact analysis,
   restored from verified backups, patched before exposure.
7. **Endpoints**: reimage, do not clean.
8. **Remote access** re-enabled last, with MFA and the initial access vector fixed.
9. **Monitoring window** with specific detections for the actor's TTPs.

## False positives & benign look-alikes

- Backup software and system restore maintenance legitimately call
  `vssadmin` (e.g. list/resize) and `wbadmin`. Delete-all with `/quiet` from
  an interactive or remote session is rarely benign; verify against change
  records.
- Mass renames from document management migrations, photo/media tools,
  compression jobs, developer build systems.
- Legitimate encryption (BitLocker enablement, EFS, archive encryption).
- ESXi admins powering off VMs during maintenance (correlate with vCenter
  tasks and change tickets).

## Pitfalls

- Powering off every machine and losing all memory evidence.
- Restoring from the latest backup, which contains the attacker's persistence.
- Rebuilding servers while the domain is still compromised.
- Focusing on encryption and missing that data was stolen first.
- Using compromised email/chat for coordination.
- Forgetting hypervisors, NAS devices, and cloud workloads in scope.
- Resetting passwords before revoking tokens and removing attacker accounts.

## Output

- Scope statement: hosts encrypted, data exfiltrated (confidence), identities
  compromised, initial access vector, dwell time.
- Family identification and decryptor status.
- Rebuild plan with order and owners; restore points chosen with evidence.
- Hand-offs: `incident-response` (notification, comms), `memory-forensics`,
  `windows-forensics`, `timeline-analysis`, `hunt-ad-identity-attacks`,
  `threat-intel-ioc` (`/ioc`), `ir-report-writing`, `post-incident-review`.

## References

- CISA, MS-ISAC et al., #StopRansomware Guide (joint guide; Part 2: Ransomware
  and Data Extortion Response Checklist).
- NIST SP 800-61 Rev. 3; NIST IR 8374, Ransomware Risk Management: A
  Cybersecurity Framework Profile.
- No More Ransom project (Europol, Dutch National Police and partners).
- US Treasury OFAC, Updated Advisory on Potential Sanctions Risks for
  Facilitating Ransomware Payments (2021).
- Microsoft Learn: Active Directory Forest Recovery Guide.
- Broadcom/VMware security advisory for CVE-2024-37085 (ESXi AD integration).
- MITRE ATT&CK: T1486, T1490, T1489, T1562.001, T1070.001, T1567.002, T1021.001,
  T1133, T1078, T1484.001 - https://attack.mitre.org/techniques/T1486/
