---
description: "Hardening review of a system, domain, tenant or cloud account: evidence-based findings against CIS / vendor baselines, prioritised by attack path and exploitability, with change-safe remediation. Usage: /harden <ad|windows|m365|entra|linux|aws|azure|gcp|k8s> [<target>] [--input <export-or-config-file>] [--after-incident <case-folder>]"
argument-hint: "<ad|windows|m365|entra|linux|aws|azure|gcp|k8s> [<target>] [--input <file>] [--after-incident <case-folder>]"
---

# /harden

A hardening review that a change board can act on: each finding has evidence, the
attack it enables, the fix, the blast radius of the fix, and a priority. Not a
200-line checklist dump.

Input: `$ARGUMENTS`

## Usage

```
/harden ad corp.contoso.example --input exports/pingcastle.xml
/harden m365 --input exports/entra-ca-policies.json
/harden linux web-02 --input exports/web-02-lynis.log
/harden aws 111122223333 --input exports/prowler-output.json
/harden entra --after-incident cases/2026-11-25-ceo-mailbox-rule
```

`--after-incident` focuses the review on the entry vector, persistence and privilege
paths observed in that case.

## Skills to load

- Windows / AD: `hardening-windows-ad`; Microsoft 365 / Entra ID: `hardening-m365-entra`
- Linux: `hardening-linux`; AWS / Azure / GCP / Kubernetes: `hardening-cloud`
- Prioritisation, CVEs, exposure: `vuln-prioritization`
- Logging gaps found during the review: `logging-coverage`

## Evidence gate

- Each finding is backed by **observed configuration** (export, command output, tool
  report, screenshot reference) with the date it was collected. No "probably enabled".
- Baseline references are named precisely (e.g. "CIS Microsoft Windows Server 2022
  Benchmark", "CIS AWS Foundations Benchmark", "Microsoft Learn: Entra Conditional
  Access"), without invented control numbers - quote a control ID only if it is in
  the input or you are certain of it.
- Prefer read-only collection: tool output the operator provides, or read-only
  commands/APIs. State the permissions used.

## Procedure

1. **Scope and context.** Asset, owner, business criticality, exposure (internet-facing?),
   compliance regime, change windows. Tier 0 assets (DCs, ADCS, IdP, backup, hypervisors,
   CI/CD with prod credentials) get the deepest review.
2. **Collect.** Use the operator's exports or propose read-only collection commands, e.g.
   PingCastle / Purple Knight style AD reports, `Get-ADDefaultDomainPasswordPolicy`,
   `auditpol /get /category:*`, Microsoft Graph exports of Conditional Access and
   authentication methods, `lynis audit system`, `sshd -T`, Prowler / ScoutSuite /
   cloud-native posture findings, `kube-bench`.
3. **Assess by attack path**, not by checklist order:

   | Area | Questions |
   |---|---|
   | Identity | MFA coverage and strength (phishing-resistant for admins), legacy auth, privileged role count, standing vs JIT admin, service accounts with SPNs and weak passwords, delegation |
   | Credential exposure | LAPS / Windows LAPS, Credential Guard, LSA protection, cached credentials, secrets in scripts/CI |
   | Lateral movement | Local admin reuse, SMB signing, NTLM restrictions, RDP exposure, tiering |
   | Execution control | ASR rules, WDAC/AppLocker, macro policy, script host restrictions |
   | Exposure | Internet-facing services, management planes, public buckets/storage, open security groups |
   | Detection readiness | Audit policy, Sysmon/EDR coverage, log forwarding, retention (`logging-coverage`) |
   | Recovery | Immutable/offline backups, tested restore, break-glass accounts |

4. **Prioritise** with `vuln-prioritization`: exploitability (known exploitation, e.g.
   CISA KEV listing), exposure, privilege gained, asset tier. P1 = direct path to
   Tier 0 or internet-facing exploitable; P4 = defence-in-depth.
5. **Plan the fix**: change, expected user impact, test approach, rollback, monitoring
   (audit mode first where available, e.g. ASR audit, CA report-only).

## Output format

```markdown
## Hardening review: <target>    collected <UTC date>    reviewer <name>
### Summary: top 5 risks in one line each
### Findings
| ID | Priority | Area | Finding (observed) | Evidence | Attack enabled (ATT&CK) | Fix | Fix blast radius | Rollback | Effort |
|---|---|---|---|---|---|---|---|---|---|
| H1 | P1 | Identity | 14 accounts excluded from MFA CA policy incl. 2 Global Admins | ca-policies.json 2026-11-24 | T1078.004 | Remove exclusions; keep 2 monitored break-glass accounts | Admins must register phishing-resistant MFA | Re-add exclusion | S |
### Quick wins (< 1 day, low risk)
### Requires change approval / project
### Detection follow-ups (-> /detect, /coverage)
```

## Gates and safety

- **Review only: do not apply configuration changes from this command.** Remediation
  produces a change proposal; applying it needs the owner's approval and the
  organisation's change process.
- Policies that can lock out users or admins (Conditional Access, MFA enforcement, NTLM
  blocking, firewall default-deny) go through audit / report-only mode first and keep
  break-glass access tested.
- Do not paste tenant exports with secrets or personal data into external services.
- After an incident, verify the specific entry vector is closed before declaring recovery.
