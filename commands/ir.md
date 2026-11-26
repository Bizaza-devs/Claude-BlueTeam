---
description: "Open an incident case folder (cases/<YYYY-MM-DD>-<slug>/) and drive the IR lifecycle: declare, scope, contain, eradicate, recover, report. Usage: /ir <slug> [\"one-line summary\"] [--type ransomware|bec|aws|entra|insider|generic] | /ir status | /ir close"
argument-hint: "<slug> [\"summary\"] [--type ransomware|bec|aws|entra|insider|generic] | status | close"
---

# /ir

Declares an incident and keeps it on rails. Creates the case folder every other
command writes into, sets severity and roles, then walks the lifecycle with the
matching playbook skill.

Input: `$ARGUMENTS`

## Usage

```
/ir ws0142-lsass "Credential dumping on finance workstation" --type generic
/ir acme-ransomware --type ransomware
/ir ceo-mailbox-rule --type bec
/ir status        # summarise the active case: phase, open actions, gaps
/ir close         # closure checklist, then hand off to /report and /postmortem
```

The slug is lowercase kebab-case, no personal names or customer secrets in it
(it ends up in folder names and possibly tickets).

## Step 1 - create the case folder

Run the scaffolder from the plugin root (`${CLAUDE_PLUGIN_ROOT}` when installed as a
plugin; otherwise the repository root):

```powershell
# Windows (use powershell.exe if pwsh is not installed; from a repo clone use .\scripts\new-case.ps1)
pwsh -NoProfile -File "$env:CLAUDE_PLUGIN_ROOT\scripts\new-case.ps1" -Name <slug>
```

```bash
# Linux / macOS (from a repo clone use ./scripts/new-case.sh)
bash "${CLAUDE_PLUGIN_ROOT}/scripts/new-case.sh" <slug>
```

It creates `cases/<YYYY-MM-DD>-<slug>/` (date = today, UTC) containing:

| File | Purpose | Header / structure |
|---|---|---|
| `notes.md` | Running case notes, decisions, status | Free text with the sections below |
| `timeline.csv` | Incident timeline | `timestamp_utc,host,source,event,detail,analyst,confidence` |
| `iocs.csv` | Indicators, defanged | `type,value_defanged,first_seen_utc,last_seen_utc,source,confidence,tlp,notes` |
| `evidence-log.csv` | Chain of custody | `item_id,description,source_host,acquired_utc,acquired_by,method,sha256,storage_location,notes` |
| `actions.md` | Containment / eradication actions and approvals | Table, see `/contain` |
| `report.md` | Report draft | Filled by `/report` |

If the script is unavailable, create exactly these files with exactly these headers
by hand and say so. Use the path the script prints; that folder is the **active case**
for the rest of the session. Case folders hold sensitive data: keep them out of git
(check `.gitignore`) and out of shared drives without access control.

## Step 2 - declare

Write to the top of `notes.md`:

```markdown
# Case <YYYY-MM-DD>-<slug>
Status: open    Phase: Detection & Analysis    Severity: <SEV1-4>    TLP: AMBER
Declared (UTC): <timestamp>    Incident commander: <name>    Scribe: <name>
Summary: <one line>
Detection source: <alert / report / third party>
## Decisions log   (timestamp_utc - decision - who - rationale)
## Open questions
## Stakeholders notified (who, when, by whom)
```

Severity guide: SEV1 = Tier 0 (domain controllers, IdP, backups) or active encryption /
exfiltration; SEV2 = confirmed compromise of user or server, contained scope;
SEV3 = single endpoint, no lateral movement; SEV4 = attempted / blocked.
Adjust to the organisation's own matrix if one exists.

## Step 3 - load the playbook

- Always: `incident-response`, `blueteam-methodology`, `evidence-handling`
- `--type ransomware` -> `ir-ransomware`; `bec` -> `ir-bec-m365`; `aws` -> `ir-cloud-aws`;
  `entra` -> `ir-azure-entra`; `insider` -> `ir-insider-threat`
- As needed: `memory-forensics`, `windows-forensics`, `linux-forensics`, `timeline-analysis`,
  `threat-intel-ioc`, `hunt-dispatch`

## Step 4 - run the lifecycle

Phases follow NIST SP 800-61 (Rev. 3 aligns them to CSF 2.0 functions; the classic
phases still apply). Update `Phase:` in `notes.md` as you move.

| Phase | Do | Exit criterion | Commands |
|---|---|---|---|
| Detection & Analysis | Confirm, scope (patient zero, accounts, hosts, data), preserve volatile evidence | Scope statement with confidence; evidence of first access or "unknown" stated | `/triage`, `/investigate`, `/hunt`, `/forensics`, `/timeline`, `/ioc` |
| Containment | Stop spread with least evidence loss; approvals recorded | No new attacker activity for an agreed watch period | `/contain` |
| Eradication | Remove persistence, malware, rogue accounts/keys; close the entry vector | Persistence hunt returns clean on all scoped hosts | `/hunt`, `/harden` |
| Recovery | Restore from known-good, reset credentials (krbtgt twice when AD is in scope), monitor | Business owner sign-off; heightened monitoring live | `/detect` |
| Post-incident | Report, lessons, detection and hardening backlog | Report delivered; actions have owners and dates | `/report`, `/postmortem`, `/coverage` |

At every phase change: one-paragraph status in `notes.md` (what we know, what we
don't, what we're doing next, decisions needed).

## /ir status

Read the active case files and print: phase, severity, time since declaration,
scoped hosts/users, last 10 timeline rows, open actions awaiting approval, evidence
items without SHA256, IOCs not yet swept, open questions.

## /ir close

Checklist before setting `Status: closed`: all actions in `actions.md` executed or
explicitly cancelled; eradication verified; credentials reset; monitoring in place;
evidence retained per policy; `/report` drafted; `/postmortem` scheduled.

## Gates and safety

- **Evidence before change:** capture memory and volatile data before reboot, isolation
  or reimage of a key host, unless the commander accepts the loss in writing.
- **No containment or eradication action executes without explicit human approval** recorded
  in `actions.md` (`/contain` enforces this). Claude proposes; humans approve.
- Assume the attacker can read email/chat on a compromised tenant: recommend
  out-of-band communication for SEV1/SEV2.
- Notification and legal obligations (regulators, customers, law enforcement, insurers)
  are decided by the organisation's legal/privacy owners; flag them, do not decide them.
- All timestamps UTC; all indicators defanged in every case file.
