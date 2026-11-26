---
description: "Structured deep-dive on one entity (user, host, IP, domain, hash, cloud principal): what it did, what touched it, how far it reaches. Usage: /investigate <user|host|ip|domain|hash|principal> <value> [--from <UTC>] [--to <UTC>] [--case <case-folder>]"
argument-hint: "<entity-type> <value> [--from <UTC>] [--to <UTC>] [--case <case-folder>]"
---

# /investigate

Take one entity and build its story: activity, relationships, anomalies, and a
scoped conclusion. Use after `/triage` returns TP or Needs more data, or when an
incident commander asks "what else did this account/host do?".

Input: `$ARGUMENTS`

## Usage

```
/investigate user j.doe@contoso.example --from 2026-11-20T00:00:00Z
/investigate host WS-0142 --case cases/2026-11-25-ws0142-lsass
/investigate ip 203.0.113.45
/investigate hash 3f2a...e91c (SHA256)
/investigate principal arn:aws:iam::111122223333:role/ci-deploy
```

Default window: 7 days before first suspicious event to now. If the entity type is
ambiguous, infer it and say so.

## Skills to load

- Always: `alert-triage`, `defender-mindset`, `threat-intel-ioc`
- Query language: `kql-sentinel-defender`, `spl-splunk`, `elastic-eql-esql`
- User / identity: `hunt-ad-identity-attacks`, `hunt-credential-access`, `ir-azure-entra`, `ir-bec-m365`
- Host: `hunt-lateral-movement`, `hunt-windows-persistence`, `hunt-linux-persistence`, `hunt-lolbins`
- IP / domain: `hunt-c2-beaconing`, `hunt-exfiltration`, `network-detection-suricata-zeek`
- Hash / file: `malware-triage`, `yara-rules`
- Cloud principal: `hunt-cloud-control-plane`, `ir-cloud-aws`, `ir-azure-entra`, `hunt-k8s-runtime`
- Building the sequence: `timeline-analysis`

## Evidence gate

- Every claim in the conclusion cites a query result or artefact (source + timestamp).
- "Compromised" requires attacker-attributable activity (not just an alert) from at
  least two sources. "Clean" requires coverage: name the log sources checked and
  their retention; absence of evidence in a missing log is not evidence of absence.

## Procedure

1. **Baseline the entity.** Owner, role, group memberships / privileges, asset tier,
   normal working hours and locations, normal peers. This is what "anomalous" is measured against.
2. **Activity sweep** over the window, per entity type:

   | Entity | Pull |
   |---|---|
   | User | Sign-ins (`SigninLogs`, 4624/4625/4648/4768/4769), MFA changes, mailbox rules, OAuth consents, privileged ops, hosts logged on to |
   | Host | Process tree anomalies, new services/tasks/run keys, logons in and out, network peers, files written to temp/startup, EDR alerts |
   | IP / domain | Which hosts/users talked to it, first/last seen, bytes, periodicity, DNS resolutions, TLS JA3/JA4 or SNI, proxy category |
   | Hash | Prevalence, first seen per host, parent processes, file paths and names, signer, network after execution |
   | Cloud principal | API calls by `eventName`/operation, source IPs and user agents, new keys/roles/policies, resource access |

3. **Pivot once per lead.** From each anomaly, pivot to the related entity (host -> user,
   user -> source IP, IP -> other hosts). Keep a pivot log; stop at 2 hops unless
   evidence demands more, and say where you stopped.
4. **Separate known-good.** Mark activity explained by change tickets, admins or tools.
5. **Order the findings** into a timeline (UTC) with `timeline-analysis`.
6. **Conclude** with a status per entity: Compromised / Suspicious / Not compromised
   (with coverage statement) / Undetermined.
7. **Hand off.** Compromised -> `/ir` (if no case yet) and `/contain`; more scope -> `/hunt`;
   missing telemetry -> `/coverage`.

## Output format

```markdown
## Investigation: <entity type> <value>
**Window (UTC):** <from> -> <to>    **Status:** <Compromised|Suspicious|Not compromised|Undetermined>
**Confidence:** <High|Medium|Low>    **Analyst:** <name>

### Baseline
### Key findings (most important first)
| # | Time (UTC) | Source | Finding | ATT&CK | Confidence |
|---|---|---|---|---|---|

### Related entities (pivot log)
| From | Relation | To | Status | Investigated? |
|---|---|---|---|---|

### Coverage: sources checked and their retention
### Indicators (defanged)
### Open questions
### Recommended actions (containment is a recommendation only; see /contain)
```

## Case integration

If a case is active, append findings to `timeline.csv`
(`timestamp_utc,host,source,event,detail,analyst,confidence`), indicators to
`iocs.csv` (`type,value_defanged,first_seen_utc,last_seen_utc,source,confidence,tlp,notes`),
and the summary to `notes.md`. Any file exported as evidence goes into
`evidence-log.csv` with its SHA256 (see `evidence-handling`).

## Gates and safety

- Read-only. Do not disable accounts, reset passwords or isolate hosts here; propose via `/contain`.
- Do not visit attacker infrastructure; passive enrichment only. Defang all indicators.
- Insider-threat subjects: involve HR/legal per `ir-insider-threat`, keep findings need-to-know,
  and do not alert the subject through your queries (e.g. no messages, no visible account changes).
