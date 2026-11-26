---
name: hunt-dispatch
description: Router and operating loop for threat hunting. Takes a hunt input (a hypothesis, a threat-intel report, an ATT&CK technique ID such as T1003.001 or T1021.002, a red-team finding, or an anomaly someone noticed) and picks the right hunt-* skill(s) for Windows persistence, lateral movement, credential access, AD/identity attacks, LOLBins, C2 beaconing, exfiltration, Linux persistence, webshells, cloud control plane or Kubernetes runtime. Defines the hunt loop (hypothesis, data check, query, stack, pivot, conclude, convert to detection), the PEAK and TaHiTI frameworks, the Hunting Maturity Model, a hunt log template and how to record a null result. Use when someone says "start a hunt", "/hunt", "hunt for this TTP", "we got an intel report, are we affected", "hypothesis-driven hunt", "PEAK", "TaHiTI", "hunt log" or "nothing found, how do I write it up".
---

# Hunt dispatch

The front door for every hunt. It turns a vague prompt ("are we affected by
X?") into a scoped, falsifiable hypothesis, checks the data exists, routes to the
specialist hunt skill(s), and makes sure every hunt ends in something durable:
a detection, a coverage gap, an incident, or a documented null result.

## When to use

- Someone types `/hunt` or asks to "hunt for" a technique, actor, tool or IOC set.
- An intel report, vendor advisory or ISAC alert lands and the question is
  "has this happened here?".
- An analyst noticed an anomaly that is not an alert (odd parent/child, a new
  service on a DC, a spike in failed logons) and wants a structured look.
- A purple-team or red-team exercise exposed a technique with no detection.
- Planning a hunt programme or backlog, or writing up a finished hunt.

## Ground rules

1. **No hunt without a written, falsifiable hypothesis.** "Look for bad stuff"
   is not a hunt. The hypothesis names a behaviour, a scope (hosts, users,
   tenant), a time window and what result would refute it.
2. **Prove the data before you trust a zero.** Before any query result counts,
   show the source is present, parsed and complete for the whole window and
   scope (volume per day per source, a known-good positive control). No data =
   "inconclusive - coverage gap", never "not found".
3. **Hunt findings are leads, not verdicts.** Nothing found in a hunt becomes a
   TP until it passes `alert-triage` with a corroborating second source. A
   confirmed TP is handed to `incident-response` immediately; the hunt pauses.
4. **Read-only by default.** Hunting does not touch the estate: no killing
   processes, deleting tasks or disabling accounts from inside a hunt. Any
   live-response collection follows `evidence-handling` and change approval.
5. **Every hunt ends with a recorded outcome** (finding, null result, coverage
   gap) and at least one follow-up item: a detection via
   `detection-engineering`, a logging fix via `logging-coverage`, or a
   hardening item.

## Workflow

The hunt loop. Each step has an exit criterion; do not skip ahead.

1. **Intake & hypothesis.** Convert the input into a hypothesis using the
   templates below. Record the trigger (intel, technique, anomaly, exercise).
   Exit: one sentence a colleague could prove wrong.
2. **Route.** Pick the specialist skill(s) from the routing table. Multi-stage
   intel (initial access, then credential theft, then lateral movement) becomes
   several linked hunts, one hypothesis each.
3. **Data check.** List required sources (each hunt skill has a "Data sources
   required" section). Run the availability queries below. Exit: every source
   marked present / partial / missing, with the gap noted.
4. **Query.** Run the narrow, high-signal query first (known-bad pattern), then
   the broad behavioural one. Time-box (see Scoping). Save every query text and
   its run time in the hunt log.
5. **Stack.** Aggregate the broad result by the attributes that should be
   stable (parent, path, signer, command-line shape, account, src-dst pair) and
   look at the rare tail (least-frequency analysis). Exclude the benign
   look-alikes listed in the skill, recording each exclusion and why.
6. **Pivot.** For each outlier: process tree, same host +/- 1 h, same user
   elsewhere, same hash / command line across the estate, network
   destinations. Use `/investigate` for entity deep-dives.
7. **Conclude.** Classify each lead: Malicious (escalate), Suspicious (needs
   data), Benign-explained (document the owner/reason), Noise. Decide the
   hypothesis: supported / refuted / inconclusive (and why).
8. **Convert.** Turn the best query into a detection through
   `detection-engineering` (Sigma via `sigma-rules`), feed missing telemetry to
   `logging-coverage`, add exclusions/allowlists you learned, update the hunt
   backlog. Close with the report stub in Output.

## Routing table

| Input mentions... | Primary skill | Often paired with |
|---|---|---|
| Run keys, services, scheduled tasks, WMI subscriptions, IFEO, COM hijack, startup folder, BITS, Office add-ins, Autoruns (T1547, T1543, T1053, T1546, T1197, T1137) | `hunt-windows-persistence` | `hunt-lolbins` |
| PsExec, WMI/WinRM/DCOM remote exec, RDP, admin shares, pass-the-hash/ticket, SSH between Windows hosts (T1021, T1047, T1569.002, T1550) | `hunt-lateral-movement` | `hunt-credential-access` |
| LSASS dump, SAM/NTDS extraction, DPAPI, browser credential theft, keylogging, password spraying, brute force (T1003, T1555, T1552, T1056, T1110) | `hunt-credential-access` | `hunt-ad-identity-attacks` |
| Kerberoasting, AS-REP roasting, DCSync, Golden/Silver tickets, DCShadow, ADCS ESC1-ESC8, Shadow Credentials, RBCD, GPO/ACL abuse, BloodHound paths (T1558, T1003.006, T1207, T1649, T1484) | `hunt-ad-identity-attacks` | `hunt-lateral-movement` |
| rundll32, regsvr32, mshta, certutil, msbuild, encoded PowerShell, AMSI bypass, Office spawning shells (T1218, T1127, T1059, T1105) | `hunt-lolbins` | `hunt-windows-persistence` |
| Beacons, jitter, DNS tunnelling, rare user-agents, JA3/JA4, long-lived connections (T1071, T1573, T1572, T1568) | `hunt-c2-beaconing` | `network-detection-suricata-zeek` |
| Large uploads, cloud storage sync, archive staging, DNS/ICMP exfil, mail forwarding (T1041, T1048, T1567, T1560, T1074) | `hunt-exfiltration` | `hunt-c2-beaconing` |
| cron, systemd units, SSH authorized_keys, LD_PRELOAD, PAM, rc scripts, kernel modules (T1053.003, T1543.002, T1098.004, T1574.006) | `hunt-linux-persistence` | `linux-forensics` |
| w3wp/httpd/nginx/java spawning shells, new .aspx/.jsp/.php in web roots, Exchange/IIS modules (T1505.003, T1505.004) | `hunt-webshells` | `hunt-lolbins` |
| CloudTrail/Azure Activity/GCP audit: new keys, role assumption, policy changes, logging disabled, consent grants (T1078.004, T1098.001, T1562.008) | `hunt-cloud-control-plane` | `ir-cloud-aws`, `ir-azure-entra` |
| Privileged pods, exec into containers, kubelet API, crypto-miners, service-account token abuse (T1610, T1611, T1609) | `hunt-k8s-runtime` | `hunt-cloud-control-plane` |

Routing by input type:

- **ATT&CK ID** - map by tactic/technique above; if the technique spans
  platforms (T1053 is Windows tasks and Linux cron), open one hunt per platform.
- **Intel report** - extract TTPs first (not just IOCs). IOCs go to
  `threat-intel-ioc` for a retro-search sweep; TTPs become hypotheses here. A
  report with only hashes/IPs is an IOC sweep, not a hunt.
- **Anomaly** - write down what was odd and why, then route by the behaviour
  (a new service on a DC is persistence and possibly lateral movement).
- **Exercise finding** - route by technique, and in Convert hand the detection
  gap to `purple-team-validation` for a re-test.

## Hypothesis templates

Fill the brackets; keep scope and window explicit.

- **TTP:** "An adversary has used [technique, ATT&CK ID] on [scope] between
  [start] and [end]; if so we expect to see [observable] in [data source]."
- **Intel-driven:** "[Actor/campaign] described in [report name, date] uses
  [TTP]; if they targeted us, [observable] would appear on [asset class]."
- **Baseline / anomaly:** "In [scope], [behaviour] normally comes from
  [population]; any [behaviour] from outside it in [window] is unexplained."
- **Crown-jewel:** "Access to [asset] in [window] came only from [expected
  admins/hosts/paths]; anything else is unauthorised."
- **Control-failure:** "[Control, e.g. ASR rule / LAPS / tiering] is assumed to
  prevent [behaviour]; evidence of [behaviour] in [scope] means the control
  is bypassed or not deployed."

Refutation clause (mandatory): "The hypothesis is refuted if, with [sources]
confirmed complete for [window], [query] returns only explained results."

## Frameworks

### PEAK (Splunk SURGe, "Prepare, Execute, Act with Knowledge")

Three hunt types, each with Prepare / Execute / Act phases:

| Type | Use it when | Prepare | Execute | Act |
|---|---|---|---|---|
| Hypothesis-driven | You have a specific TTP or intel | Topic research, hypothesis, scope, data check | Query, analyse, refine | Preserve hunt, document, create detections, communicate |
| Baseline (exploratory data analysis) | You want "normal" for a data source or behaviour | Pick data source, understand fields | Stack, distributions, outliers | Document baseline; outliers become hypothesis hunts |
| Model-assisted threat hunt (M-ATH) | A scoring/ML or statistical model helps (beaconing, entropy, clustering) | Choose features and model | Run, review top-scored items | Same as above; also keep the model as an analytic |

"Knowledge" runs through all three: business context, prior hunts, CTI.

### TaHiTI (Targeted Hunting integrating Threat Intelligence)

Developed by the Dutch financial sector. Three phases:

1. **Initiate** - a trigger (CTI, prior incident, red-team result, anomaly)
   becomes an abstract in the hunt backlog.
2. **Hunt** - define/refine (hypothesis, data, techniques), then execute;
   iterate while the hypothesis is being refined.
3. **Finalize** - document, hand over to follow-up processes: incident
   response, security monitoring (new use cases), threat intel (new
   intel), vulnerability management, and hunt-backlog updates.

TaHiTI's strength is the explicit handover list; use it as the Convert checklist.

### Hunting Maturity Model (HMM0-HMM4, David Bianco)

HMM0 relies on alerts only; HMM1 does IOC searches from intel; HMM2 follows
published hunt procedures; HMM3 creates new procedures; HMM4 automates
successful hunts into detections. Aim every hunt at leaving an HMM4 artefact.

## Data check (run before any hunt query)

```kql
// Defender XDR advanced hunting: daily volume per table. Gaps or cliffs = coverage problem.
union withsource=TableName DeviceProcessEvents, DeviceRegistryEvents, DeviceLogonEvents, DeviceEvents
| where Timestamp > ago(30d)
| summarize Events = count() by TableName, Day = bin(Timestamp, 1d)
| order by TableName asc, Day asc
// Sentinel: same idea with TimeGenerated, e.g. union withsource=TableName SecurityEvent, SigninLogs, Event
```

```kql
// Devices reporting per day vs. inventory - finds silent endpoints in scope. Tune the inventory source.
DeviceInfo
| where Timestamp > ago(30d)
| summarize LastSeen = max(Timestamp) by DeviceId, DeviceName, OSPlatform
| where LastSeen < ago(2d)
```

Splunk: daily count per index:sourcetype (restrict `index=*` to your hunt
indexes), then hosts silent for more than two days.

```spl
| tstats count where index=* earliest=-30d by index, sourcetype, _time span=1d
| eval src=index.":".sourcetype
| xyseries _time src count
```

```spl
| tstats latest(_time) as last_seen where index=wineventlog earliest=-30d by host
| where last_seen < relative_time(now(), "-2d")
| convert ctime(last_seen)
```

Also confirm the audit policy behind each event ID (e.g. 4698 needs "Audit
Other Object Access Events"; 4662 needs Directory Service Access auditing plus
a SACL). The specialist skills list these per behaviour; `logging-coverage`
owns the fixes.

**Positive control.** Where the change process allows, trigger a harmless,
known instance of the behaviour (e.g. a published Atomic Red Team test in a lab
or on an approved test host via `purple-team-validation`) and confirm the hunt
query returns it before trusting a zero.

## Scoping and time-boxing

- Default window: 30 days for behaviour hunts, 90 days for rare/slow TTPs
  (persistence, AD changes) if retention allows. State retention per source.
- Default time box: 1-2 analyst days per hypothesis. When it runs out, write
  up the state as inconclusive with the remaining leads rather than drifting.
- Start with crown-jewel scope (DCs, ADCS, Entra Connect, jump hosts, CI/CD,
  finance) when time is short; expand to the whole estate for stacking.

## Stacking (least-frequency analysis) - common method

1. Pull the broad behaviour set (all services installed, all LSASS accesses).
2. Normalise noisy fields: lower-case paths, replace user profile names with
   `<user>`, GUIDs with `<guid>`, digits in temp names with `<n>`.
3. Count by the normalised key and by `dcount(host)`.
4. Review the tail: keys seen on 1-3 hosts, or first seen in the window.
5. Every exclusion is written into the hunt log with its reason; exclusions
   become detection allowlists later.

Each hunt skill gives the exact stacking keys for its domain.

## False positives & benign look-alikes

| Look-alike | Why it fools a hunt | How to separate |
|---|---|---|
| IT admin tooling (SCCM/Intune, RMM, PsExec used by ops) | Same primitives as attackers | Known admin hosts/accounts, change tickets, consistent schedule |
| Security tools (EDR, vuln scanners, backup agents) | Touch LSASS, enumerate AD, connect everywhere | Signer + path + service account; confirm with tool owner |
| Golden images / mass deployment | A "rare" artefact appears on 500 hosts at once | First-seen burst aligned to a deployment window |
| Pen-test / red-team activity | Real TTPs | Rules-of-engagement window and source IPs from the test lead |
| Logging gaps | Absence looks like "clean" | Data check and positive control |

## Pitfalls

- Treating an IOC sweep as a hunt; IOCs age in days, TTPs in years.
- Reporting "not found" without proving the data was there.
- Filtering out the noisy population before stacking (you delete the attacker
  who hid in it); exclude after inspecting, and record exclusions.
- Hunting the whole estate first; baseline on a known-good subset, then widen.
- Never converting: a hunt that does not leave a detection or a documented
  gap is repeated work next quarter.
- Pausing too late: a confirmed TP goes to `incident-response` the moment it is
  confirmed, not at the end of the hunt.

## Output

### Hunt log (keep it live while hunting)

```markdown
# Hunt <ID: HUNT-YYYYMMDD-slug>
- Owner: <analyst>          Framework: PEAK hypothesis | baseline | M-ATH / TaHiTI
- Trigger: <intel report name+date | ATT&CK ID | anomaly | exercise finding>
- Hypothesis: <one sentence>   Refuted if: <clause>
- Scope: <hosts/users/tenant>  Window: <UTC start - end>  Time box: <days>
- Routed to: <hunt skill(s)>
## Data check
| Source | Present/Partial/Missing | Volume/day | Retention | Note |
## Query log
| # | Time (UTC) | Platform | Query (file/link) | Rows | Note |
## Exclusions applied
| Key | Reason | Owner who confirmed |
## Leads
| Lead | Entity | Classification | Evidence | Next step |
```

### Recording a null result

A null result is a valid, valuable outcome when it is defensible. Write:

- **Hypothesis status:** refuted (data complete, nothing unexplained) or
  inconclusive (data gap, time box hit, scope incomplete). Never just "clean".
- **Evidence of coverage:** sources, volumes, retention, positive-control result.
- **What was looked at:** query texts and row counts, including stacks reviewed.
- **Residual risk:** what an adversary could still do that this hunt would not
  see (e.g. "no command-line logging on 14% of servers").
- **Follow-ups:** detection created or not (why), logging gaps raised, next
  review date.

### Hand-off

Confirmed malicious activity goes to `incident-response` (`/ir`); queries
become detections via `detection-engineering` / `/detect`; coverage gaps go to
`logging-coverage` / `/coverage`; IOCs to `threat-intel-ioc`; re-tests to
`purple-team-validation`. Final write-up uses each specialist skill's hunt
report stub.

## References

- MITRE ATT&CK Enterprise matrix: https://attack.mitre.org/
- Splunk SURGe, "PEAK Threat Hunting Framework" (David Bianco et al.).
- TaHiTI threat hunting methodology (Dutch financial sector / FI-ISAC NL).
- David Bianco, "The Pyramid of Pain" and the Hunting Maturity Model (Sqrrl).
- SANS, "Threat Hunting" whitepapers and the SANS FOR508 hunt process.
- NIST SP 800-61 Rev. 3, Incident Response Recommendations and Considerations.
