---
name: vuln-prioritization
description: Risk-based vulnerability prioritisation. Covers why CVSS v3.1/v4.0 base scores measure severity not risk (CVSS-B/BT/BE/BTE, Exploit Maturity), FIRST EPSS probability and percentile, the CISA Known Exploited Vulnerabilities (KEV) catalog and BOD 22-01 due dates, CISA SSVC decision points (Exploitation, Automatable, Technical Impact, Mission and Well-being -> Track/Track*/Attend/Act), asset criticality and internet exposure, remediation SLA tables, compensating controls and virtual patching, verifying exploitation in the wild, patch-vs-mitigate decisions, exceptions, and reporting vulnerability risk to management. Use when asked "which CVEs do we patch first", "is this CVE being exploited", "build an SLA", triage a Tenable/Qualys/Rapid7/Defender TVM export, or brief leadership on a critical vulnerability.
---

# Vulnerability prioritisation

## When to use

- A scanner export (Tenable, Qualys, Rapid7, Defender Vulnerability Management,
  Wiz/CSPM, container scanners) has thousands of findings and the team needs an order.
- A new high-profile CVE lands and leadership asks "are we exposed and how fast do we
  fix it?"
- Designing or revising remediation SLAs, an exception process or a vuln KPI report.

Not for: hunting for exploitation already happening (use `hunt-dispatch`,
`hunt-webshells`, `incident-response`) or writing detections for an exploit
(`detection-engineering`).

## Ground rules

- **No "exploited" claim without a named source.** "Actively exploited" requires a
  citable source: CISA KEV entry, vendor advisory marking exploitation, a reputable
  threat-intel report, or your own telemetry. A public PoC is not exploitation.
- **No priority without the asset.** A CVE score is about the software; risk needs the
  asset's exposure (internet-facing?), criticality and compensating controls. Record
  all three or mark the item "needs data".
- **Version evidence beats scanner banners.** Confirm affected version/configuration
  (package version, build number, feature enabled) before declaring a host vulnerable
  or not vulnerable; scanners both over- and under-report (backports, unauthenticated
  scans).
- **If exploited and exposed, also hunt.** For KEV-listed, internet-facing
  vulnerabilities, assume prior compromise is possible: patching does not remove a
  webshell. Hand off to `incident-response` / `hunt-webshells` in parallel.
- **Every exception has an owner, compensating control, and expiry date.**

## Workflow

1. **Normalise the data**: one row per (asset, CVE) with asset ID, owner, software,
   version, CVE, CVSS vector, scanner confidence (authenticated?), first seen.
2. **Enrich each CVE**: KEV (yes/no, dateAdded, dueDate, knownRansomwareCampaignUse),
   EPSS (score, percentile, date), CVSS v3.1/v4 vector, vendor exploitation status,
   fix availability.
3. **Enrich each asset**: internet exposure (from ASM/firewall/cloud data, not
   assumption), business criticality tier, data sensitivity, identity role (DC, IdP,
   hypervisor, edge device = crown jewels), existing controls (WAF, EDR, segmentation).
4. **Decide** with the SSVC-style table below; output Act / Attend / Track* / Track.
5. **Pick the response**: patch, mitigate (config/workaround/virtual patch), isolate,
   accept with exception. Assign owner and due date from the SLA table.
6. **Verify the fix** (rescan or version check) and, for exploited CVEs, verify no
   compromise (hunt).
7. **Report** risk and trend, not raw counts.

## Scoring systems and their limits

### CVSS v3.1

- Base score measures technical severity of the vulnerability in a generic setting.
  It does not know whether the bug is exploited, whether your asset is exposed, or
  how important the asset is.
- Temporal and Environmental metrics exist but are rarely filled in by scanners.
- Scope (S:C) inflation and vendor/NVD scoring differences are common; use the vector,
  not just the number.

### CVSS v4.0

- Nomenclature: **CVSS-B** (base only), **CVSS-BT** (base + threat), **CVSS-BE**
  (base + environmental), **CVSS-BTE** (all). Report which one you use.
- New/changed base metrics: Attack Requirements (AT), User Interaction None/Passive/
  Active, separate Vulnerable-system and Subsequent-system impacts (replaces Scope).
- Threat metric **Exploit Maturity**: Attacked (A), POC (P), Unreported (U) — fill it
  from KEV/intel to lower or raise the score.
- Supplemental metrics (Safety, Automatable, Recovery, Value Density, Vulnerability
  Response Effort, Provider Urgency) do not change the score but help decisions.

### EPSS (FIRST)

- Probability (0-1) that a CVE will see exploitation activity in the next 30 days,
  plus a percentile relative to all scored CVEs. Updated daily; the model is versioned.
- Use it to rank the long tail of non-KEV findings. It is not asset-specific and
  lags for brand-new CVEs (score may be low on day 1).
- Record score, percentile, and date: EPSS changes over time.

```bash
# EPSS API (FIRST): score for one or more CVEs
curl -s "https://api.first.org/data/v1/epss?cve=CVE-YYYY-NNNNN" | jq '.data[] | {cve, epss, percentile, date}'
```

### CISA KEV

- Catalog of CVEs with reliable evidence of active exploitation and clear remediation
  guidance; binding for US federal civilian agencies under BOD 22-01, a strong signal
  for everyone. Fields include `cveID`, `vendorProject`, `product`, `dateAdded`,
  `dueDate`, `requiredAction`, `knownRansomwareCampaignUse`.
- KEV is a floor, not a ceiling: exploitation is often seen before KEV listing, and KEV
  covers only CVEs meeting its criteria.

```bash
# Join scanner CVEs (one per line in cves.txt) with the KEV JSON feed
curl -s https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json -o kev.json
jq -r '.vulnerabilities[] | [.cveID,.dateAdded,.dueDate,.knownRansomwareCampaignUse] | @tsv' kev.json \
  | grep -Ff cves.txt
```

## Verifying exploitation in the wild

| Source | What it tells you | Caveat |
|---|---|---|
| CISA KEV | Confirmed exploitation, due date | Listing lag; criteria-limited |
| Vendor advisory | e.g. Microsoft Exploitability Index "Exploitation Detected" / "More Likely"; vendor "exploited in the wild" notes | Vendors differ in transparency |
| National CERT / CISA alerts | Campaign context | Sometimes days later |
| GreyNoise / honeypot data | Mass scanning or exploitation attempts against a CVE tag | Scanning is not successful exploitation |
| Threat-intel reports (vendor IR teams) | Actor, targeting, TTPs | Check date and evidence quality |
| Exploit DB / Metasploit / nuclei template | Public weaponised PoC exists | Raises likelihood; not proof of exploitation |
| Your telemetry | WAF/IDS hits, EDR detections, webshell finds | Strongest evidence for *your* risk |

Label the result: **Exploited (source)**, **PoC public**, **No known exploitation
(as of date)**. Re-check at least weekly for open Attend/Act items.

## Decision table (SSVC-style)

CISA's SSVC uses decision points **Exploitation** (none / public PoC / active),
**Automatable** (yes/no), **Technical Impact** (partial/total) and **Mission &
Well-being** (low/medium/high), with outcomes **Track, Track\*, Attend, Act**. The
table below is a simplified internal adaptation; use the CISA SSVC guide or calculator
for the authoritative tree.

| Exploitation | Exposure / Automatable | Technical impact | Asset criticality | Outcome |
|---|---|---|---|---|
| Active (KEV/vendor/telemetry) | Internet-facing or automatable | Any | Any | **Act** |
| Active | Internal only | Total | High (DC, IdP, hypervisor, backup) | **Act** |
| Active | Internal only | Partial | Low/Med | **Attend** |
| Public PoC | Internet-facing / automatable | Total | Med/High | **Attend** (Act if edge device or IdP) |
| Public PoC | Internal | Any | Any | **Track\*** (Attend if High) |
| None | Internet-facing | Total | High | **Track\*** |
| None | Internal | Any | Any | **Track** (normal patch cycle) |

Outcome meaning (CISA definitions, paraphrased): **Act** = remediate as soon as
possible with senior leadership attention; **Attend** = remediate sooner than
standard timelines, supervisory attention; **Track\*** = monitor closely, standard
timelines; **Track** = standard timelines.

EPSS as a tie-breaker inside Track/Track\*: high percentile (e.g. top 5-10%) moves an
item up one level. Tune the threshold to your capacity.

## Example SLA table

Example values to adapt, not a standard. Measure from the time the vulnerability is
known to apply to the asset (or KEV listing date, whichever is later).

| Outcome | Internet-facing / crown-jewel | Internal |
|---|---|---|
| Act | 48-72 h (mitigate in 24 h if no patch) | 7 days |
| Attend | 7 days | 14-30 days |
| Track\* | 30 days | 60 days |
| Track | Next regular cycle (30-90 days) | Next regular cycle |

- KEV items: never slower than the KEV due date if you follow BOD 22-01 as a policy.
- End-of-life software with no fix: replace/isolate plan with a date; exception only
  with compensating controls.

## Patch vs mitigate

| Situation | Response |
|---|---|
| Patch available, low change risk | Patch; verify; done |
| Patch available, high change risk (core system) and Act | Mitigate now (disable feature, block path, WAF rule, restrict access), patch in emergency change within days |
| No patch yet | Vendor workaround; reduce exposure (take off Internet, VPN-only, allowlist IPs); add detections; hunt |
| Edge device (VPN, firewall, MFT, load balancer) exploited | Patch + follow vendor integrity check / IOC guidance + assume compromise until checked; may require credential rotation and rebuild |
| Library inside an app (e.g. Java, OpenSSL) | Find reachable usage; vendor app updates; SBOM to locate copies |

Compensating controls must be **verified** (show the WAF rule blocking a test
request, the ACL in place, the feature disabled), not assumed. Virtual patches are
temporary; set an expiry.

## Asset context checklist

- Exposure: reachable from Internet? (verify with external scan/ASM, cloud SG/NSG,
  firewall NAT), from user VLANs? from partner networks?
- Role: identity (DC, IdP, ADFS, PAM), edge/remote access, hypervisor/backup,
  CI/CD, data store with regulated data -> crown jewels.
- Privilege: does compromise give domain/cloud admin or only a low-privilege service?
- Controls: EDR present and healthy, app allowlisting, segmentation, MFA in front.
- Lifecycle: production vs test, decommission date.

## Reporting to management

- Lead with **exposure and trend**: "3 internet-facing systems with actively exploited
  vulnerabilities; all mitigated within 24 h; patches due Friday" beats "4,312
  criticals".
- KPIs: % of Act items within SLA, mean time to remediate by outcome, KEV items open
  past due, internet-facing critical exposure count, exceptions open/expired.
- For an emergency CVE brief: what it is (one sentence), are we exposed (assets,
  evidence), are we compromised (hunt status), what we are doing (actions, owners,
  times), what we need (decisions: downtime approval, budget, risk acceptance).
- State confidence and data gaps (e.g. "unauthenticated scans cover 70% of servers").

## False positives & benign look-alikes

- Distro backports: RHEL/Debian fix CVEs without changing the upstream version number;
  scanner version checks flag them falsely. Check the distro security advisory/package
  changelog.
- Vulnerable component present but feature disabled or not reachable (module not
  loaded, service not listening): document the evidence; it may be Track, not Act.
- Duplicate findings across scanners/agents for the same asset: deduplicate on asset
  ID + CVE.
- Container image findings for packages not used at runtime: still fix in the base
  image, but lower urgency unless reachable.

## Pitfalls

- Sorting by CVSS base score only: patches many unexploitable "criticals" while an
  exploited "high" on the VPN waits.
- Treating EPSS as asset risk or using it for brand-new CVEs on day 0.
- Ignoring network devices, appliances and SaaS-managed components because the
  scanner does not see them.
- Closing a finding on "patch deployed" without verifying it installed and the service
  restarted.
- Patching an exploited edge device without checking for prior compromise.
- Exceptions without expiry: they become permanent risk acceptance nobody signed.

## Output

- Prioritised remediation list: asset, CVE, outcome (Act/Attend/Track\*/Track),
  evidence (KEV/EPSS/source/exposure), response (patch/mitigate), owner, due date.
- Emergency CVE brief for leadership (template in "Reporting to management").
- Hunt requests for exploited, exposed CVEs to `hunt-dispatch` / `/hunt`; detection
  requests to `detection-engineering` / `/detect`; hardening follow-ups to
  `hardening-windows-ad`, `hardening-linux`, `hardening-cloud`.

## References

- FIRST: CVSS v3.1 Specification; CVSS v4.0 Specification and User Guide; EPSS model
  documentation and API (https://www.first.org/epss/).
- CISA: Known Exploited Vulnerabilities Catalog; BOD 22-01 "Reducing the Significant
  Risk of Known Exploited Vulnerabilities"; Stakeholder-Specific Vulnerability
  Categorization (SSVC) guide.
- Carnegie Mellon SEI: SSVC documentation.
- NIST SP 800-40 Rev. 4: Guide to Enterprise Patch Management Planning.
- Microsoft Security Update Guide: Exploitability Index.
- MITRE ATT&CK: T1190 Exploit Public-Facing Application, T1133 External Remote
  Services, T1068 Exploitation for Privilege Escalation, T1210 Exploitation of Remote
  Services.
