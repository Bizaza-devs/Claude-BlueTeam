---
description: "Extract, normalise, defang, enrich and pivot on indicators (IPs, domains, URLs, hashes, emails, file paths, registry keys); produce a sweep plan and case-ready CSV. Usage: /ioc extract <text|file> | /ioc enrich <indicator> | /ioc sweep [--platform kql|spl|esql] [--case <case-folder>]"
argument-hint: "extract <text|file> | enrich <indicator> | sweep [--platform kql|spl|esql] [--case <case-folder>]"
---

# /ioc

Indicators are cheap to collect and expensive to get wrong. This command turns raw
text (reports, alerts, sandbox output) into a clean, defanged, de-duplicated,
confidence-rated list, enriches it passively, and sweeps the environment for it.

Input: `$ARGUMENTS`

## Usage

```
/ioc extract intel/vendor-report.txt
/ioc extract "<paste alert or report text>"
/ioc enrich 203.0.113.45
/ioc enrich hxxps://login-contoso[.]example/auth
/ioc sweep --platform kql --case cases/2026-11-25-payroll-phish
```

## Skills to load

- Always: `threat-intel-ioc`
- Sweeps: `kql-sentinel-defender`, `spl-splunk`, `elastic-eql-esql`
- Network indicators in packet/flow data: `network-detection-suricata-zeek`
- Hashes and file artefacts: `malware-triage`, `yara-rules`

## Defanging (mandatory in every output and every case file)

| Type | Raw | Defanged |
|---|---|---|
| URL | `https://evil.example/path` | `hxxps://evil[.]example/path` |
| Domain | `evil.example` | `evil[.]example` |
| IPv4 | `203.0.113.45` | `203.0.113[.]45` |
| IPv6 | `2001:db8::1` | `2001[:]db8[:][:]1` |
| Email | `ceo@evil.example` | `ceo[@]evil[.]example` |

Hashes, file paths, registry keys, mutexes and user agents are not defanged. Refang
only inside a query that needs the literal value, and say so. Never make an indicator
clickable (no Markdown links).

## Evidence gate

- Every indicator carries its **source** (report, alert ID, sandbox run, case artefact)
  and a **confidence** (High / Medium / Low). No source, no entry.
- An indicator is not "malicious" because it appeared in a report: shared hosting,
  CDN, cloud provider and sinkhole IPs, popular domains and legitimate tools are
  context, not verdicts. Flag them as `low` / `context`.
- A sweep "no hits" result states the sources and time range searched.

## Procedure - extract

1. Pull candidates with patterns for IPv4/IPv6, domains, URLs, emails, MD5/SHA1/SHA256,
   Windows paths, registry keys, CVE IDs (as context only).
2. **Refang to normalise, then de-duplicate**, lower-case domains, strip trailing dots.
3. **Drop noise:** RFC 1918 / documentation / loopback ranges (unless internal context
   matters), the report publisher's own domains, well-known benign domains, version
   strings mistaken for IPs.
4. Classify role: delivery, C2, exfil destination, payload, staging, actor infra, victim/internal.
5. Assign confidence and TLP (inherit the source's TLP; default TLP:AMBER for case data).

## Procedure - enrich (passive only)

- IP: ASN and owner, geolocation (as a hint, not proof), hosting type, passive DNS,
  first/last seen in internal logs.
- Domain: registration date (RDAP), registrar, name servers, passive DNS history,
  certificate transparency, similarity to the organisation's brands.
- Hash: prevalence internally, multi-engine reputation, signer, first-seen.
- URL: reputation lookups by value. **Do not fetch the URL.** Sandbox only via the
  organisation's approved service and only if TLP allows submission.
- Pivot: shared infrastructure (same IP, name server, certificate, registrant
  pattern) - mark pivoted indicators as lower confidence than the seed.

## Procedure - sweep

Write one labelled query per indicator type for the chosen platform, over the full
retention or the incident window, e.g. Sentinel/Defender `DeviceNetworkEvents`
(`RemoteIP`, `RemoteUrl`), `DnsEvents`, `DeviceFileEvents` (`SHA256`), `EmailUrlInfo`,
`CommonSecurityLog`; Splunk proxy/DNS/EDR sourcetypes; ECS `destination.ip`,
`dns.question.name`, `url.domain`, `file.hash.sha256`. Batch indicators with a
watchlist / lookup table rather than giant inline lists. Note index names to tune.

## Output format

```markdown
## IOC set: <name>   (source: <report / case>, TLP:<...>, generated <UTC>)
| type | value_defanged | role | first_seen_utc | last_seen_utc | source | confidence | tlp | notes |
|---|---|---|---|---|---|---|---|---|
| domain | login-contoso[.]example | credential harvest | 2026-11-24T08:12:00Z | 2026-11-25T07:40:00Z | phish msg 4411 | high | AMBER | registered 2 days before campaign |

### Dropped as noise (and why)
### Sweep queries (labelled, with tuning notes) and results: hits per indicator, hosts, users
```

## Case integration

With an active case, append rows to `iocs.csv` using exactly its header
`type,value_defanged,first_seen_utc,last_seen_utc,source,confidence,tlp,notes`
(skip `role`, put it in `notes`). Update `last_seen_utc` by adding a new row with a note
rather than silently editing history. Sweep hits go to `timeline.csv`.

## Gates and safety

- No live interaction with attacker infrastructure (no browsing, no scanning, no
  emailing). Blocking indicators is a containment action: `/contain`, with approval.
- Respect TLP when sharing; TLP:RED stays with named recipients.
