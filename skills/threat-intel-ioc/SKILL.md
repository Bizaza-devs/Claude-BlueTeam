---
name: threat-intel-ioc
description: Defensive threat intelligence and indicator (IOC) handling. Covers the IOC lifecycle (extract, validate, enrich, score, deploy, age out), defanging (hxxp, [.]), enrichment with VirusTotal, AbuseIPDB, Shodan, Censys, urlscan.io, GreyNoise, MISP, OpenCTI, WHOIS/RDAP, certificate transparency and passive DNS, OPSEC and privacy (do not tip off the attacker, do not upload client files, TLP 2.0 CLEAR/GREEN/AMBER/AMBER+STRICT/RED), pivoting (domain -> IP -> certificate -> infrastructure), confidence and indicator decay, Pyramid of Pain, STIX 2.1 objects and patterns, TAXII, turning intel into detections and retro-hunting historical logs. Use when asked to "/ioc these indicators", enrich or pivot on an IP/domain/hash, share intel with partners, load a feed, or check whether an IOC from a report was seen in our logs.
---

# Threat intel & IOC handling

## When to use

- An alert, phishing email, malware sample or vendor report produced indicators that
  need extraction, enrichment, scoring, sharing or deployment.
- A partner/ISAC/CERT shared indicators and the question is "have we seen these?"
  (retro-hunt) and "should we block them?"
- Building or cleaning a TI feed / MISP / OpenCTI instance and its ageing rules.

Not for: analysing the malware itself (`malware-triage`), phishing message analysis
(`phishing-analysis`), or writing behaviour-based detections (`detection-engineering`).

## Ground rules

- **Passive before active.** Enrich via third-party datasets (passive DNS, CT logs,
  scan datasets, reputation APIs) before anything that touches attacker
  infrastructure. Never browse, scan or connect to attacker infrastructure from
  corporate IP space; if active interaction is approved, use an isolated, attributable-
  to-nobody analysis environment.
- **Do not leak victim data.** Never upload client/internal files, emails or
  documents to public services (VirusTotal upload, public urlscan) without the data
  owner's approval; search by hash first. URLs can carry tokens and email addresses:
  scrub them or use private scans.
- **Respect TLP.** Handle and forward intel exactly as its TLP marking allows; mark
  everything you produce.
- **No block on a single unvetted source.** An indicator goes to blocking only with a
  confidence score, a source, a first/last-seen date and a check against allowlists
  (top domains, CDNs, cloud ranges, your own assets). Blocking a CDN IP or a shared
  host takes down legitimate business.
- **An IOC hit is a lead, not a verdict.** A match in logs needs `alert-triage`-style
  corroboration (process, user, timing, volume) before it is called a compromise.

## Workflow

1. **Extract** indicators from the source (report, alert, email, sandbox output);
   normalise (lowercase domains, strip ports/paths where appropriate, full hashes).
2. **Defang for transport**, refang only inside tools.
3. **Validate**: remove RFC1918/reserved, your own ranges, well-known benign
   (warninglists), sinkholes, documentation ranges; flag shared infrastructure
   (CDNs, cloud, free hosting, URL shorteners).
4. **Enrich** passively (table below); record what each source said and when.
5. **Score** confidence and decide the use: block / alert / hunt-only / context.
6. **Retro-hunt** across retention (DNS, proxy, firewall, EDR, mail, cloud logs).
7. **Deploy** to controls with an expiry; **share** with the right TLP.
8. **Age out** on schedule; record hits and false positives back into the platform.

## Defanging conventions

| Type | Live | Defanged |
|---|---|---|
| URL scheme | `http://`, `https://` | `hxxp://`, `hxxps://` |
| Domain / IP dot | `evil.example.com`, `198.51.100.7` | `evil[.]example[.]com`, `198.51.100[.]7` |
| Email | `user@example.com` | `user[@]example[.]com` |
| Port / colon (optional) | `:8443` | `[:]8443` |

Hashes are not defanged. Use documentation ranges (RFC 5737: 192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24) and `example.com`-style domains (RFC 2606) in
templates, training and tests.

```python
# Minimal refang for tool input (never refang in reports or chat)
import re
def refang(s): return re.sub(r'\[\.\]', '.', s).replace('hxxp', 'http').replace('[@]', '@').replace('[:]', ':')
```

## Enrichment sources and OPSEC

| Source | Use | OPSEC / privacy note |
|---|---|---|
| VirusTotal | Hash/URL/domain/IP reputation, relations, first-seen | Uploading files/URLs shares them with VT users; search by hash first; attackers monitor VT for their samples |
| AbuseIPDB | Crowd-sourced abuse reports for IPs | Reports are noisy; age and category matter |
| Shodan / Censys | Open ports, banners, TLS certs, historical scans | Passive (their scans); good for pivots on certs/banners |
| urlscan.io | Page rendering, redirects, requested resources, similar pages | Set visibility to *private* or *unlisted*; public scans are searchable by anyone incl. the attacker |
| GreyNoise | Is this IP mass-scanning the internet (noise) or a known benign service | Distinguishes background noise from targeted activity |
| Passive DNS (e.g. DomainTools/Farsight DNSDB, CIRCL, SecurityTrails) | Historical resolutions, co-hosted domains | Licensing; data gaps |
| WHOIS / RDAP | Registrar, dates, (often redacted) registrant | Registration date is a strong signal for new domains |
| Certificate transparency (e.g. crt.sh) | Certificates and SANs for a domain, new lookalikes | Passive |
| MISP / OpenCTI | Internal/community intel, correlations, sightings | Respect sharing groups and TLP |
| Sandbox reports | Network IOCs from detonation | Detonation can contact C2: use isolated egress |

## TLP 2.0 (FIRST)

| Label | May share with |
|---|---|
| TLP:RED | Named recipients only, not further |
| TLP:AMBER+STRICT | Recipient's organisation only |
| TLP:AMBER | Recipient's organisation and its clients/partners who need to know to protect themselves |
| TLP:GREEN | Recipient's community, not public |
| TLP:CLEAR | Public (replaces TLP:WHITE) |

Mark the whole document and, where needed, individual sections. Incident data with
client names or PII is at least TLP:AMBER regardless of the IOC itself.

## Pivoting methodology

1. Start from a high-confidence seed (C2 domain from sandbox + EDR telemetry).
2. Domain -> passive DNS resolutions (time-bounded) -> IPs.
3. IP -> other domains resolving there **in the same time window** -> filter out
   shared hosting/CDN.
4. Domain/IP -> TLS certificate (serial, subject, SANs, issuer, validity) -> other
   hosts presenting the same certificate (Shodan/Censys).
5. Server fingerprints: JARM/JA3S/JA4 families, HTTP headers, favicon hash, distinctive
   page titles/paths -> candidate infrastructure.
6. Registration patterns: registrar, name servers, creation time clustering.
7. Validate each pivot with a **second independent attribute** before adding it to the
   cluster; record the pivot chain (seed -> attribute -> result -> confidence).

Stop pivoting when an attribute is shared by many unrelated parties (Cloudflare IPs,
Let's Encrypt issuer alone, default web server banners, parked-domain name servers).

## Confidence and ageing

Score each indicator (example scheme, adapt to your platform):

| Confidence | Evidence |
|---|---|
| High | Seen in your incident telemetry or a detonated sample's confirmed C2, plus a second source |
| Medium | Reputable vendor/CERT report with context, not seen locally |
| Low | Single crowd-sourced/reputation source, no context |

Typical decay (tune to your feeds; MISP supports decay models):

| Type | Pyramid of Pain level | Useful life (rule of thumb) | Use |
|---|---|---|---|
| File hash | Trivial for attacker to change | Long (hash never becomes benign) but low reuse | Alert/hunt; block if malicious verdict |
| IP address | Easy | Days to weeks (cloud/VPS reassigned) | Alert/hunt; block only with high confidence and short expiry |
| Domain | Simple | Weeks to months; check for expiry/sinkhole | Block/alert if newly registered and confirmed |
| URL | Simple | Short | Proxy block, mail purge |
| Network/host artifacts (URI pattern, JA4, mutex, named pipe) | Annoying | Months | Detection logic |
| TTPs | Tough | Years | `detection-engineering` behaviour rules |

Push effort up the Pyramid of Pain: every incident should yield at least one
behavioural detection, not just a hash list.

## STIX 2.1 basics

- SDOs used most: `indicator`, `malware`, `threat-actor`, `intrusion-set`,
  `campaign`, `attack-pattern`, `infrastructure`, `report`, `identity`,
  `vulnerability`, `course-of-action`, `observed-data`, `note`.
- SCOs: `ipv4-addr`, `ipv6-addr`, `domain-name`, `url`, `file`, `email-addr`,
  `x509-certificate`, `network-traffic`.
- SROs: `relationship` (e.g. indicator *indicates* malware), `sighting` (seen where/when).
- Transport: TAXII 2.1 collections. Marking: `marking-definition` for TLP.

```json
{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--<uuid4>",
  "created": "2026-01-15T10:00:00.000Z",
  "modified": "2026-01-15T10:00:00.000Z",
  "name": "C2 domain from case 2026-001",
  "indicator_types": ["malicious-activity"],
  "pattern": "[domain-name:value = 'c2.example.net']",
  "pattern_type": "stix",
  "valid_from": "2026-01-15T10:00:00Z",
  "valid_until": "2026-04-15T10:00:00Z",
  "confidence": 80,
  "labels": ["case-2026-001"]
}
```

Set `valid_until` so consumers age the indicator out; replace `<uuid4>` with a real
UUIDv4 and attach the TLP marking definition your sharing community uses.

## Retro-hunting

Search the full retention window, not just the last 24 h. Record the time range and
data sources searched, including the ones that do not exist (gaps).

```kql
// Defender XDR / Sentinel: network and file hits for an IOC list (replace values; tune tables to what you ingest)
let ips = dynamic(["198.51.100.7", "203.0.113.20"]);
let domains = dynamic(["c2.example.net", "update-check.example.org"]);
let hashes = dynamic(["<sha256-1>", "<sha256-2>"]);
union
 (DeviceNetworkEvents | where RemoteIP in (ips) or RemoteUrl has_any (domains)
   | project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemoteUrl, Hit="network"),
 (DeviceFileEvents | where SHA256 in (hashes)
   | project Timestamp, DeviceName, FolderPath, FileName, SHA256, Hit="file"),
 (DeviceProcessEvents | where SHA256 in (hashes)
   | project Timestamp, DeviceName, FileName, ProcessCommandLine, SHA256, Hit="process")
| order by Timestamp asc
```

~~~spl
```Splunk: DNS and proxy hits for IOC domains (index/sourcetypes and lookup are local)```
| inputlookup ioc_domains.csv
| fields domain
| join type=inner domain
    [ search index=dns OR index=proxy earliest=-90d
      | eval domain=lower(coalesce(query, dest_host, url_domain))
      | fields _time domain src_ip user ]
| stats min(_time) as first max(_time) as last count by domain src_ip user
~~~

- Prefer DNS and proxy logs for domains (EDR may only see IPs behind CDNs).
- For mail IOCs, search message trace / `EmailEvents` and `EmailUrlInfo` and purge
  with approval (`ir-bec-m365`, `phishing-analysis`).
- A hit before the incident start date moves the timeline: tell the incident lead.

## Writing intel into detections

- **Atomic IOCs** to controls with expiry: EDR custom indicators (file hash, IP,
  URL/domain, certificate) with action alert or block; proxy/DNS blocklists; mail
  blocklists. Microsoft Sentinel stores TI in its threat-intelligence tables (legacy
  `ThreatIntelligenceIndicator`, newer `ThreatIntelIndicators` / `ThreatIntelObjects`;
  check which your workspace populates) and ships TI-matching analytics rules.
- **Behavioural intel** (TTPs from the report) to `detection-engineering` /
  `sigma-rules`, mapped to ATT&CK.
- Every deployed indicator links back to the source report/case so hits can be triaged.

## False positives & benign look-alikes

- IPs of CDNs, cloud providers, Tor exits, VPN providers and shared hosting appear in
  reports but also serve legitimate traffic: context-only unless the full URL/host matches.
- Sinkholed domains: post-takedown resolutions point to researchers' sinkholes;
  hits are infected hosts beaconing, not new infrastructure (still worth triage).
- Hashes of legitimate tools abused by attackers (PsExec, AnyDesk, rclone): a hit
  shows usage, not maliciousness; context decides.
- Vendor reports listing benign domains contacted by malware for connectivity checks
  (e.g. major search/OS update domains): filter with warninglists.
- Reputation "malicious" on an IP owned by a large ISP/NAT gateway means some user
  behind it misbehaved.

## Pitfalls

- Blocking an entire IOC dump from a report without validation (outage via a CDN IP).
- Public urlscan/VT submission of a URL containing a victim's email or session token.
- Treating absence of IOC hits as absence of compromise: attackers rotate infrastructure
  per victim. Hunt the behaviour too (`hunt-dispatch`).
- Never-expiring indicators that turn the blocklist into noise and slow matching.
- Pivoting on a shared attribute and "attributing" unrelated infrastructure to the actor.
- Forwarding TLP:AMBER+STRICT intel to a vendor or MSSP without permission.

## Output

- IOC table: type, value (defanged), source, first/last seen, confidence, TLP,
  recommended action (block/alert/hunt/context), expiry, related case.
- Enrichment notes with pivot chain and the sources queried (with timestamps).
- Retro-hunt result: data sources and time range searched, hits, gaps.
- STIX 2.1 bundle or MISP event for sharing; detection requests to
  `detection-engineering`; hits to `alert-triage` / `incident-response`.
  `/ioc` runs this workflow.

## References

- MITRE ATT&CK: TA0042 Resource Development (T1583 Acquire Infrastructure,
  T1584 Compromise Infrastructure), TA0011 Command and Control (T1071, T1568 Dynamic
  Resolution, T1090 Proxy).
- FIRST: Traffic Light Protocol (TLP) 2.0 definitions and usage.
- OASIS: STIX Version 2.1 and TAXII Version 2.1 specifications.
- David Bianco: "The Pyramid of Pain".
- MISP Project documentation (warninglists, decaying models, taxonomies);
  OpenCTI documentation.
- NIST SP 800-150: Guide to Cyber Threat Information Sharing.
- IETF RFC 5737 (IPv4 documentation addresses), RFC 2606 (reserved example domains).
