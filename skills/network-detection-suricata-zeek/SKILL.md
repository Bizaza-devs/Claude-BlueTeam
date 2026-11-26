---
name: network-detection-suricata-zeek
description: Network detection and hunting with Suricata IDS/IPS rules and Zeek logs. Covers Suricata rule anatomy (action, protocol, header, flow, content modifiers, pcre, sticky buffers http.uri, http.user_agent, tls.sni, tls.cert_subject, dns.query, file.data, ja3.hash and JA4 where supported, threshold, detection_filter, flowbits), offline PCAP testing with eve.json, and Zeek hunting in conn.log (long connections, scans, byte ratios), dns.log (DGA, NXDOMAIN, tunnelling), http.log (rare user agents, POST to raw IPs), ssl.log / x509.log (self-signed certs, SNI, JA3/JA4), files.log and notice.log, with zeek-cut and jq one-liners and pointers to RITA-style beacon analysis. Use when asked to "write a Suricata rule", "detect this C2 on the network", "hunt in Zeek logs", "test a rule against a pcap", or "tune Suricata alerts".
---

# Network detection with Suricata and Zeek

Suricata tells you that a packet stream matched a pattern; Zeek tells you what
every connection looked like. Use Suricata for known-bad signatures and Zeek
for behaviour, baselining and hunting - and use the Zeek `uid` / Suricata
`flow_id` / community ID to pivot between them and the endpoint.

## When to use

- A C2 profile, exploit or malware traffic pattern from an incident needs a network signature.
- Hunting for beacons, tunnelling, exfiltration or rogue services in Zeek data.
- Tuning a noisy Suricata ruleset (ET Open/Pro or local rules).
- Validating a rule against a PCAP from a sandbox or incident.

## Ground rules

- **A network alert is not a host compromise.** Before a TP verdict, tie the
  flow to a host and process (EDR network events, DHCP/asset data) or show the
  payload/response proving success (e.g. 200 OK with a payload, not a blocked request).
- **Every new rule is tested twice:** against a PCAP containing the traffic
  (must alert) and against at least a day of representative production traffic
  or PCAP (expected volume recorded) - plus the 30-day baseline in the SIEM
  where Suricata/Zeek logs land (`detection-engineering`).
- **Encrypted traffic limits content matching.** Say explicitly when a rule can
  only see SNI/certificate/JA3/JA4 metadata, not payload.
- **Know your sensor coverage.** State which segments, which direction and what
  packet loss (Zeek `capture_loss.log`, Suricata `stats.log` drops) apply to any
  "not seen" claim.
- **Blocking (IPS `drop`/`reject`) is a production change** - requires change
  approval and an alert-only soak period first.
- PCAPs contain personal data and credentials: handle under `evidence-handling`.

## Workflow

1. Get the traffic: PCAP from sandbox/incident, or Zeek/Suricata logs around the event.
2. Identify the protocol and the most stable distinguishing feature: URI
   pattern, header order/value, SNI, certificate fields, JA3/JA4, DNS name
   structure, byte pattern in a binary protocol.
3. Write the rule with the right sticky buffer and `flow` direction; anchor
   content (`startswith`, `endswith`, `depth`, `bsize`) for precision and speed.
4. Test against the PCAP offline; check `eve.json` for the alert and fields.
5. Run against normal traffic; tune; add `threshold` if repeats are expected.
6. Deploy as alert-only; review a week of alerts; consider IPS drop only with approval.
7. For hunting, query Zeek logs (below) and hand beacon candidates to `hunt-c2-beaconing`.

## Suricata rule anatomy

```
action proto src_ip src_port direction dst_ip dst_port (options;)
alert  http  $HOME_NET any   ->        $EXTERNAL_NET any (msg:"..."; ...; sid:1000001; rev:1;)
```

- **Actions:** `alert`, `pass`, `drop` (IPS), `reject`, `rejectsrc`, `rejectdst`, `rejectboth`.
- **Protocols:** `tcp`, `udp`, `icmp`, `ip`, and app-layer `http`, `tls`, `dns`, `smb`, `ssh`, `ftp`, `smtp`, `krb5`, `quic` (support depends on version/build).
- **Direction:** `->` or `<>`. Use variables (`$HOME_NET`, `$EXTERNAL_NET`, `$HTTP_PORTS`) from `suricata.yaml`.
- **Required meta:** `msg`, `sid` (local rules: 1000000-1999999), `rev`; add `classtype`, `reference`, `metadata` (e.g. `created_at`, `mitre_technique_id`).

### Key options

| Option | Purpose |
|---|---|
| `flow:established,to_server;` | match only on established sessions, client->server (`to_client` for responses) |
| `content:"...";` | byte/string match; hex inside pipes: `content:"|0d 0a|";` |
| `nocase; depth:N; offset:N; distance:N; within:N;` | content modifiers (position relative to buffer start / previous match) |
| `startswith; endswith; bsize:N;` | anchor to buffer start/end; exact buffer size |
| `fast_pattern;` | choose the content used for the prefilter (pick the rarest) |
| `pcre:"/regex/i";` | regex on the current sticky buffer; always pair with a `content` prefilter |
| Sticky buffers | `http.method`, `http.uri`, `http.uri.raw`, `http.host`, `http.user_agent`, `http.header`, `http.cookie`, `http.request_body`, `http.stat_code`, `http.response_body`, `tls.sni`, `tls.cert_subject`, `tls.cert_issuer`, `tls.cert_serial`, `dns.query`, `file.data`, `file.name`, `ja3.hash`, `ja3s.hash` |
| JA4 | newer Suricata releases add `ja4.hash` when built with JA4 support - confirm with `suricata --list-keywords` |
| `threshold:type limit, track by_src, count 1, seconds 3600;` | limit/threshold/both alert rate |
| `detection_filter:track by_src, count 20, seconds 60;` | alert only after N matches (brute force) |
| `flowbits:set,name; flowbits:isset,name; flowbits:noalert;` | multi-step logic within a flow |
| `dsize:>500;` | payload size (packet-level) |

JA3 hashing must be enabled in `suricata.yaml` (`app-layer.protocols.tls.ja3-fingerprints`)
on versions where it is not on by default.

### Example rules

```suricata
# 1. HTTP C2 check-in: POST to a fixed URI pattern with a distinctive User-Agent (T1071.001)
# Tune: verify UA is not used by internal software; adjust URI anchor
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"LOCAL ExampleLoader HTTP check-in"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/api/"; startswith; content:"/check?id="; distance:0; http.user_agent; content:"ExampleAgent/2."; startswith; classtype:trojan-activity; metadata:mitre_technique_id T1071.001, created_at 2026_11_20; sid:1000101; rev:1;)
```

```suricata
# 2. DNS query to a known-bad domain and its subdomains (T1071.004) - domain is a placeholder
# Tune: replace with the incident domain; dotprefix makes ".bad.example" match the apex and any subdomain
alert dns $HOME_NET any -> any any (msg:"LOCAL DNS query for incident domain bad.example"; dns.query; dotprefix; content:".bad.example"; nocase; endswith; classtype:bad-unknown; sid:1000102; rev:1;)
```

```suricata
# 3. TLS to a suspicious SNI on a non-standard port (T1573, T1571)
# Tune: SNI placeholder; consider tls.cert_subject / ja3.hash when SNI is absent or rotated
alert tls $HOME_NET any -> $EXTERNAL_NET !443 (msg:"LOCAL TLS to incident SNI on non-443 port"; flow:established,to_server; tls.sni; content:"update-check.example"; nocase; endswith; classtype:trojan-activity; sid:1000103; rev:1;)
```

```suricata
# 4. Windows PE downloaded over plain HTTP from an external host (T1105)
# Tune: noisy in estates with HTTP software updates - threshold and allowlist update hosts
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"LOCAL PE executable downloaded over HTTP"; flow:established,to_client; file.data; content:"MZ"; startswith; content:"PE|00 00|"; distance:0; within:512; threshold:type limit, track by_dst, count 1, seconds 600; classtype:policy-violation; sid:1000104; rev:1;)
```

```suricata
# 5. Many SSH connection attempts from one source (T1110) - packet-level SYN counting
# Tune: count/seconds; exclude jump hosts and scanners via variables
alert tcp any any -> $HOME_NET 22 (msg:"LOCAL SSH connection burst from single source"; flow:to_server; flags:S,12; detection_filter:track by_src, count 30, seconds 60; classtype:attempted-recon; sid:1000105; rev:1;)
```

```suricata
# 6. Two-step: web request with shell metacharacters in URI, then response contains command output (T1190, T1505.003)
# Tune: strings for your stack; flowbits keeps the first rule silent
alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"LOCAL possible command injection request"; flow:established,to_server; http.uri; content:"cmd="; nocase; pcre:"/cmd=[^&]*(%7C|%3B|%60|\x7c|\x3b|\x60)/i"; flowbits:set,local.cmdinj; flowbits:noalert; sid:1000106; rev:1;)
alert http $HTTP_SERVERS $HTTP_PORTS -> $EXTERNAL_NET any (msg:"LOCAL command injection response with uid= output"; flow:established,to_client; flowbits:isset,local.cmdinj; file.data; content:"uid="; content:"gid="; distance:0; within:40; classtype:web-application-attack; sid:1000107; rev:1;)
```

Domains above (`bad.example`, `update-check.example`) are placeholders under the
reserved `.example` TLD - substitute real indicators from the case.

### Testing rules offline

```bash
# Syntax/config check with only the local rule file
suricata -T -c /etc/suricata/suricata.yaml -S local.rules

# Replay a PCAP (offline mode); -k none ignores bad checksums common in captured traffic
mkdir -p /tmp/suri-out
suricata -c /etc/suricata/suricata.yaml -S local.rules -k none -r case.pcap -l /tmp/suri-out

# Alerts with the fields an analyst needs
jq -c 'select(.event_type=="alert") | {ts:.timestamp, sig:.alert.signature, sid:.alert.signature_id, src:.src_ip, dst:.dest_ip, dport:.dest_port, flow:.flow_id}' /tmp/suri-out/eve.json

# Volume against a benign day of traffic: count per sid
jq -r 'select(.event_type=="alert") | .alert.signature_id' /tmp/suri-out/eve.json | sort | uniq -c | sort -rn
```

Also run `suricata-update` to manage ET rules and `disable.conf`/`modify.conf`
for tuning instead of editing vendor rule files; put per-host suppressions in
`threshold.config` (`suppress gen_id 1, sig_id 1000104, track by_dst, ip 10.20.30.40`).

## Zeek logs and what to hunt

| Log | Key fields | Hunt for |
|---|---|---|
| `conn.log` | `uid`, `id.orig_h`, `id.orig_p`, `id.resp_h`, `id.resp_p`, `proto`, `service`, `duration`, `orig_bytes`, `resp_bytes`, `conn_state`, `history`, `orig_pkts`, `resp_pkts` | long-lived connections (C2, tunnels), periodic connections (beacons), large `orig_bytes` outbound (exfil), `S0`/`REJ` fan-out (scanning), internal hosts talking to many internal hosts on 445/3389/5985 (lateral movement), services on unusual ports |
| `dns.log` | `query`, `qtype_name`, `rcode_name`, `answers`, `TTLs`, `id.orig_h` | DGA (many NXDOMAIN), long/high-entropy subdomains and high TXT/NULL volume (tunnelling), very low TTLs (fast flux), direct DNS to external resolvers bypassing corporate DNS, newly seen domains |
| `http.log` | `method`, `host`, `uri`, `user_agent`, `referrer`, `status_code`, `request_body_len`, `response_body_len`, `resp_mime_types` | rare user agents, `host` is a raw IP, POSTs with large bodies to new hosts, executables (`application/x-dosexec`) downloaded, scripting UAs (`curl`, `python-requests`, `PowerShell`) from user workstations |
| `ssl.log` | `server_name` (SNI), `version`, `cipher`, `established`, `validation_status`, cert-chain fields; `ja3`/`ja4` with the respective packages | self-signed / untrusted certs to external hosts, missing SNI, SNI not matching cert, old TLS versions, rare JA3/JA4 client fingerprints |
| `x509.log` | `certificate.subject`, `certificate.issuer`, `certificate.not_valid_before`, `certificate.not_valid_after`, `san.dns` | default/placeholder subjects, very short or very new validity, issuer == subject, certificates reused across unrelated IPs |
| `files.log` | `fuid`, `mime_type`, `filename`, `source`, `total_bytes`, hashes (`md5`/`sha1`/`sha256` when hashing is enabled), `extracted` | PE/script files over HTTP/SMB, hashes for intel lookup (`threat-intel-ioc`), files transferred over SMB to admin shares |
| `notice.log` | `note`, `msg`, `sub`, `src`, `dst` | `Scan::Port_Scan`, `Scan::Address_Scan` (if scan policy loaded), `SSL::Invalid_Server_Cert`, `SSH::Password_Guessing`, capture loss notices |
| `weird.log` / `capture_loss.log` | `name` / `percent_lost` | protocol anomalies; sensor health before trusting absence |

Field names vary slightly across Zeek versions and loaded packages (e.g.
cert-chain and file-host fields changed in recent releases); check `#fields`
in your log headers.

### Zeek one-liners

```bash
# Longest connections (C2 / tunnels) - TSV logs with zeek-cut
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto service duration | sort -t$'\t' -k6 -rn | head -20

# Top outbound byte senders to external hosts (exfil candidates) - tune internal ranges
cat conn.log | zeek-cut id.orig_h id.resp_h orig_bytes | awk -F'\t' '$2 !~ /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)/ && $3 != "-" {b[$1" "$2]+=$3} END {for (k in b) print b[k], k}' | sort -rn | head -20

# Hosts with many failed/unanswered connection attempts (scanning)
cat conn.log | zeek-cut id.orig_h conn_state | awk -F'\t' '$2=="S0" || $2=="REJ" {c[$1]++} END {for (h in c) print c[h], h}' | sort -rn | head

# NXDOMAIN count per client (DGA) and longest queries (tunnelling)
cat dns.log | zeek-cut id.orig_h rcode_name | awk -F'\t' '$2=="NXDOMAIN" {c[$1]++} END {for (h in c) print c[h], h}' | sort -rn | head
cat dns.log | zeek-cut query | awk '{print length($0), $0}' | sort -rn | uniq | head -20

# Rare user agents
cat http.log | zeek-cut user_agent | sort | uniq -c | sort -n | head -30

# Self-signed / failed validation certificates by SNI (requires validate-certs policy)
cat ssl.log | zeek-cut id.orig_h id.resp_h server_name validation_status | grep -v -e 'ok$' | sort | uniq -c | sort -rn | head

# JSON logs: executables seen in files.log
jq -c 'select(.mime_type=="application/x-dosexec") | {ts, fuid, source, filename, sha1}' files.log
```

Timestamps: `zeek-cut -d ts` converts epoch to readable time. In a SIEM, the
same hunts translate to `stats` over the Zeek sourcetype/index (`spl-splunk`,
`kql-sentinel-defender`, `elastic-eql-esql`).

### Beacon analysis

Periodic connections with low jitter, consistent sizes and long overall
duration are the classic beacon signature. RITA (Active Countermeasures) scores
beacons, long connections, DNS tunnelling and threat-intel hits from Zeek logs.
The full method - scoring interval regularity, data-size consistency, jitter
handling and allowlisting - is in `hunt-c2-beaconing`; exfiltration volume
analysis is in `hunt-exfiltration`.

## False positives & benign look-alikes

| Signal | Benign source | Distinguish by |
|---|---|---|
| Periodic connections | Update agents, EDR/AV cloud, monitoring, NTP, M365/Teams | Known vendor ASN/SNI, signed process on host, fleet-wide prevalence |
| Long connections | VPN, video calls, websockets, backups | Destination ownership, bytes pattern, business hours |
| Self-signed certs | Internal appliances, printers, iLO/iDRAC, dev servers | Internal destination, asset inventory |
| Long DNS names | CDN, AV reputation lookups, cloud telemetry | Registered domain reputation, many hosts, stable rate |
| PE over HTTP | Legacy software updates, internal package mirrors | Update servers on an allowlist, signed binaries |
| Rare user agents | Niche business apps, scripts in IT automation | Source host role, owner confirmation |

| Verdict | Evidence |
|---|---|
| True Positive | Network match + host/process attribution + malicious content or behaviour confirmed |
| Benign True Positive | Pattern real but sanctioned (pentest, scanner, admin tool) |
| False Positive | Rule matched unrelated traffic (content too short, wrong buffer, missing flow direction) |
| Needs more data | No host attribution, encrypted payload only, sensor loss during window |

## Pitfalls

- Short `content` (< 4 bytes) or no `fast_pattern` choice - slow and noisy.
- `pcre` without a `content` prefilter - evaluated on every buffer.
- Unescaped `;`, `"` or `\` inside `content`/`pcre`/`msg` values break rule parsing -
  escape them or use hex (`|3b|` in content, `\x3b` in pcre).
- Using legacy content modifiers (`http_uri;` after content) mixed with sticky
  buffers - pick the sticky-buffer style consistently.
- Missing `flow` direction - matches responses and requests alike.
- Rules for HTTP that never see traffic because TLS is not decrypted.
- Asymmetric routing / SPAN drops - Suricata misses half the session; check stats.
- Trusting a domain-based rule after the adversary rotates infrastructure -
  pair IOC rules (expiry date in `metadata`) with behavioural ones.
- Zeek's `orig_bytes`/`resp_bytes` can be `-` (unknown) for some states - handle in scripts.

## Output

- Suricata rule(s) with SID/rev, metadata, test evidence (PCAP alert output and
  benign-traffic volume), tuning notes and deployment mode (alert vs drop, with approval).
- Zeek hunt results: query used, time range, sensor coverage, candidate list
  with host attribution and verdicts.
- Hand-offs: `hunt-c2-beaconing`, `hunt-exfiltration`, `hunt-lateral-movement`,
  `threat-intel-ioc` (indicators), `alert-triage`, `incident-response`,
  `detection-engineering` for versioning and review.

## References

- Suricata User Guide: rules format, HTTP/TLS/DNS keywords, file keywords, thresholding, flowbits, eve.json output
- Zeek documentation: log files reference (conn, dns, http, ssl, x509, files, notice, weird), `zeek-cut`
- Emerging Threats rule conventions (SID ranges, metadata)
- Active Countermeasures RITA documentation
- JA3 (Salesforce) and JA4+ (FoxIO) fingerprint specifications
- MITRE ATT&CK: https://attack.mitre.org/techniques/T1071/, https://attack.mitre.org/techniques/T1048/
