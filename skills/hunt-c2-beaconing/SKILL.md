---
name: hunt-c2-beaconing
description: Hypothesis-driven hunt for command-and-control traffic. Covers beacon statistics (connection count, mean interval, standard deviation, coefficient of variation, Bowley skew), the RITA / AC-Hunter approach, Zeek conn.log, ssl.log, http.log and dns.log analysis, long connections, DNS tunnelling (subdomain length, entropy, TXT volume, NXDOMAIN rates), DNS-over-HTTPS, JA3/JA3S/JA4 TLS fingerprints, rare user-agents, newly observed and newly registered domains, C2 over legitimate services (cloud storage, Slack, Teams, Telegram, Discord APIs, tunnels such as ngrok) and CDN / domain-fronting signs. Maps to T1071, T1071.004, T1573, T1572, T1102, T1568, T1090.004. Use when asked to "hunt for beaconing", "find C2", "look for DNS tunnelling", "check Zeek for periodic connections", "run RITA", or when an intel report names a C2 framework.
---

# Hunt: C2 beaconing and covert channels

## When to use

- Proactive network hunt across an estate with Zeek / Corelight, NDR, proxy, firewall or EDR network telemetry.
- Intel names a C2 framework, a domain family or a TLS fingerprint and you need to know if it is present.
- An alert (EDR, IDS, DNS firewall) hints at one host; you want to know whether the pattern is wider.
- After containment, to prove a C2 channel is really gone (re-run the same queries on the post-containment window).

Not for: writing the final IDS signature (hand off to `network-detection-suricata-zeek`), or enriching a single IOC (`threat-intel-ioc`, `/ioc`).

## Ground rules

- **Periodicity alone is not C2.** No TP verdict on a beacon score without (a) the process or device that owns the traffic and (b) one corroborating signal: destination reputation/age, rare TLS fingerprint, rare user-agent, payload size pattern, or host-side artefact.
- **Name the time window and data coverage** in every claim. "No beaconing found" is only valid for the sensors, VLANs and days actually queried. Check sensor gaps (Zeek `capture_loss.log`, missing days) before saying "absent".
- **Never contact suspected C2 from a production or analyst host.** Passive enrichment only (passive DNS, WHOIS, certificate transparency, sandbox reports). Active probing belongs in an isolated analysis environment with approval.
- **Blocking a destination is a containment action** (`/contain`): it tips off the operator and can break business traffic. Requires incident-commander approval; capture full PCAP or at least extended Zeek logs for the pair first.
- **Every threshold below is a starting point** - record the values you used in the hunt report so the hunt is reproducible.

## Workflow

1. **Frame the hypothesis** (templates below) and pick the window: 24 h minimum for beacon maths, 7 days preferred for slow beacons (sleep > 10 min).
2. **Confirm data coverage**: which sensors/proxies see egress, is TLS inspected, is DNS logged at the resolver *and* at the edge, are timestamps UTC and in sync.
3. **Reduce the haystack**: drop internal-to-internal, known update/CDN/SaaS destinations (allowlist maintained, versioned), and broadcast/multicast. Keep the allowlist small - attackers live in big SaaS too.
4. **Score periodicity** per (source, destination, port) pair: count, mean/median interval, std-dev, CV, Bowley skew, MAD. Also score data-size consistency.
5. **Stack the survivors** by rarity: how many internal hosts talk to this destination? Beacons to a destination only 1-3 hosts use rank highest.
6. **Enrich** the top 20-50: domain age, passive DNS, certificate issuer/validity, JA3/JA4, user-agent, ASN/hosting type, process name from EDR.
7. **Pivot to the host**: owning process, its parent, signer, path, persistence (`hunt-windows-persistence`, `hunt-linux-persistence`), and lateral activity (`hunt-lateral-movement`).
8. **Verdict** with the decision table; escalate per criteria; feed confirmed patterns to `detection-engineering`.

## Hypothesis templates

- "A host in <segment> is beaconing over HTTPS to infrastructure first seen in our environment in the last 30 days, at a regular interval with < 20 % jitter."
- "An implant uses DNS as transport: one internal client issues high volumes of unique, long subdomains (or TXT queries) under a single registered domain."
- "A non-browser process uses a legitimate web service (Telegram/Discord/Slack API, cloud storage, paste site, tunnelling service) as a C2 or dead-drop channel."
- "A process bypasses corporate DNS by using DNS-over-HTTPS to a public resolver."
- "A TLS client fingerprint (JA3/JA4) associated with <framework> appears on hosts where that client software is not installed."
- "A long-lived (hours) outbound session with low byte counts exists to a non-corporate destination (interactive tunnel or reverse proxy)."

## ATT&CK sub-technique map

| Behaviour | Technique |
|---|---|
| HTTP(S) C2 | T1071.001 Application Layer Protocol: Web Protocols |
| DNS C2 / tunnelling | T1071.004 DNS; T1572 Protocol Tunneling |
| Encrypted channel | T1573.001 Symmetric / T1573.002 Asymmetric Cryptography |
| C2 over web services (Telegram, Slack, cloud storage) | T1102.002 Bidirectional Communication; T1102.001 Dead Drop Resolver; T1102.003 One-Way |
| DGA / fast flux | T1568.002 Domain Generation Algorithms; T1568.001 Fast Flux DNS |
| Domain fronting | T1090.004 Proxy: Domain Fronting |
| External proxy / tunnelling service | T1090.002 External Proxy; T1572 |
| Non-standard port | T1571 |
| Non-application protocol (raw TCP/UDP/ICMP) | T1095 |
| Encoding/obfuscation of C2 data | T1132.001, T1001 |
| Commercial remote-access tools as C2 | T1219 |

## Data sources required

| Source | Fields that matter | Notes |
|---|---|---|
| Zeek `conn.log` | `ts uid id.orig_h id.resp_h id.resp_p proto service duration orig_bytes resp_bytes conn_state history` | Core for interval and long-connection maths |
| Zeek `ssl.log` | `server_name version cipher validation_status`, plus `ja3`/`ja3s`/`ja4` if the JA3/JA4 packages are loaded | Field names depend on the package installed - verify locally |
| Zeek `x509.log` | issuer, subject, validity dates | Self-signed / very short-lived certs |
| Zeek `dns.log` | `query qtype_name rcode_name answers TTLs` | Must sit where it sees client queries, not only resolver-to-root traffic |
| Zeek `http.log` | `host uri method user_agent request_body_len response_body_len` | Cleartext or post-TLS-inspection only |
| Proxy (Zscaler, Squid, Blue Coat, etc.) | URL, user-agent, bytes, category, user | Often the only place with user identity |
| EDR network events | `DeviceNetworkEvents` (MDE), Sysmon EID 3 (network connect), EID 22 (DNS query) | Gives the owning process - the decisive pivot |
| Resolver logs | Windows DNS analytic log / Sentinel `DnsEvents`, ASIM `_Im_Dns`, Infoblox, BIND query log | For DNS tunnelling at volume |
| Firewall | `CommonSecurityLog` (CEF), PAN `pan:traffic` | Bytes and duration when Zeek is absent |

## Beacon statistics - what to compute

For each (src, dst, dport) pair, sort timestamps, take deltas `d[i] = t[i] - t[i-1]`, then:

| Metric | Why | Beacon-like |
|---|---|---|
| Connection count `n` | Need enough samples | > 50 per 24 h (tune; slow beacons need longer windows) |
| Mean / median interval | Sleep time | Stable median |
| Std-dev, CV = std/mean | Jitter | CV < 0.2 strong, 0.2-0.5 possible (jittered implants) |
| Bowley skew = (Q1 + Q3 - 2*Q2) / (Q3 - Q1) | Symmetry of interval distribution, robust to outliers | Near 0 |
| MAD (median absolute deviation) | Robust dispersion | Small relative to median |
| Data-size skew / mode share | Same request/response size each check-in | One dominant `orig_bytes` value |
| Distinct hours active | Machine vs human | Activity across all 24 hours incl. nights/weekends |

Jitter of 10-50 % is a configurable option in common frameworks, so do not require CV ~ 0. Combine interval and size scores as RITA does rather than relying on one number.

### RITA / AC-Hunter approach

RITA (Active Countermeasures, open source) ingests Zeek logs and scores beacons from timestamp regularity (Bowley skew, MAD, connection count / dispersion) and data-size regularity, plus long connections, DNS subdomain explosion ("exploded DNS") and threat-intel hits. AC-Hunter is the commercial UI on the same idea.

```bash
# RITA v4.x syntax - imports a day of Zeek logs and lists top beacons
rita import /opt/zeek/logs/2026-11-24 hunt_20261124
rita show-beacons hunt_20261124 -H | head -40          # score, src, dst, conn count, interval stats
rita show-long-connections hunt_20261124 -H | head -20
rita show-exploded-dns hunt_20261124 -H | head -20       # domains with most unique subdomains
# RITA v5.x changed the CLI (e.g. `rita import --database <db> --logs <dir>`, then `rita view <db>`); check `rita --help` for your version.
```

## Queries

### Zeek - interval statistics per pair (bash)

```bash
# Finds periodic TCP pairs in conn.log. Tune: MIN (sample size), proto filter, internal ranges to exclude.
zcat /opt/zeek/logs/2026-11-24/conn.*.log.gz | zeek-cut ts id.orig_h id.resp_h id.resp_p proto \
| awk '$5=="tcp" && $3 !~ /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)/' \
| sort -k2,2 -k3,3 -k4,4n -k1,1n \
| awk -v MIN=50 '{k=$2" "$3" "$4; if(k==pk){d=$1-pt; n[k]++; s[k]+=d; ss[k]+=d*d} pk=k; pt=$1}
  END{for(k in n) if(n[k]>=MIN){m=s[k]/n[k]; v=ss[k]/n[k]-m*m; sd=sqrt(v<0?0:v);
      if(m>0) printf "%s n=%d mean=%.1f sd=%.1f cv=%.3f\n",k,n[k]+1,m,sd,sd/m}}' \
| sort -t= -k5,5n | head -50
```

### Zeek - long connections and data-size regularity (bash)

```bash
# Sessions > 1 h to external hosts; low bytes + long duration suggests an interactive tunnel.
# Zeek logs a connection when it ends - very long sessions may need the conn-long package to appear before close.
zcat conn.*.log.gz | zeek-cut id.orig_h id.resp_h id.resp_p duration orig_bytes resp_bytes \
| awk '$4>3600' | sort -k4,4nr | head -30

# Dominant request size per pair: a single orig_bytes value covering most connections is beacon-like.
zcat conn.*.log.gz | zeek-cut id.orig_h id.resp_h orig_bytes \
| awk '{c[$1" "$2" "$3]++; t[$1" "$2]++} END{for(k in c){split(k,a," "); p=a[1]" "a[2]; if(t[p]>50 && c[k]/t[p]>0.8) print p, "size="a[3], "share="c[k]/t[p]}}'
```

### MDE / Defender XDR - interval statistics with owning process (KQL)

```kql
// Periodic outbound connections per device/process/destination. Tune: window, Conns threshold, CV cut-off, allowlist.
let window = 1d;
DeviceNetworkEvents
| where Timestamp > ago(window)
| where ActionType == "ConnectionSuccess" and RemoteIPType == "Public"
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
| extend Key = strcat(DeviceName, "|", RemoteIP, "|", RemotePort, "|", InitiatingProcessFileName)
| sort by Key asc, Timestamp asc
| extend PrevKey = prev(Key), PrevTs = prev(Timestamp)
| where Key == PrevKey
| extend DeltaSec = datetime_diff('second', Timestamp, PrevTs)
| summarize Conns = count(), MeanSec = avg(DeltaSec), StdSec = stdev(DeltaSec),
            Q1 = percentile(DeltaSec, 25), Q2 = percentile(DeltaSec, 50), Q3 = percentile(DeltaSec, 75),
            Urls = make_set(RemoteUrl, 5)
            by DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName
| extend CV = iff(MeanSec > 0, StdSec / MeanSec, real(null)),
         Bowley = iff(Q3 > Q1, (Q1 + Q3 - 2.0 * Q2) / (Q3 - Q1), 0.0)
| where Conns >= 50 and CV < 0.3 and abs(Bowley) < 0.2
| join kind=leftouter (DeviceNetworkEvents | where Timestamp > ago(window)
    | summarize DevicesToDest = dcount(DeviceName) by RemoteIP) on RemoteIP
| where DevicesToDest <= 3          // rarity stack: few internal hosts use this destination
| order by CV asc
```

### Proxy / firewall - interval statistics (SPL)

```spl
index=proxy sourcetype=<your_proxy_sourcetype> earliest=-24h ```Beacon stats per src/dest from proxy logs. Tune index/sourcetype, field names (CIM Web), thresholds.```
| fields _time src dest
| sort 0 src dest _time
| streamstats current=f last(_time) as prev_time by src dest
| eval delta=_time-prev_time
| where isnotnull(delta)
| stats count as conns avg(delta) as mean stdev(delta) as sd perc25(delta) as q1 median(delta) as q2 perc75(delta) as q3 by src dest
| eval cv=round(sd/mean,3), bowley=if(q3>q1, round((q1+q3-2*q2)/(q3-q1),3), 0)
| where conns>=50 AND cv<0.3 AND abs(bowley)<0.2
| eventstats dc(src) as hosts_to_dest by dest
| where hosts_to_dest<=3
| sort cv
```

### DNS tunnelling (bash on Zeek dns.log)

```bash
# Unique subdomains, mean query length and TXT share per registered domain (naive last-two-labels;
# use a public-suffix-aware parser for co.uk-style TLDs). Tune: thresholds, resolver IP filter.
zcat dns.*.log.gz | zeek-cut id.orig_h query qtype_name rcode_name \
| awk '{n=split($2,p,"."); if(n<3) next; reg=p[n-1]"."p[n]; sub("\\."reg"$","",$2);
        k=$1" "reg; q[k]++; L[k]+=length($2); u[k","$2]=1; if($3=="TXT") t[k]++; if($4=="NXDOMAIN") nx[k]++}
  END{for(x in u){split(x,a,","); uq[a[1]]++}
      for(k in q) if(q[k]>200) printf "%s queries=%d uniq_sub=%d avg_len=%.1f txt=%d nx=%d\n",k,q[k],uq[k],L[k]/q[k],t[k]+0,nx[k]+0}' \
| sort -t= -k3,3nr | head -30

# Shannon entropy of the leftmost label for a suspect domain (> ~3.5-4 bits on long labels is suspicious; baseline first)
zcat dns.*.log.gz | zeek-cut query | grep -F '.suspect-domain.example' | cut -d. -f1 \
| awk '{s=$1; n=length(s); delete c; for(i=1;i<=n;i++) c[substr(s,i,1)]++; e=0;
        for(ch in c){p=c[ch]/n; e-=p*log(p)/log(2)} printf "%.2f %d %s\n", e, n, s}' | sort -nr | head
```

### DNS tunnelling (KQL, ASIM DNS parser in Sentinel)

```kql
// High-cardinality subdomains / TXT / NXDOMAIN per client and registered domain. KQL has no native entropy
// function - use length and unique-count as proxies, compute entropy in a notebook if needed.
_Im_Dns(starttime = ago(1d), endtime = now())
| extend Parts = split(DnsQuery, ".")
| extend N = array_length(Parts)
| where N >= 3
| extend Registered = strcat(tostring(Parts[N-2]), ".", tostring(Parts[N-1])),
         Label = tostring(Parts[0])
| summarize Queries = count(), UniqueSub = dcount(DnsQuery), AvgLabelLen = avg(strlen(Label)),
            TXT = countif(DnsQueryTypeName == "TXT"), NX = countif(DnsResponseCodeName == "NXDOMAIN")
            by SrcIpAddr, Registered
| where UniqueSub > 300 or (AvgLabelLen > 30 and Queries > 100) or TXT > 200
| order by UniqueSub desc
```

### DGA / NXDOMAIN storms (SPL, Sysmon EID 22 or resolver logs)

```spl
index=dns earliest=-24h reply_code=NXDomain ```Hosts with many NXDOMAIN answers across many distinct domains. Tune: index, reply_code field/value (CIM Network_Resolution), threshold.```
| stats count dc(query) as distinct_domains by src
| where distinct_domains>100
| sort - distinct_domains
```

```spl
index=dns earliest=-24h ```Entropy of subdomains with URL Toolbox (ut_parse_extended / ut_shannon macros).```
| eval list="mozilla" | `ut_parse_extended(query,list)` | `ut_shannon(ut_subdomain)`
| stats count avg(ut_shannon) as avg_entropy dc(ut_subdomain) as uniq by src ut_domain
| where uniq>200 AND avg_entropy>3.5
```

### DNS-over-HTTPS (KQL / Zeek)

```kql
// Non-browser processes reaching well-known public DoH endpoints. Tune: resolver list, sanctioned browsers.
let DoH = dynamic(["dns.google","cloudflare-dns.com","mozilla.cloudflare-dns.com","dns.quad9.net","doh.opendns.com","dns.nextdns.io"]);
DeviceNetworkEvents
| where Timestamp > ago(7d) and RemotePort == 443
| where RemoteUrl has_any (DoH) or RemoteIP in ("8.8.8.8","8.8.4.4","1.1.1.1","1.0.0.1","9.9.9.9")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","svchost.exe")
| summarize Conns = count(), Devices = dcount(DeviceName) by InitiatingProcessFileName, InitiatingProcessFolderPath, RemoteUrl
```

```bash
# Zeek ssl.log: who talks TLS to DoH resolvers by SNI
zcat ssl.*.log.gz | zeek-cut id.orig_h server_name | grep -E 'dns\.google|cloudflare-dns\.com|dns\.quad9\.net|doh\.' | sort | uniq -c | sort -nr
```

Windows 11 and modern browsers support DoH natively; Firefox honours the canary domain `use-application-dns.net`. Decide policy first, then hunt deviations from it.

### TLS fingerprints - JA3 / JA3S / JA4 (bash on Zeek ssl.log)

```bash
# Rarest client fingerprints by number of internal hosts. Field names depend on your JA3/JA4 Zeek package.
zcat ssl.*.log.gz | zeek-cut id.orig_h ja3 server_name \
| awk '{h[$2" "$1]=1; s[$2]=$3} END{for(k in h){split(k,a," "); c[a[1]]++} for(f in c) print c[f], f, s[f]}' \
| sort -n | head -30
```

JA3 hashes the ClientHello field order; browsers that randomise TLS extension order (Chrome since 2023) make JA3 unstable for them, so JA3 is better at spotting *non-browser* clients. JA4 sorts extensions and is more stable; JA4S/JA4X cover server and certificate. Treat fingerprint matches to published C2 lists as leads, not verdicts - default library TLS stacks (Go, Python, .NET) are shared by legitimate tools.

### Rare user-agents (SPL / KQL)

```spl
index=proxy earliest=-7d ```User-agents seen from <= 2 hosts in 7 days. Tune: proxy sourcetype, field names.```
| stats dc(src) as hosts count values(dest) as dests by http_user_agent
| where hosts<=2
| sort count
```

```kql
// Sentinel with proxy data in CommonSecurityLog (field mapping varies by vendor - verify RequestClientApplication)
CommonSecurityLog
| where TimeGenerated > ago(7d) and isnotempty(RequestClientApplication)
| summarize Hosts = dcount(SourceIP), Hits = count(), Dests = make_set(DestinationHostName, 10) by RequestClientApplication
| where Hosts <= 2
```

### Newly observed / newly registered domains (KQL)

```kql
// Domains first contacted in the last 1 day that were never seen in the prior 30 days. Enrich survivors with WHOIS age.
let lookback = 30d; let recent = 1d;
let Known = DeviceNetworkEvents | where Timestamp between (ago(lookback) .. ago(recent)) and isnotempty(RemoteUrl)
    | distinct RemoteUrl;
DeviceNetworkEvents
| where Timestamp > ago(recent) and isnotempty(RemoteUrl)
| where RemoteUrl !in (Known)
| summarize FirstSeen = min(Timestamp), Devices = dcount(DeviceName), Procs = make_set(InitiatingProcessFileName, 5) by RemoteUrl
| where Devices <= 2
```

Pair with the "newly registered domain" / "newly seen domain" categories your secure web gateway or protective DNS provider offers.

### C2 over legitimate services (KQL)

```kql
// Non-browser, non-chat-client processes calling messaging/paste/tunnel APIs. Tune the sanctioned-client list.
let Services = dynamic(["api.telegram.org","discord.com","discordapp.com","hooks.slack.com","slack.com",
  "graph.microsoft.com","pastebin.com","raw.githubusercontent.com","ngrok.io","ngrok-free.app","trycloudflare.com"]);
DeviceNetworkEvents
| where Timestamp > ago(7d) and RemoteUrl has_any (Services)
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","slack.exe","ms-teams.exe","teams.exe","outlook.exe","onedrive.exe","telegram.exe","discord.exe")
| summarize Conns = count(), Devices = dcount(DeviceName), Urls = make_set(RemoteUrl, 10)
    by InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA256
| order by Devices asc
```

For cloud storage C2 (Dropbox, Google Drive, OneDrive, S3 APIs), look for scripted clients (python, powershell, rundll32, unsigned binaries in user-writable paths) calling the API at regular intervals - combine with the interval query.

### CDN and domain-fronting signs

- With TLS inspection: compare TLS SNI to HTTP `Host` header. A mismatch where both are on the same CDN is the classic fronting signature.
- Without inspection: SNI of a high-reputation domain + periodic small transfers + a process that has no business with that domain.
- Major CDNs have moved to reject mismatched SNI/Host; verify your current provider behaviour rather than assuming fronting is impossible.
- Reverse proxies / redirectors on cloud functions or CDNs mean the IP reputation is "clean" - pivot on behaviour, not IP.

```bash
# After TLS inspection, Zeek http.log host vs ssl.log server_name joined on uid (only if both logged on the same sensor)
join -1 1 -2 1 <(zcat ssl.*.log.gz | zeek-cut uid server_name | sort) <(zcat http.*.log.gz | zeek-cut uid host | sort) \
| awk '$2!=$3' | head
```

## Baselining and stacking

- **Destination popularity**: count distinct internal hosts per destination per week. C2 destinations are almost always low-popularity.
- **Per-process destination set**: for each signed process, the set of domains it normally contacts; new domain for an old process = lead.
- **Time-of-day profile**: beacons ignore working hours; plot hourly counts for the pair.
- **Allowlist as code**: keep update services, AV cloud, telemetry and monitoring agents in a reviewed list with owner and date; re-review quarterly.
- **Long-tail stacking**: JA3/JA4, user-agent, certificate issuer, server ASN - sort ascending by host count.

## Verdict and escalation

| Verdict | Evidence that moves it there |
|---|---|
| True Positive | Periodic channel + unexpected process/binary (unsigned, user-writable path, renamed) + one of: young/never-seen domain, known-bad fingerprint, host-side persistence, matching intel |
| Benign True Positive | Periodicity real but owner identified: sanctioned agent, monitoring, update check, red-team with authorisation letter |
| False Positive | Pair is an artefact: NAT/proxy aggregation of many users, load-balancer health checks, sensor duplication |
| Needs more data | No process attribution (no EDR on host), TLS not inspected and destination ambiguous, < 24 h of data |

Escalate to `incident-response` (and open `/ir`) when: a TP verdict on any host; any DNS tunnel with data volume; a beacon from a server tier (DC, database, hypervisor, build server); or the same fingerprint/destination appears on more than one host.

## False positives & benign look-alikes

| Look-alike | Why it beacons | How to separate |
|---|---|---|
| AV / EDR / MDM agents | Fixed check-in interval | Signed vendor binary, vendor domain, fleet-wide popularity |
| Software updaters, telemetry | Periodic polling | Many hosts, known domains, consistent across builds |
| NTP, health checks, monitoring (SNMP, Nagios, Prometheus scrapes) | Exact intervals | Internal destinations, infra owners can confirm |
| Push / notification services, mail clients | Long-lived sessions, keepalives | Process is the expected client; large user population |
| CDNs and ad/analytics beacons in browsers | Regular small requests | Browser process; many users hit same domain |
| Anti-spam / CDN DNS with long hashed labels (e.g. reputation lookups) | High-entropy subdomains | Resolver-side, well-known vendor domains, query only (no TXT payloads) |
| Cloud sync clients (OneDrive, Dropbox) | Polling + bursts | Sanctioned binary in standard install path |
| Authorised red-team C2 | It is C2 | Rules-of-engagement document and deconfliction contact |

## Pitfalls

- NAT, proxies and VPN concentrators collapse many users into one source - beacon maths on the proxy IP is meaningless. Use per-user or per-client fields.
- Sleeping beacons (hours) and "working hours only" beacons need 7-30 day windows and lower `n`.
- Byte counts: MDE `DeviceNetworkEvents` has no byte fields - use Zeek, firewall or proxy logs for size regularity.
- Connection reuse (HTTP keep-alive, HTTP/2) hides check-ins inside one TCP session; analyse at request level in proxy/http logs.
- DNS logs at the resolver only show the resolver's client; logs at the edge only show the resolver. You need client-side or internal resolver query logs.
- Clock skew between sensors distorts intervals; Zeek on a SPAN with packet loss drops connections and inflates jitter.
- QUIC/HTTP3 (UDP 443) bypasses many proxies and TLS inspection - check whether it is permitted.

## Output

Hunt report stub (save under the case folder, e.g. `cases/<id>/hunts/c2-beaconing-<date>.md`):

```markdown
# Hunt report - C2 beaconing - <date>
- Hypothesis: <template used, filled in>
- ATT&CK: <T-IDs>
- Window / data: <UTC start-end>, sensors <list>, coverage gaps <list>
- Method: queries <links/IDs>, thresholds (n, CV, Bowley, rarity) <values>, allowlist version <ref>
- Results: <pairs reviewed> reviewed, <n> leads, verdict table:
  | Src host | Process | Destination | Interval / CV | Evidence | Verdict |
- Escalations: <case IDs or none>
- Detection opportunities: <behaviour -> rule idea, hand-off to detection-engineering>
- Gaps found: <e.g. no DNS client logging in VLAN X -> logging-coverage>
- Analyst / reviewer: <names>
```

Hand-offs: confirmed C2 -> `incident-response` / `/contain`; IOCs -> `threat-intel-ioc` / `/ioc`; rule -> `detection-engineering`, `network-detection-suricata-zeek`, `sigma-rules`; host deep-dive -> `windows-forensics`, `linux-forensics`, `memory-forensics`; logging gaps -> `logging-coverage`.

## References

- MITRE ATT&CK: T1071 (https://attack.mitre.org/techniques/T1071/), T1071.004, T1572, T1573, T1102, T1568.002, T1090.004
- Active Countermeasures: RITA documentation (beacon scoring, long connections, exploded DNS)
- Zeek documentation: conn.log, dns.log, ssl.log field reference
- Salesforce JA3 and FoxIO JA4+ project documentation
- SANS / Active Countermeasures papers on beacon analysis and DNS tunnelling detection
- Microsoft Learn: DeviceNetworkEvents table schema; ASIM DNS normalization schema
