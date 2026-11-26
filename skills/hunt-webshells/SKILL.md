---
name: hunt-webshells
description: Hypothesis-driven hunt for web shells on IIS, Apache, Nginx, PHP-FPM, Tomcat/Java, Exchange, SharePoint and edge appliances. Covers web workers spawning shells (w3wp.exe, httpd, nginx, php-fpm, java, UMWorkerProcess.exe), new .aspx/.jsp/.php files in web roots, App_Web DLLs in Temporary ASP.NET Files, IIS modules, IIS/Apache/Nginx log hunting (rare POST URIs, single-client access), China Chopper / Godzilla / Behinder / reGeorg patterns at a conceptual level, memory-resident Java shells, file-integrity diffing and YARA hand-off. Sources: DeviceProcessEvents, DeviceFileEvents, Sysmon 1/11, W3CIISLog, auditd, Falco. Maps to T1505.003, T1505.004, T1190. Use when asked to "hunt for webshells", "w3wp spawned cmd", "check Exchange/SharePoint for webshells", or after exploitation of a public-facing app.
---

# Hunt: web shells

## When to use

- After a vulnerability disclosure or exploitation report for a public-facing product you run (Exchange, SharePoint, Confluence, MOVEit-style file transfer, CMS plugins, edge VPN appliances).
- EDR or IDS hit on a web server (e.g. `w3wp.exe` spawning `cmd.exe`) that needs scoping across the farm.
- Proactive hunt on internet-facing servers, especially those without EDR coverage.
- During IR, to find every web-tier foothold before eviction.

Writing signatures for a found shell: `yara-rules`. Analysing a recovered shell: `malware-triage`. Host timeline: `windows-forensics`, `linux-forensics`, `timeline-analysis`.

## Ground rules

- **A suspicious file is not a webshell until shown to be one**: either (a) code that executes request-supplied input (commands, code, file operations) on review, or (b) access-log/EDR evidence of it being used. Report "suspicious file" until then.
- **Preserve before removal.** Copy the file with hash, full path, MACB timestamps and NTFS/ext4 metadata, plus the matching access-log window and any App_Web compiled DLLs (`evidence-handling`). Deleting a shell destroys the best evidence of what the actor did and tips them off.
- **Assume more than one.** Actors routinely drop several shells and a non-file backdoor (stolen machine keys, IIS module, new account). Removal is a coordinated eviction step under incident-commander approval, together with patching the entry vulnerability.
- **Never interact with a found webshell** (no test requests to "see if it works") from any host. Analysis is static, in a sandbox, or via logs.
- **Taking a public-facing server offline is a containment decision** with business impact - route through `/contain`; isolation via EDR keeps memory and disk intact, powering off loses memory-resident shells.

## Workflow

1. **Inventory the web tier**: servers, products and versions, web roots, virtual directories, app pools/service accounts, log locations, EDR coverage, load balancers/WAF in front (and whether they log the real client IP, e.g. `X-Forwarded-For`).
2. **Process lineage hunt** (highest signal): web server workers spawning shells, recon tools, script interpreters or network tools.
3. **File hunt**: new/modified script files in web roots and product directories, writer process, compiled ASP.NET artefacts, IIS modules.
4. **Log hunt**: rare script URIs receiving POST, URIs accessed by one or two clients, unusual user-agents, responses with consistent odd sizes, requests to static-looking files returning 200 with POST.
5. **Integrity diff** against the release artefact or a known-good snapshot; stack hashes across farm members.
6. **Triage candidates** statically (conceptual indicators below) and hand off signatures to `yara-rules`.
7. **Scope post-exploitation**: commands run via the shell, credential access (`hunt-credential-access`), lateral movement (`hunt-lateral-movement`), persistence beyond the web tier.
8. **Verdict, escalation, detection hand-off.**

## Hypothesis templates

- "Following exploitation of <product/CVE>, an actor wrote a script file into a web-accessible directory on <server group> and used it to run commands as the app pool / web service account."
- "A web server worker process (w3wp, httpd, php-fpm, java) spawned a shell or recon binary in the last <N> days."
- "A script URI on <site> receives POST requests from one or two external IPs only, and the file is absent from the deployed release."
- "An actor installed a non-file backdoor on the web tier: an IIS native/managed module, a stolen ASP.NET machine key, or an in-memory Java filter/servlet."
- "An edge appliance (VPN/ADC) was modified to host a web shell outside our EDR visibility."

## ATT&CK sub-technique map

| Behaviour | Technique |
|---|---|
| Script web shell | T1505.003 Server Software Component: Web Shell |
| IIS native/managed module backdoor | T1505.004 IIS Components |
| Initial exploitation of web app | T1190 Exploit Public-Facing Application |
| Commands via shell | T1059.003 Windows Command Shell, T1059.001 PowerShell, T1059.004 Unix Shell |
| Tool download through shell | T1105 Ingress Tool Transfer |
| HTTP tunnel (reGeorg-style) | T1090.001 Internal Proxy, T1572 Protocol Tunneling |
| Shell named like legitimate files | T1036.005 Match Legitimate Name or Location |
| Timestamp manipulation | T1070.006 Timestomp |
| Credential theft from web server (LSASS, config strings, machine keys) | T1003.001, T1552.001 |

## Data sources required

| Source | Use | Notes |
|---|---|---|
| EDR process events (`DeviceProcessEvents`, Sysmon EID 1, Security 4688 with command line) | Worker-process children | Decisive signal |
| EDR/Sysmon file events (`DeviceFileEvents`, Sysmon EID 11) | Script files written in web roots, writer process | Some EDRs sample file events - check |
| IIS W3C logs (`%SystemDrive%\inetpub\logs\LogFiles\W3SVC<id>\u_ex*.log`, Sentinel `W3CIISLog`) | Request patterns | Enable `cs(User-Agent)`, `cs(Referer)`, `X-Forwarded-For` custom field behind LBs |
| Apache/Nginx access logs (combined format) | Request patterns | POST bodies are not logged |
| WAF / reverse-proxy logs | Real client IP, blocked attempts | Often the only pre-exploitation record |
| Exchange: `MSExchange Management` event log, HttpProxy logs | Admin cmdlets, proxied requests | Product-specific |
| auditd / Falco (Linux) | execve by web user, file writes in web roots | Rules below |
| Deployment artefacts (CI release, package, git) | Known-good baseline | For integrity diffing |

## Queries

### Web server spawning shells and recon tools (KQL, MDE)

```kql
// Children of web server workers. Tune: legitimate children (e.g. app calls to csc.exe/conhost, Jenkins-style java apps).
let WebParents = dynamic(["w3wp.exe","httpd.exe","httpd","apache2","nginx.exe","nginx","php-cgi.exe","php.exe","tomcat.exe",
    "tomcat8.exe","tomcat9.exe","java.exe","java","node.exe","node","UMWorkerProcess.exe","lighttpd"]);
let Suspicious = dynamic(["cmd.exe","powershell.exe","pwsh.exe","whoami.exe","net.exe","net1.exe","nltest.exe","systeminfo.exe",
    "ipconfig.exe","quser.exe","tasklist.exe","certutil.exe","bitsadmin.exe","rundll32.exe","regsvr32.exe","reg.exe","wmic.exe",
    "sh","bash","dash","zsh","whoami","id","uname","curl","wget","python","python3","perl","nc","ncat","socat"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ (WebParents) or InitiatingProcessFileName startswith "php-fpm"
| where FileName in~ (Suspicious)
| summarize Count = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            Cmds = make_set(ProcessCommandLine, 20), AppPool = any(InitiatingProcessCommandLine)
            by DeviceName, InitiatingProcessFileName, FileName, AccountName
| order by FirstSeen desc
```

`w3wp.exe` command lines carry the app pool name (`-ap "MSExchangeOWAAppPool"`, `"SharePoint - 80"`), which tells you which application was exploited.

### Same, Sysmon in Splunk (SPL)

```spl
index=sysmon EventCode=1 (ParentImage="*\\w3wp.exe" OR ParentImage="*\\httpd.exe" OR ParentImage="*\\php-cgi.exe" OR ParentImage="*\\tomcat*.exe" OR ParentImage="*\\UMWorkerProcess.exe") ```Web worker children. Tune index/sourcetype and the allowlist of expected children.```
| search Image IN ("*\\cmd.exe","*\\powershell.exe","*\\pwsh.exe","*\\whoami.exe","*\\net.exe","*\\certutil.exe","*\\rundll32.exe","*\\nltest.exe")
| stats count min(_time) as first max(_time) as last values(CommandLine) as cmds by host ParentImage ParentCommandLine Image User
```

### New script files in web and product directories (KQL, MDE)

```kql
// Script/config files created or modified under web roots, with the writer. Tune: deployment accounts/tools, paths of your apps.
DeviceFileEvents
| where Timestamp > ago(30d) and ActionType in ("FileCreated","FileModified","FileRenamed")
| where FileName matches regex @"(?i)\.(aspx|ashx|asmx|asp|cshtml|svc|config|jsp|jspx|war|php\d?|phtml|cfm)$"
| where FolderPath has_any (@"\inetpub\", @"\wwwroot\", @"\FrontEnd\HttpProxy\", @"\ClientAccess\", @"\aspnet_client\",
        @"\TEMPLATE\LAYOUTS\", "/var/www/", "/usr/share/nginx/", "/srv/www/", "/webapps/", "/htdocs/")
| extend WriterIsWebWorker = InitiatingProcessFileName in~ ("w3wp.exe","httpd","php-fpm","java","java.exe","tomcat9.exe","node","UMWorkerProcess.exe")
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, InitiatingProcessFileName,
          InitiatingProcessCommandLine, InitiatingProcessAccountName, WriterIsWebWorker
| order by WriterIsWebWorker desc, Timestamp desc
```

A script file written by the web worker itself (upload handler, deserialization, path traversal) is far more suspicious than one written by `msdeploy.exe`, `robocopy.exe` or a CI agent under the deployment account.

```kql
// ASP.NET compiles requested pages into App_Web_*.dll; a new compiled DLL for an unknown page means the page was requested.
DeviceFileEvents
| where Timestamp > ago(30d) and FolderPath has "Temporary ASP.NET Files" and FileName startswith "App_Web_"
| summarize Count = count(), First = min(Timestamp) by DeviceName, FileName, FolderPath
```

```kql
// IIS module installation (T1505.004). Also review applicationHost.config changes and `appcmd list modules` output.
DeviceProcessEvents
| where Timestamp > ago(90d) and FileName =~ "appcmd.exe" and ProcessCommandLine has_any ("install module","add module")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```

### IIS log hunting (KQL, Sentinel W3CIISLog)

```kql
// Script URIs receiving POST from <= 2 client IPs. Behind a load balancer cIP is the LB - use your XFF field instead.
W3CIISLog
| where TimeGenerated > ago(30d)
| where csMethod == "POST" and csUriStem matches regex @"(?i)\.(aspx|ashx|asmx|asp)$"
| summarize Hits = count(), Clients = dcount(cIP), ClientList = make_set(cIP, 5), FirstSeen = min(TimeGenerated),
            UAs = make_set(csUserAgent, 5), Statuses = make_set(scStatus, 5) by Computer, sSiteName, csUriStem
| where Clients <= 2 and Statuses has "200"
| order by FirstSeen desc
```

### IIS log hunting (bash, raw W3C files)

```bash
# Parses the #Fields header so column order does not matter. Lists POST script URIs with <= 2 distinct clients.
cat u_ex*.log | awk '/^#Fields:/{delete f; for(i=2;i<=NF;i++) f[$i]=i-1; next} /^#/{next}
  { m=$f["cs-method"]; u=tolower($f["cs-uri-stem"]); c=$f["c-ip"] }
  m=="POST" && u ~ /\.(aspx|ashx|asmx|asp)$/ { hits[u]++; pair[u" "c]=1 }
  END{ for(p in pair){split(p,a," "); n[a[1]]++} for(u in hits) if(n[u]<=2) print hits[u], n[u], u }' \
| sort -k1,1nr | head -50
```

### Apache / Nginx log hunting (bash, combined format)

```bash
# POST to script files: hits, distinct clients, status codes. Tune extensions and log paths (rotated .gz files: use zcat -f).
zcat -f /var/log/nginx/access.log* /var/log/apache2/access.log* /var/log/httpd/access_log* 2>/dev/null \
| awk '$6=="\"POST" { split($7,u,"?"); p=tolower(u[1]);
       if (p ~ /\.(php[0-9]?|phtml|jsp|jspx|cgi)$/) { hits[p]++; pair[p" "$1]=1; st[p" "$9]++ } }
  END{ for(x in pair){split(x,a," "); n[a[1]]++} for(p in hits) if(n[p]<=2) print hits[p], n[p], p }' \
| sort -k1,1nr | head -50

# First appearance of each script URI in the logs (new endpoints after the exploitation date stand out)
zcat -f access.log* | awk '{split($7,u,"?"); p=u[1]; if(!(p in seen)){seen[p]=$4; print $4, p}}' | grep -iE '\.(php|jsp|aspx)' | sort | tail -50
```

Other log signals: POST to files with image/static extensions returning 200; requests with no `Referer` and a scripting/library user-agent; the same response size repeated (shell "OK" responses); requests to a script that is not in the release; WAF blocks from the same IP shortly before the first successful hit.

### Linux telemetry (auditd, Falco)

```bash
# auditd: every execve by the web service account (www-data is uid 33 on Debian/Ubuntu, apache is uid 48 on RHEL - verify locally)
-a always,exit -F arch=b64 -S execve -F euid=33 -k www_exec
-w /var/www/ -p wa -k webroot_write
# then: ausearch -k www_exec -i --start this-week | grep -E 'proctitle|exe='
```

```yaml
# Falco: web server process spawning a shell or network tool (host or container). Tune lists for your stack.
- list: bt_web_server_procs
  items: [httpd, apache2, nginx, lighttpd, java, node, php-cgi]
- list: bt_webshell_children
  items: [sh, bash, dash, zsh, ash, curl, wget, nc, ncat, socat, python, python3, perl, whoami, id, uname]
- rule: BT Web Server Spawned Shell or Tool
  desc: A web server or app-server process started a shell or network utility
  condition: >
    spawned_process and proc.name in (bt_webshell_children)
    and (proc.pname in (bt_web_server_procs) or proc.pname startswith php-fpm)
  output: "Web process spawned %proc.name (cmd=%proc.cmdline parent=%proc.pname user=%user.name container=%container.id image=%container.image.repository)"
  priority: WARNING
  tags: [host, container, persistence, T1505.003]
```

## File integrity diffing

```bash
# Preferred: diff the live web root against the release artifact for the deployed version
diff -rq /var/www/html /mnt/release-1.42/html | grep -vE '/(cache|uploads|tmp)/'
# Recently changed scripts (mtime can be forged - also compare ctime)
find /var/www -type f \( -iname '*.php*' -o -iname '*.phtml' -o -iname '*.jsp*' \) -mtime -14 -printf '%TY-%Tm-%Td %CY-%Cm-%Cd %s %p\n'
# Hash inventory per farm member; stack hashes across members (a file on one member only = lead)
find /var/www -type f -exec sha256sum {} + | sort -k2 > /case/webroot-$(hostname).sha256
# If deployed from git
git -C /var/www/html status --porcelain --ignored
```

```powershell
# IIS: recently written script files and a hash inventory for stacking across servers
Get-ChildItem -Path C:\inetpub, "C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy" -Recurse -File -Include *.aspx,*.ashx,*.asmx,*.asp,*.config -ErrorAction SilentlyContinue |
  Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-14) -or $_.CreationTime -gt (Get-Date).AddDays(-14) } |
  Select-Object FullName, Length, CreationTime, LastWriteTime
Get-ChildItem -Path C:\inetpub\wwwroot -Recurse -File | Get-FileHash -Algorithm SHA256 |
  Export-Csv "C:\case\webroot-$env:COMPUTERNAME.csv" -NoTypeInformation
```

## Static triage indicators (conceptual)

Use these to prioritise files for review and YARA, not as proof. Never execute candidates.

| Stack | Indicators |
|---|---|
| PHP | `eval`/`assert`/`create_function` on request data; `base64_decode`, `gzinflate`, `str_rot13` chains; `system`, `shell_exec`, `passthru`, `proc_open`, `popen`; `preg_replace` with `/e`; PHP inside image files plus `.htaccess` `AddType` |
| ASPX / ASP | Page evaluating a request parameter (JScript `eval` of `Request.Item`), `Process.Start`, `Assembly.Load` of request bytes, `FromBase64String` + decryption, file-manager forms |
| JSP / Java | `Runtime.getRuntime().exec`, `ProcessBuilder`, `ClassLoader.defineClass` on request bytes, AES-decrypting POST bodies |
| Generic | Very small file (one line) or very large obfuscated blob; password/key parameter check; name mimicking legitimate files; timestamp identical to neighbours but ctime recent |

Families you will meet in public reporting, described at behaviour level: **China Chopper** (one-line page that evaluates code sent by the client each request), **ASPXSpy** (full file manager/command UI), **Godzilla** and **Behinder** (encrypted POST payloads, optional in-memory loading), **reGeorg / Neo-reGeorg** (HTTP-to-SOCKS tunnel for internal access). Encrypted families make access logs and POST size patterns more useful than content inspection.

```bash
# Candidate shortlist for review / YARA (expect many hits in frameworks; stack and review, do not auto-delete)
grep -rlE 'eval\s*\(\s*(base64_decode|gzinflate|str_rot13|\$_(POST|GET|REQUEST|COOKIE))|assert\s*\(\s*\$_|shell_exec|passthru|proc_open' --include='*.php*' /var/www 2>/dev/null
grep -rlE 'Runtime\.getRuntime\(\)\.exec|ProcessBuilder|defineClass' --include='*.jsp' --include='*.jspx' /opt/tomcat/webapps 2>/dev/null
```

Hand-off: matched or suspicious files -> `yara-rules` (write family/behaviour rules, run across all web roots and backups) and `malware-triage` for deobfuscation.

## Product context

- **Exchange (on-prem)**: shells historically land in `\FrontEnd\HttpProxy\owa\auth\`, `\FrontEnd\HttpProxy\ecp\auth\`, `\ClientAccess\`, `C:\inetpub\wwwroot\aspnet_client\`; check the `MSExchange Management` event log for abused cmdlets (e.g. virtual-directory `ExternalUrl` changes used to write files), app-pool children of `w3wp.exe`, and `UMWorkerProcess.exe` children. Run Microsoft's current Exchange health/IOC scripts for the vulnerability in question.
- **SharePoint (on-prem)**: `...\Web Server Extensions\16\TEMPLATE\LAYOUTS\` is web-reachable. Shells that read the ASP.NET `machineKey` (as in the July 2025 "ToolShell" exploitation, CVE-2025-53770) let actors forge signed `__VIEWSTATE` payloads after the file is deleted - eviction requires rotating machine keys and restarting IIS per Microsoft guidance, not only deleting the file.
- **Java app servers (Tomcat, WebLogic, JBoss, Confluence)**: memory-resident shells (injected filters, servlets, listeners, valves) leave no file; hunt process lineage and network behaviour, and capture a heap dump/memory image before restart (`memory-forensics`).
- **Edge appliances (VPN, ADC, firewall management)**: no EDR; follow the vendor and CISA advisory for the product, run the vendor's integrity/IOC tool, export logs off-box, and treat a clean integrity check as weak evidence. Factory reset/rebuild decisions go through the incident commander.

## Baselining and stacking

- **Expected children of each app pool / web service** (some apps legitimately call `csc.exe`, `conhost.exe`, image tools): allowlist per app, not globally.
- **Release manifest** per site: everything outside it is a lead; uploads directories should never contain executable script types.
- **Farm stacking**: files/hashes present on one member of a load-balanced farm.
- **URI first-seen** list from access logs: new script endpoints after the vulnerability window.

## Verdict and escalation

| Verdict | Evidence that moves it there |
|---|---|
| True Positive | File executes request-supplied input on review, or access logs/EDR show it used (POST + child process / file writes) |
| Benign True Positive | Admin/diagnostic page or tool deployed by the owner with change record (still a risk - recommend removal) |
| False Positive | Framework/vendor file matching patterns; hash matches the vendor release |
| Needs more data | No access logs for the window, file not in release but no use observed, appliance without telemetry |

Escalate to `incident-response` (and `/ir`) on any TP, any web worker spawning recon/shell commands, any evidence of machine-key or credential access from the web tier, and any finding on Exchange, SharePoint, identity-adjacent or edge systems. Request eviction/containment through `/contain` with patch status confirmed - removing a shell without closing the vulnerability invites immediate re-entry.

## False positives & benign look-alikes

| Look-alike | Why it fires | How to separate |
|---|---|---|
| Deployments (msdeploy, CI agents, rsync, git pull) | New script files in web roots | Deployment account/tool lineage, matches release, change window |
| CMS auto-updates / plugin installs (WordPress, Drupal) | PHP files written by the web user | Matches vendor package hashes; admin session in logs |
| Apps that legitimately shell out (image conversion, PDF tools, reporting) | Web worker children | Same command line every time, fixed binaries, documented |
| Monitoring / health checks | Single-client repeated requests | Internal monitoring IPs, GET only |
| Vulnerability scanners and pentests | POSTs to odd URIs, webshell-like payloads in logs | Scanner IPs, authorised window, 404/403 results |
| Obfuscated commercial code (ionCube, licensing modules) | Base64/eval patterns | Vendor-signed/licensed, present across all installs |
| ASP.NET dynamic compilation | App_Web DLLs, csc.exe children | Pages are in the release |

## Pitfalls

- Load balancers/CDNs/WAFs replace the client IP; without `X-Forwarded-For` logging, "single client" analysis is meaningless.
- POST bodies are not logged by default; encrypted shells look like ordinary form posts - rely on endpoint and rarity.
- Logs on a compromised server can be edited; prefer centrally shipped logs and WAF/LB copies.
- Timestomped files: rely on ctime/$MFT/USN journal (`windows-forensics`) rather than LastWriteTime.
- Shells can live in configuration (`web.config` handlers), IIS modules, or memory - a clean file sweep is not "no webshell".
- Restarting the app pool/JVM to "clean" a memory shell destroys the evidence; capture first.

## Output

Hunt report stub (`cases/<id>/hunts/webshells-<date>.md`):

```markdown
# Hunt report - Web shells - <date>
- Hypothesis / trigger: <filled template, vulnerability reference>
- ATT&CK: <T-IDs>
- Scope: servers/sites <list>, window <UTC>, log sources and gaps (XFF? retention?)
- Findings:
  | Server | Path | SHA256 | Writer / first seen | Used? (log/EDR evidence) | Commands observed | Verdict |
- Non-file backdoors checked: IIS modules, machine keys, accounts, memory (method)
- YARA hand-off: rules requested / results (yara-rules)
- Escalations, eviction prerequisites (patch level, key rotation), approvals
- Detection opportunities: <hand-off to detection-engineering>
```

Hand-offs: incident -> `incident-response`, `/contain`; file analysis -> `malware-triage`, `yara-rules`; host timeline -> `windows-forensics`, `linux-forensics`, `timeline-analysis`; follow-on activity -> `hunt-credential-access`, `hunt-lateral-movement`, `hunt-c2-beaconing`; patch prioritisation -> `vuln-prioritization`; rules -> `detection-engineering`, `sigma-rules`.

## References

- MITRE ATT&CK: T1505.003 (https://attack.mitre.org/techniques/T1505/003/), T1505.004, T1190
- NSA / ASD joint guidance: "Detect and Prevent Web Shell Malware" (and its companion mitigating-web-shells repository)
- Microsoft Learn / Microsoft Security blog: guidance on web shell attacks against IIS and Exchange; SharePoint machine-key rotation guidance
- CISA advisories for the specific product exploited (Exchange, SharePoint, edge appliances)
- Microsoft Learn: W3CIISLog, DeviceProcessEvents, DeviceFileEvents schemas
- IIS documentation: W3C logging fields; Falco rules documentation
