---
name: hunt-linux-persistence
description: Hypothesis-driven hunt for persistence on Linux servers and container hosts. Covers cron, anacron, at, systemd services, timers and generators, rc.local/init.d, shell profiles (.bashrc, /etc/profile.d), SSH authorized_keys, PAM tampering (pam_exec, modified pam_unix.so), LD_PRELOAD and /etc/ld.so.preload, kernel modules and eBPF rootkit signs, sudoers, new UID 0 accounts, setuid binaries, udev rules, motd scripts and container escapes. Gives auditd rules with ausearch, osquery queries, Falco rules, MDE for Linux KQL and package integrity checks (rpm -Va, debsums). Maps to T1053.003, T1543.002, T1546.004, T1098.004, T1556.003, T1574.006, T1547.006, T1014. Use when asked to "hunt Linux persistence", "check a server for backdoors", "is there a rootkit", or after a Linux compromise.
---

# Hunt: Linux persistence

## When to use

- Fleet hunt across Linux servers with EDR (MDE for Linux, CrowdStrike, Elastic Defend), auditd, osquery or Falco.
- A single host is suspected compromised (webshell, cryptominer, SSH brute force success) and you need every foothold before eviction.
- After eviction, to verify no persistence survived a rebuild-free remediation.
- Container hosts where an escape is suspected (hand container-level detail to `hunt-k8s-runtime`).

For full disk/memory forensics on one host use `linux-forensics` and `memory-forensics`; for baseline hardening use `hardening-linux`.

## Ground rules

- **Do not trust a live system you suspect is rootkitted.** A clean `ls`/`ps`/`cat` on a host with `/etc/ld.so.preload` or a kernel rootkit proves nothing. Corroborate with an out-of-band view: offline disk image, EDR/auditd telemetry recorded before the hunt, a statically linked toolkit from read-only media, or memory analysis.
- **Collect before you change.** Copy the persistence artefact (file, unit, key, module) with hashes and timestamps (`evidence-handling`) before disabling it. Removing persistence is an eviction step coordinated by the incident commander - partial removal tips off the actor and they re-enter through the one you missed.
- **No TP on a single file without context**: who wrote it (auditd/EDR process lineage), when, and what it executes. A new systemd unit is normal on a patched server; one written by `bash` spawned from `php-fpm` is not.
- **Package verification is evidence, not proof**: `rpm -Va`/`debsums` trust the local package database, which a root-level attacker can modify. Say so when you report "integrity verified".
- Live triage commands below are **read-only**. Run them with an approved account and log what you ran (shell history of the responder is evidence too).

## Workflow

1. **Scope**: which hosts, distro families (RHEL-like vs Debian-like paths differ), what telemetry exists (auditd keys, EDR, osquery, Falco), and the window.
2. **Telemetry first** (fleet-wide, non-intrusive): writes to persistence paths, module loads, new accounts, sudoers changes - from auditd/EDR/Falco.
3. **State sweep** (osquery or scripted read-only collection): enumerate every mechanism in the table below on all in-scope hosts.
4. **Stack** results across the fleet: entries present on 1-2 hosts out of hundreds of identically built servers rank highest.
5. **Package integrity**: verify binaries and libraries against packages; list unowned files in system paths.
6. **Rootkit checks** on suspicious hosts: taint flags, module list discrepancies, eBPF programs, hidden PIDs, preload.
7. **Attribute**: process lineage of the writer, initial-access vector, other hosts with the same artefact hash.
8. **Verdict and hand-off**: decision table; escalate; feed patterns to `detection-engineering`.

## Hypothesis templates

- "An actor with root on <host group> added a systemd service or timer that executes from a user-writable path (/tmp, /dev/shm, /var/tmp, a home directory)."
- "An SSH key not issued through our key-management process was added to root or a service account's authorized_keys."
- "A PAM module was modified or a pam_exec line added to capture or bypass credentials."
- "A userland rootkit is loaded via /etc/ld.so.preload, or a kernel/eBPF rootkit hides processes or files."
- "A web-server or database account escalated via a setuid binary or sudoers change and persisted via cron."
- "A compromised container broke out to the node (privileged container, docker.sock, core_pattern/release_agent abuse)."

## ATT&CK sub-technique map

| Mechanism | Technique |
|---|---|
| cron / anacron | T1053.003 Scheduled Task/Job: Cron |
| at | T1053.002 At |
| systemd timers | T1053.006 Systemd Timers |
| systemd services, generators | T1543.002 Create or Modify System Process: Systemd Service |
| rc.local, init.d | T1037.004 RC Scripts |
| update-motd.d scripts | T1037 Boot or Logon Initialization Scripts (commonly mapped) |
| .bashrc, /etc/profile.d | T1546.004 Unix Shell Configuration Modification |
| authorized_keys | T1098.004 SSH Authorized Keys |
| PAM tampering | T1556.003 Pluggable Authentication Modules |
| LD_PRELOAD, ld.so.preload | T1574.006 Dynamic Linker Hijacking |
| Kernel modules | T1547.006 Kernel Modules and Extensions; T1014 Rootkit |
| sudoers | T1548.003 Sudo and Sudo Caching |
| setuid/setgid, capabilities | T1548.001 Setuid and Setgid |
| New UID 0 / local account | T1136.001 Create Account: Local Account; T1078.003 |
| udev rules | T1546.017 Udev Rules |
| XDG autostart (desktops) | T1547.013 XDG Autostart Entries |
| Container escape | T1611 Escape to Host |

## Data sources required

| Source | What it gives | Notes |
|---|---|---|
| auditd (`/var/log/audit/audit.log`) | File writes by key, syscalls (`init_module`, `finit_module`, `bpf`), process lineage via `ppid` | Rules below; watches cannot wildcard home directories |
| EDR for Linux (MDE `DeviceFileEvents`, `DeviceProcessEvents`) | Writer process, command line, account | Coverage of file events on Linux varies by sensor version |
| osquery | Point-in-time state across the fleet | Schedule packs for change over time |
| Falco | Real-time syscall rules (host and containers) | Rules below; tune exceptions |
| Sysmon for Linux | EID 1 process create, 3 network, 11 file create, 23 file delete (to syslog) | Needs its own XML config |
| Auth logs (`/var/log/auth.log`, `/var/log/secure`, journald) | SSH logins with key fingerprint, sudo use, useradd | `LogLevel VERBOSE` in sshd logs key fingerprints |
| Package DB | Integrity of installed files | Trust caveat above |

## Mechanism checklist and read-only triage

| Mechanism | Locations to check |
|---|---|
| cron | `/etc/crontab`, `/etc/cron.d/`, `/etc/cron.{hourly,daily,weekly,monthly}/`, `/var/spool/cron/` (RHEL), `/var/spool/cron/crontabs/` (Debian), `/etc/anacrontab` |
| at | `atq`; `/var/spool/at/` (RHEL), `/var/spool/cron/atjobs/` (Debian) |
| systemd | `/etc/systemd/system/`, `/usr/lib/systemd/system/`, `/lib/systemd/system/`, `/run/systemd/`, `~/.config/systemd/user/`, drop-ins `*.service.d/`, generators `/etc/systemd/system-generators/`, `/usr/lib/systemd/system-generators/` |
| rc / init | `/etc/rc.local`, `/etc/init.d/`, `/etc/rc*.d/` |
| Shell config | `/etc/profile`, `/etc/profile.d/`, `/etc/bash.bashrc`, `/etc/bashrc`, `~/.bashrc`, `~/.bash_profile`, `~/.profile`, `~/.bash_logout`, `~/.zshrc` |
| SSH | `~/.ssh/authorized_keys*`, `/etc/ssh/sshd_config` (+ `sshd_config.d/`): `AuthorizedKeysFile`, `AuthorizedKeysCommand`, `PermitRootLogin`; `~/.ssh/rc`, `/etc/ssh/sshrc` |
| PAM | `/etc/pam.d/`, module dirs `/lib/x86_64-linux-gnu/security/`, `/lib64/security/`, `/usr/lib64/security/` |
| Dynamic linker | `/etc/ld.so.preload`, `/etc/ld.so.conf.d/`, `LD_PRELOAD` in `/proc/*/environ` |
| Kernel | `/etc/modules`, `/etc/modules-load.d/`, `/etc/modprobe.d/` (`install` lines run commands), `lsmod`, `/proc/modules`, `/sys/module/` |
| Privilege | `/etc/sudoers`, `/etc/sudoers.d/`, `/etc/passwd`, `/etc/shadow`, `/etc/group`, setuid/setgid files, `getcap` |
| udev | `/etc/udev/rules.d/`, `/usr/lib/udev/rules.d/`, `/lib/udev/rules.d/` (`RUN+=`) |
| motd | `/etc/update-motd.d/` (runs as root at SSH login via pam_motd on Debian/Ubuntu) |
| Package hooks | `/etc/apt/apt.conf.d/` (`APT::Update::Pre-Invoke`, `DPkg::Post-Invoke`), `/etc/yum/pluginconf.d/`, `/etc/dnf/plugins/` |

```bash
# Read-only sweep (run as root). Output to a case file; hash it afterwards.
cat /etc/crontab /etc/anacrontab /etc/cron.d/* 2>/dev/null | grep -vE '^\s*(#|$)'
for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u "$u" 2>/dev/null | sed "s/^/[$u] /"; done
atq 2>/dev/null
systemctl list-unit-files --type=service,timer --state=enabled --no-pager
systemctl list-timers --all --no-pager
find /etc/systemd /usr/lib/systemd /lib/systemd /run/systemd /home/*/.config/systemd /root/.config/systemd \
  \( -name '*.service' -o -name '*.timer' -o -name '*.conf' \) -mtime -30 -ls 2>/dev/null
grep -rhE '^\s*Exec(Start|StartPre|StartPost|Stop)=' /etc/systemd /home/*/.config/systemd /root/.config/systemd 2>/dev/null \
  | grep -E '/tmp/|/dev/shm|/var/tmp|curl|wget|base64|bash -c|sh -c|/dev/tcp|python[0-9.]* -c'
grep -nE 'curl|wget|/dev/tcp|base64 -d|nc |ncat|python[0-9.]* -c|LD_PRELOAD|alias (sudo|ssh)' \
  /etc/profile /etc/profile.d/* /etc/bash.bashrc /etc/bashrc /root/.bashrc /root/.profile /home/*/.bashrc /home/*/.profile 2>/dev/null
find / -xdev -name 'authorized_keys*' -exec ls -la {} \; -exec cat {} \; 2>/dev/null
grep -rn 'pam_exec' /etc/pam.d/
grep -rhoE '(/[^ ]+)?pam_[A-Za-z0-9_]+\.so' /etc/pam.d/ | sort | uniq -c | sort -n   # rare or absolute-path modules = leads; stack across fleet
cat /etc/ld.so.preload 2>/dev/null; grep -l LD_PRELOAD /proc/[0-9]*/environ 2>/dev/null
awk -F: '$3==0 {print "UID0:", $0}' /etc/passwd
grep -rhvE '^\s*(#|$)' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -E 'NOPASSWD|ALL'
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -exec ls -la --time-style=full-iso {} \; 2>/dev/null
getcap -r / 2>/dev/null
grep -rn 'RUN' /etc/udev/rules.d/ 2>/dev/null; ls -la /etc/update-motd.d/ /etc/rc.local /etc/init.d/ 2>/dev/null
grep -rnE 'Pre-Invoke|Post-Invoke' /etc/apt/apt.conf.d/ 2>/dev/null
```

### Rootkit and eBPF signs

```bash
cat /proc/sys/kernel/tainted                      # non-zero: decode bits; 4096 (O) out-of-tree, 8192 (E) unsigned module
dmesg 2>/dev/null | grep -iE 'taint|module verification failed'
diff <(awk '{print $1}' /proc/modules | sort) <(ls /sys/module | sort) | grep '^>' | head   # in /sys but not /proc/modules (built-ins also appear - review)
bpftool prog list 2>/dev/null; bpftool link list 2>/dev/null   # unexpected kprobe/tracepoint/lsm programs; know which agents use eBPF (Falco, Cilium, EDR)
ip -details link show | grep -i xdp; tc filter show dev eth0 ingress 2>/dev/null
ss -0pb 2>/dev/null                               # packet sockets with attached classic BPF filters (magic-packet backdoors)
diff <(ps -eo pid --no-headers | tr -d ' ' | sort -n) <(ls /proc | grep -E '^[0-9]+$' | sort -n)   # PIDs in /proc but not ps = hidden (short-lived PIDs cause noise; repeat)
ls -la /proc/*/exe 2>/dev/null | grep '(deleted)'  # processes running from deleted binaries
```

Tools such as `unhide`, `chkrootkit` and `rkhunter` help but are signature-based and run on the suspect kernel. Treat a clean result as weak evidence; a positive result as a lead to confirm in memory (`memory-forensics`).

### Container-escape indicators on the node

```bash
docker ps -q | xargs -r docker inspect --format '{{.Name}} priv={{.HostConfig.Privileged}} pid={{.HostConfig.PidMode}} net={{.HostConfig.NetworkMode}} binds={{.HostConfig.Binds}}' \
  | grep -E 'priv=true|pid=host|docker.sock|binds=\[/:'
cat /proc/sys/kernel/core_pattern                 # a pipe to an unexpected binary is an escape/persistence vector
```

## Telemetry queries

### auditd rules (`/etc/audit/rules.d/50-persistence.rules`)

```bash
# Persistence path watches - tune paths per distro, then: augenrules --load
-w /etc/crontab -p wa -k persist_cron
-w /etc/cron.d/ -p wa -k persist_cron
-w /etc/anacrontab -p wa -k persist_cron
-w /var/spool/cron/ -p wa -k persist_cron
-w /etc/systemd/system/ -p wa -k persist_systemd
-w /usr/lib/systemd/system/ -p wa -k persist_systemd
-w /etc/rc.local -p wa -k persist_rc
-w /etc/init.d/ -p wa -k persist_rc
-w /etc/profile -p wa -k persist_shell
-w /etc/profile.d/ -p wa -k persist_shell
-w /etc/bash.bashrc -p wa -k persist_shell
-w /root/.ssh/ -p wa -k persist_ssh
-w /etc/ssh/sshd_config -p wa -k persist_ssh
-w /etc/pam.d/ -p wa -k persist_pam
-w /etc/ld.so.preload -p wa -k persist_preload
-w /etc/ld.so.conf.d/ -p wa -k persist_preload
-w /etc/sudoers -p wa -k persist_sudo
-w /etc/sudoers.d/ -p wa -k persist_sudo
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/udev/rules.d/ -p wa -k persist_udev
-w /etc/update-motd.d/ -p wa -k persist_motd
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k kmod
-a always,exit -F arch=b32 -S init_module,finit_module,delete_module -k kmod
-a always,exit -F arch=b64 -S bpf -F a0=5 -k bpf_prog_load   # BPF_PROG_LOAD; noisy where eBPF agents run
```

```bash
ausearch -k persist_cron -i --start this-week | less                       # who wrote what (exe=, comm=, auid=)
ausearch -k persist_systemd -i --start this-week | less
ausearch -k kmod -i --start recent
ausearch -k persist_ssh -i --start today | grep -E 'exe=|name='
aureport -k --summary --start this-month                                    # volume per key to spot outliers
```

```spl
index=linux sourcetype=linux:audit key IN ("persist_*","kmod","identity","bpf_prog_load") earliest=-7d ```Writes to persistence paths by non-package-manager executables. Tune index, field names (exe, auid, key), allowlist.```
| search NOT exe IN ("/usr/bin/dpkg","/usr/bin/rpm","/usr/bin/dnf","/usr/bin/yum","/usr/bin/apt","/usr/bin/apt-get","/usr/lib/systemd/systemd")
| stats count values(exe) as exe values(name) as files values(auid) as auid by host key
```

### MDE for Linux (KQL)

```kql
// Writes to Linux persistence locations by anything other than package/config-management tooling.
// Tune: config-management agents (puppet, chef, ansible, salt), image build hosts.
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath startswith "/etc/cron" or FolderPath startswith "/var/spool/cron"
    or FolderPath startswith "/etc/systemd/system" or FolderPath has "/.config/systemd/"
    or FolderPath startswith "/etc/profile.d" or FolderPath endswith "bashrc" or FolderPath endswith "/.profile"
    or FolderPath has "/.ssh/authorized_keys" or FolderPath startswith "/etc/pam.d"
    or FolderPath endswith "ld.so.preload" or FolderPath startswith "/etc/sudoers"
    or FolderPath startswith "/etc/udev/rules.d" or FolderPath startswith "/etc/update-motd.d" or FolderPath endswith "rc.local"
| where InitiatingProcessFileName !in~ ("dpkg","rpm","dnf","yum","apt","apt-get","unattended-upgr","packagekitd","puppet","chef-client","ansible-playbook","salt-minion","cloud-init")
| project Timestamp, DeviceName, ActionType, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, InitiatingProcessAccountName
```

```kql
// Scheduler or init spawning download/decode/reverse-shell style commands.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("cron","crond","atd","systemd","anacron","run-parts")
| where ProcessCommandLine has_any ("curl","wget","base64","/dev/tcp","python -c","python3 -c","perl -e","nc ","ncat","socat","/tmp/","/dev/shm/")
| summarize Hosts = dcount(DeviceName), Example = any(ProcessCommandLine) by InitiatingProcessFileName, FileName
| order by Hosts asc
```

### osquery (SQL, fleet sweep)

```sql
-- Cron entries; stack the command column across the fleet
SELECT event, minute, hour, command, path FROM crontab;
-- Locally defined or user systemd units (package units live in /usr/lib/systemd)
SELECT id, active_state, sub_state, fragment_path FROM systemd_units
 WHERE fragment_path LIKE '/etc/systemd/system/%' OR fragment_path LIKE '%/.config/systemd/%';
-- SSH keys per user
SELECT u.username, ak.key_file, ak.algorithm, ak.key FROM users u CROSS JOIN authorized_keys ak USING (uid);
-- UID 0 and sudoers NOPASSWD
SELECT username, uid, gid, shell FROM users WHERE uid = 0;
SELECT source, rule_details FROM sudoers WHERE rule_details LIKE '%NOPASSWD%';
-- setuid binaries (stack path+hash across identical builds)
SELECT s.path, s.username, s.permissions, h.sha256 FROM suid_bin s JOIN hash h USING (path);
-- Kernel modules and preload
SELECT name, size, used_by, status FROM kernel_modules;
SELECT path, size, mtime FROM file WHERE path = '/etc/ld.so.preload';
SELECT p.pid, p.name, p.path, e.value FROM process_envs e JOIN processes p USING (pid) WHERE e.key = 'LD_PRELOAD';
-- Processes running from deleted binaries or temp paths
SELECT pid, name, path, cmdline FROM processes WHERE on_disk = 0 OR path LIKE '/tmp/%' OR path LIKE '/dev/shm/%';
```

### Falco rules (YAML)

```yaml
# Custom persistence rules. Uses default macros open_write and spawned_process. Tune bt_trusted_writers per estate.
- list: bt_trusted_writers
  items: [dpkg, rpm, dnf, yum, apt, apt-get, unattended-upgr, puppet, chef-client, salt-minion, cloud-init]

- list: bt_persistence_prefixes
  items: [/etc/cron, /var/spool/cron, /etc/systemd/system, /etc/profile.d, /etc/pam.d, /etc/sudoers,
          /etc/udev/rules.d, /etc/update-motd.d, /etc/ld.so.preload, /etc/ld.so.conf.d, /etc/rc.local, /etc/init.d]

- rule: BT Write to Linux Persistence Location
  desc: A file under a persistence location was opened for writing by a non-package-management process
  condition: open_write and fd.name pmatch (bt_persistence_prefixes) and not proc.name in (bt_trusted_writers)
  output: "Persistence path written (file=%fd.name proc=%proc.name cmd=%proc.cmdline parent=%proc.pname user=%user.name container=%container.id)"
  priority: WARNING
  tags: [host, container, persistence, T1053.003, T1543.002, T1574.006]

- rule: BT SSH Authorized Keys Modified
  desc: An authorized_keys file was written
  condition: open_write and fd.filename startswith authorized_keys and not proc.name in (bt_trusted_writers)
  output: "authorized_keys written (file=%fd.name proc=%proc.name cmd=%proc.cmdline user=%user.name container=%container.id)"
  priority: WARNING
  tags: [host, persistence, T1098.004]

- list: bt_module_load_parents
  items: [systemd-modules-load, systemd-udevd, kmod]

- rule: BT Kernel Module Load Tool Executed
  desc: insmod/modprobe run outside of boot and package management
  condition: >
    spawned_process and proc.name in (insmod, modprobe)
    and not proc.pname in (bt_module_load_parents) and not proc.pname in (bt_trusted_writers)
  output: "Kernel module load (cmd=%proc.cmdline parent=%proc.pname user=%user.name)"
  priority: NOTICE
  tags: [host, persistence, T1547.006]
```

Falco's upstream rulesets (stable / incubating / sandbox) include related rules for sensitive file reads, shell config modification and kernel module loading; check the ruleset version you deploy rather than duplicating them.

### Package integrity (bash)

```bash
# RHEL-like: files whose digest (5) differs from the package, excluding config files (c)
rpm -Va 2>/dev/null | awk '$1 ~ /5/ && $2 != "c"'
rpm -V pam openssh-server sudo coreutils procps-ng       # targeted: auth path and common trojan targets
# Debian-like
debsums -s 2>/dev/null                                   # silent: only report mismatches
dpkg --verify 2>/dev/null | grep -v ' c '                # '5' in column 3 = digest mismatch
# Unowned executables in system paths (expected in /usr/local; review elsewhere)
find /usr/bin /usr/sbin /usr/lib/systemd /etc/systemd -type f 2>/dev/null | while read -r f; do
  dpkg -S "$f" >/dev/null 2>&1 || rpm -qf "$f" >/dev/null 2>&1 || echo "UNOWNED $f"; done
```

For high-assurance verification compare hashes against packages fetched from the vendor repository on a clean system, or mount the disk image read-only on an analysis host.

## Baselining and stacking

- **Golden image diff**: for identically built hosts (autoscaling groups, Kubernetes nodes), anything present on few hosts is a lead - cron lines, units, keys, setuid hashes, modules.
- **Key inventory**: compare authorized_keys fingerprints with the key-management system / IdP-issued certificates.
- **Expected writers**: build the list of processes that legitimately write persistence paths (package managers, config management, cloud-init) and alert on everything else.
- **Kernel module and eBPF inventory** per kernel version and per agent stack (Falco, Cilium, EDR all load eBPF programs).

## Verdict and escalation

| Verdict | Evidence that moves it there |
|---|---|
| True Positive | Mechanism executes attacker-controlled content (download, reverse shell, unknown binary) or grants access (unknown key, UID 0, sudoers), and writer lineage is not change-managed |
| Benign True Positive | Change traced to config management, vendor agent install or approved change ticket |
| False Positive | Artefact of telemetry (package upgrade rewriting files, log rotation) with matching package-manager lineage |
| Needs more data | No writer attribution (no auditd/EDR), host not trustworthy (possible rootkit) - acquire image/memory |

Escalate to `incident-response` when: any TP; any sign of rootkit (preload, hidden PIDs, unexplained taint, unexpected eBPF); the same artefact on more than one host; persistence on a host holding secrets (CI runners, bastions, Kubernetes control-plane nodes). Eviction (removing keys/units, rebuilding) is coordinated and approval-gated; prefer rebuild from a known-good image for rootkitted hosts.

## False positives & benign look-alikes

| Look-alike | Why it fires | How to separate |
|---|---|---|
| Package upgrades rewriting units, PAM files, sudoers.d | Writes to persistence paths | Writer is dpkg/rpm; matching package version change |
| Config management (Ansible, Puppet, Chef, Salt) | Mass writes to cron/systemd/sudoers/keys | Agent process lineage, change record, consistent across fleet |
| cloud-init injecting SSH keys at first boot | authorized_keys written | Occurs at instance launch; key matches the cloud key pair |
| Monitoring / backup agents | New services, timers, cron jobs | Vendor-signed packages, fleet-wide |
| EDR, Falco, Cilium, observability agents | eBPF programs, kernel modules | Known program names, owning process, all hosts |
| Proprietary drivers (GPU, storage, VMware tools) | Tainted kernel (P/O flags) | Module name/vendor matches installed package |
| Developers' dotfiles | .bashrc changes with aliases/curl | Workstation/dev hosts, user-owned, no network callback |
| setuid binaries from packages (ping, sudo, passwd) | Setuid sweep | Owned by package, hash matches |

## Pitfalls

- RHEL vs Debian path differences (cron spool, PAM module dir, bashrc names) silently produce "nothing found".
- auditd watches do not cover new home directories or wildcards; user-level persistence needs EDR or osquery sweeps.
- Timestomping: `touch` changes mtime/atime but not ctime; compare ctime (and birth time where the filesystem records it).
- A userland rootkit hides the very file you grep for; read `/etc/ld.so.preload` from the disk image if in doubt.
- systemd drop-ins (`*.service.d/override.conf`) and generators modify legitimate units without new unit names.
- Immutable or ephemeral infrastructure: persistence may live in the image, launch template, user-data or Kubernetes manifests rather than on the host (`hunt-cloud-control-plane`, `hunt-k8s-runtime`).

## Output

Hunt report stub (`cases/<id>/hunts/linux-persistence-<date>.md`):

```markdown
# Hunt report - Linux persistence - <date>
- Hypothesis: <filled template>
- ATT&CK: <T-IDs>
- Scope: <host groups, distros, count>, window <UTC>, telemetry <auditd/EDR/osquery/Falco>
- Method: sweep script version <hash>, queries <IDs>, baseline <golden image/fleet stack>
- Findings:
  | Host | Mechanism | Path / entry | Writer (process, user, time) | Executes / grants | Fleet prevalence | Verdict |
- Integrity: rpm/debsums results, caveats (local DB trust)
- Rootkit checks: taint, modules, eBPF, hidden PIDs - results and how obtained (live vs image)
- Escalations / eviction requests: <IDs>
- Detection opportunities and logging gaps: <hand-offs>
```

Hand-offs: host deep-dive -> `linux-forensics`, `memory-forensics`, `timeline-analysis`; incident -> `incident-response`, `/contain`; webshell origin -> `hunt-webshells`; containers -> `hunt-k8s-runtime`; prevention -> `hardening-linux`; rules -> `detection-engineering`, `sigma-rules`; telemetry gaps -> `logging-coverage`.

## References

- MITRE ATT&CK: T1053.003 (https://attack.mitre.org/techniques/T1053/003/), T1543.002, T1546.004, T1098.004, T1556.003, T1574.006, T1547.006, T1014, T1548.001, T1548.003, T1546.017, T1611
- Linux kernel documentation: "Tainted kernels" (taint flag bits)
- auditd: auditctl(8), ausearch(8), aureport(8) man pages
- osquery schema documentation (crontab, systemd_units, authorized_keys, suid_bin, kernel_modules, process_envs, sudoers)
- Falco documentation: rules syntax, default macros, rulesets
- rpm(8) `--verify` output format; debsums(1); dpkg(1) `--verify`
- Microsoft Learn: Microsoft Defender for Endpoint on Linux; DeviceFileEvents schema
