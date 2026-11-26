---
name: hardening-linux
description: Hardening review and remediation for Linux servers and container hosts (RHEL family, Debian/Ubuntu, SUSE). Covers the CIS Benchmark approach (Level 1/2, OpenSCAP/SCAP Security Guide, usg, DISA STIG), sshd_config hardening (PermitRootLogin, PasswordAuthentication, sshd -T), sudoers review (NOPASSWD, GTFOBins-escapable commands, use_pty), patching and reboots (unattended-upgrades, dnf-automatic, needrestart), auditd rules, kernel sysctl (kptr_restrict, ptrace_scope, unprivileged_bpf_disabled), mount options (nodev nosuid noexec), SELinux/AppArmor enforcing, service minimisation and systemd sandboxing, Lynis hardening index, and Docker/Kubernetes host hardening (docker-bench-security, kube-bench). Use when asked to harden a Linux box, "/harden this server", read a Lynis or OpenSCAP report, or fix a finding without breaking production.
---

# Linux hardening

## When to use

- A Linux server, VM image, golden AMI or container host needs a baseline or review.
- An audit (Lynis, OpenSCAP, CIS-CAT, cloud CSPM host findings) needs turning into a
  prioritised change list.
- After `linux-forensics` or `hunt-linux-persistence` showed how an attacker got in or
  stayed (SSH keys, sudo misconfig, cron, writable service unit).

Not for: investigating a live intrusion (use `linux-forensics` /
`hunt-linux-persistence`) or Kubernetes runtime detection (use `hunt-k8s-runtime`).

## Ground rules

- **Never lock yourself out.** For SSH, PAM, firewall and sudo changes: keep an
  existing root/admin session open, validate syntax (`sshd -t`, `visudo -c`), have
  console/out-of-band access ready, then reload.
- **Measure before enforce.** SELinux/AppArmor go through permissive/complain mode;
  `noexec` mounts and sysctls are tested on a staging host running the real workload.
- **Evidence per finding**: the command output (`sshd -T`, `sysctl -a`, `findmnt`,
  `getenforce`, Lynis test ID) captured with host and date.
- **Bake it, don't hand-edit it.** Fixes go into config management (Ansible, Salt,
  Puppet, cloud-init, image pipeline); hand-fixed hosts drift back.
- **Production changes need a change ticket and rollback** (reboot windows for kernel
  updates, previous config file kept).

## Workflow

1. **Classify the host**: role, exposure (internet-facing? which ports?), data
   sensitivity, distro and version (`/etc/os-release`), support status (EOL distros
   are a finding by themselves).
2. **Pick the baseline**: CIS Benchmark Level 1 Server for most hosts, Level 2 for
   high-risk; DISA STIG where required. Choose the matching SCAP profile.
3. **Scan read-only**: Lynis + OpenSCAP (or `usg audit`). Save HTML/XML reports.
4. **Triage** with the checklist below: exposure and credential paths first,
   cosmetic findings last.
5. **Remediate via config management**, test on staging, roll out in rings.
6. **Re-scan**, record the delta, list accepted exceptions with owner and expiry.
7. **Telemetry**: confirm auditd/journald/EDR logs reach the SIEM (`logging-coverage`).

## Prioritised checklist

| # | Control | Impact | Break risk |
|---|---|---|---|
| 1 | Supported OS, security patches applied, reboot after kernel/glibc/openssl updates | Very high | Low-Med |
| 2 | SSH: keys only, no root login, restricted users/groups | Very high | Med (lockout) |
| 3 | Host firewall: only required ports, admin ports from management networks | Very high | Med |
| 4 | sudo: no `NOPASSWD: ALL`, no shell-escapable commands, logging on | High | Low-Med |
| 5 | Remove unused services/packages; no world-listening dev/debug services | High | Low-Med |
| 6 | SELinux enforcing / AppArmor enforcing for exposed services | High | Med |
| 7 | auditd with identity, privilege, module and exec rules, shipped off-host | High (for IR) | Low (watch volume) |
| 8 | Kernel sysctls (info leak, ptrace, BPF, network) | Med | Low-Med |
| 9 | Mount options on /tmp, /dev/shm, /var/tmp, /home | Med | Med (installers using /tmp) |
| 10 | SUID/SGID and world-writable review | Med | Low |
| 11 | PAM: faillock, password quality, no empty passwords, single UID 0 | Med | Low |
| 12 | Unneeded kernel modules / filesystems disabled | Low-Med | Low |
| 13 | Container host: socket protection, no privileged containers, CIS Docker | High on container hosts | Med |

## Baselines and scanners

```bash
# OpenSCAP with SCAP Security Guide (RHEL family; datastream name differs per distro/version)
oscap info /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml          # list profiles
oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_cis_server_l1 \
  --results /root/scan-results.xml --report /root/scan-report.html \
  /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml
# Ubuntu Pro: Ubuntu Security Guide
usg audit cis_level1_server
# Lynis (read-only audit; results in /var/log/lynis.log and /var/log/lynis-report.dat)
lynis audit system
grep -E '^(warning|suggestion)\[\]' /var/log/lynis-report.dat
```

- Do not run `--remediate` / `usg fix` blindly on production: review the generated
  script, test on staging. Some CIS controls (e.g. separate partitions) require a
  rebuild, not a change.
- The Lynis *hardening index* is a trend metric, not a pass mark.

## SSH

Put changes in `/etc/ssh/sshd_config.d/10-hardening.conf` where the distro includes
that directory. sshd uses the **first** value it reads for most keywords, so a drop-in
included at the top wins over later lines; confirm the effective config with `sshd -T`.

```bash
# /etc/ssh/sshd_config.d/10-hardening.conf  (adjust AllowGroups to your admin group)
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
PubkeyAuthentication yes
AuthenticationMethods publickey
AllowGroups ssh-users
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no        # yes only on bastions that need it
ClientAliveInterval 300
ClientAliveCountMax 2
LogLevel VERBOSE             # logs key fingerprints used for each login
```

```bash
sshd -t && sshd -T | grep -Ei 'permitrootlogin|passwordauthentication|allowgroups|loglevel'
systemctl reload sshd   # or ssh on Debian/Ubuntu; keep your current session open
```

- Review `authorized_keys` for all users (including root and service accounts) and
  `AuthorizedKeysFile` overrides; unknown keys are an incident lead, not just a finding
  (`hunt-linux-persistence`).
- Prefer SSH certificates or a central access broker over per-host keys at scale.
- `ssh-audit` checks offered ciphers/KEX/MACs; modern OpenSSH defaults are acceptable,
  so remove legacy algorithms only if they were explicitly re-enabled.
- MFA for SSH (PAM + OTP/FIDO `sk-` keys) for internet-exposed bastions.

## sudo

```bash
visudo -c                                  # syntax check of sudoers and includes
grep -rEn 'NOPASSWD|ALL\s*=\s*\(ALL(:ALL)?\)\s*ALL' /etc/sudoers /etc/sudoers.d/
sudo -l -U appuser                         # effective rights for a user
```

- No `NOPASSWD: ALL`; scope NOPASSWD to exact commands with exact arguments for
  automation accounts.
- Commands that allow shell escape or arbitrary file write (editors, pagers, `find`,
  `tar`, `awk`, `less`, `vim`, `python`, `systemctl edit`, wildcards in arguments)
  equal full root; check entries against GTFOBins.
- `Defaults use_pty`, `Defaults logfile="/var/log/sudo.log"`, optionally
  `Defaults log_input,log_output` (I/O logs can contain secrets; protect them).
- Restrict `su` to a group with `pam_wheel`.

## Patching

- Debian/Ubuntu: `unattended-upgrades` for security pocket; `needrestart` to restart
  services using old libraries. RHEL family: `dnf-automatic` (security only) or
  managed patch tooling; `needs-restarting -r` shows if a reboot is needed.
- Kernel live patching (Livepatch, kpatch, KernelCare) reduces reboot urgency but
  does not cover all CVEs; still schedule reboots.
- Track by exposure: internet-facing services and KEV-listed CVEs first
  (`vuln-prioritization`).

## auditd

Rules live in `/etc/audit/rules.d/*.rules`, loaded with `augenrules --load`. Put
`-e 2` (immutable until reboot) last once stable. A community starting point is the
Neo23x0 auditd best-practice ruleset; trim it to your volume budget.

```bash
# /etc/audit/rules.d/50-blueteam.rules (64-bit; add arch=b32 variants on mixed systems)
-b 8192
-f 1
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k priv_esc
-w /etc/sudoers.d/ -p wa -k priv_esc
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /root/.ssh/ -p wa -k root_ssh
-w /etc/cron.d/ -p wa -k cron
-w /etc/systemd/system/ -p wa -k systemd_units
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=unset -k root_exec_by_user
```

```bash
ausearch -k identity -ts today -i     # verify rules fire
aureport --summary
```

- Full `execve` auditing is very noisy; EDR or a Sysmon-for-Linux / eBPF sensor may be
  a better source. Decide with `logging-coverage`.
- Forward to the SIEM (audisp/af_unix, rsyslog, Elastic Agent/auditbeat, or laurel for
  JSON) and alert on gaps.

## Kernel sysctl

```bash
# /etc/sysctl.d/60-hardening.conf  - test on staging; comments mark common breakers
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1            # 2/3 breaks debuggers and some monitoring agents
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
kernel.kexec_load_disabled = 1
kernel.sysrq = 0
kernel.randomize_va_space = 2
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
fs.suid_dumpable = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1         # breaks asymmetric routing setups
net.ipv4.conf.all.log_martians = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_redirects = 0
# net.ipv4.ip_forward = 0               # NOT on routers, VPN gateways, container/K8s nodes
```

Apply with `sysctl --system`; verify with `sysctl <key>`. Restricting unprivileged
user namespaces reduces kernel attack surface but breaks rootless containers and
browser sandboxes; the knob differs per distro (sysctl or AppArmor policy).

## Filesystems and mounts

```bash
findmnt -no TARGET,OPTIONS /tmp /dev/shm /var/tmp /home
```

- `/tmp`, `/var/tmp`, `/dev/shm`: `nodev,nosuid,noexec`; `/home`: `nodev,nosuid`;
  separate `/var/log` and `/var/log/audit` so log floods cannot fill `/`.
- `noexec` on `/tmp` breaks some installers and build tools; point their TMPDIR
  elsewhere rather than dropping the option. `noexec` is a speed bump (interpreters
  can still run scripts), not a control on its own.
- Review SUID/SGID and world-writable files against the package baseline:

```bash
find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -exec ls -l {} + 2>/dev/null
find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null     # world-writable dirs without sticky bit
awk -F: '($3==0){print $1}' /etc/passwd                          # only root should print
rpm -Va 2>/dev/null | grep '^..5'  ||  debsums -s 2>/dev/null    # changed package files
```

- Disable unused filesystems/protocol modules via `/etc/modprobe.d/` (`install cramfs
  /bin/false`, likewise `udf`, `dccp`, `sctp`, `rds`, `tipc`, and `usb-storage` where
  policy allows).

## SELinux / AppArmor

- SELinux (RHEL family): `getenforce`, `sestatus`; target `Enforcing` with the
  `targeted` policy. Fix denials properly: `ausearch -m AVC -ts recent | audit2why`,
  use booleans (`getsebool -a`, `setsebool -P`), file contexts (`semanage fcontext`,
  `restorecon -Rv`), and only then a small local module. `setenforce 0` is not a fix.
- AppArmor (Debian/Ubuntu/SUSE): `aa-status`; move exposed services' profiles from
  complain to enforce (`aa-enforce /etc/apparmor.d/<profile>`); denials appear in the
  kernel/audit log as `apparmor="DENIED"`.

## Services and systemd sandboxing

```bash
ss -tulpn                                          # what listens, on which address
systemctl list-unit-files --type=service --state=enabled
systemctl disable --now <unit>; systemctl mask <unit>     # after confirming it is unused
systemd-analyze security <unit>                    # exposure score per service
```

- Bind admin/monitoring endpoints to localhost or the management network.
- For in-house services add `NoNewPrivileges=yes`, `ProtectSystem=strict`,
  `ProtectHome=yes`, `PrivateTmp=yes`, `CapabilityBoundingSet=`, `ReadWritePaths=`
  in a drop-in, test, then iterate on the `systemd-analyze security` score.
- Remove compilers and network tools from production images where the CIS profile
  asks for it and operations agree.

## Container hosts

- Minimal host OS (container-optimised distros or a stripped base), patched kernel,
  nothing else running on the node.
- Docker: never expose `/var/run/docker.sock` to containers or the daemon on TCP
  without mTLS; membership in the `docker` group equals root. Use rootless mode or
  `userns-remap` where feasible; `daemon.json` with `"no-new-privileges": true`,
  `"live-restore": true`, `"icc": false` as appropriate.
- No `--privileged`, no host PID/network namespaces, no sensitive host mounts, drop
  capabilities, read-only root filesystems, seccomp/AppArmor/SELinux profiles on.
- Audit with `docker-bench-security` (CIS Docker Benchmark) and `kube-bench` (CIS
  Kubernetes Benchmark) for nodes; Pod Security Admission `restricted` for workloads.
- Add auditd watches for `/usr/bin/dockerd`, `/etc/docker/`, `/var/lib/docker/`.
- Runtime detection and K8s audit logs: `hunt-k8s-runtime`.

## False positives & benign look-alikes

- Lynis/OpenSCAP flag "no separate partition" on cloud images by design; record as an
  accepted exception or compensate (quotas, log shipping), do not rebuild for points.
- SUID binaries from packages (`passwd`, `sudo`, `mount`, `ping` on some distros) are
  expected; investigate SUID files not owned by a package or recently created.
- `ip_forward = 1` on Kubernetes nodes, VPN or router hosts is required.
- `NOPASSWD` for a CI/automation account on one exact command is acceptable with
  justification.
- SELinux denials right after an app upgrade are usually labelling, not an attack;
  still read them before allowing.

## Pitfalls

- Reloading sshd with `PasswordAuthentication no` before anyone's key works; or a
  drop-in that never applies because an earlier line already set the keyword.
- `-e 2` in auditd before the rules are final (needs a reboot to change).
- Turning SELinux off to "fix" an app and never turning it back on.
- Applying desktop/workstation CIS profiles to servers or Level 2 to everything.
- Patching packages without restarting services/rebooting: the vulnerable library
  stays loaded.
- Hardening the host but leaving the docker socket, cloud metadata access, or a
  world-readable `.env` with secrets.

## Output

- Per-host or per-image findings: control, evidence, target, impact, break risk,
  owner, ticket, exception expiry.
- Config-management change set (Ansible role / drop-in files) with test results.
- Telemetry requests (auditd keys, file watches) handed to `detection-engineering`
  and checked with `/coverage`; vulnerable package findings to `vuln-prioritization`.
  Start a review with `/harden`.

## References

- MITRE ATT&CK: T1098.004 SSH Authorized Keys, T1548.003 Sudo and Sudo Caching,
  T1548.001 Setuid and Setgid, T1053.003 Cron, T1543.002 Systemd Service,
  T1611 Escape to Host, T1068 Exploitation for Privilege Escalation.
- CIS Benchmarks: distribution-specific Linux benchmarks, CIS Docker Benchmark,
  CIS Kubernetes Benchmark.
- SCAP Security Guide / OpenSCAP documentation; DISA STIGs for RHEL and Ubuntu.
- Red Hat: Security hardening and Using SELinux guides; Ubuntu Security Guide docs.
- OpenSSH `sshd_config(5)`, `sudoers(5)`, `auditctl(8)`, `systemd.exec(5)` man pages.
