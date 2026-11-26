---
name: linux-forensics
description: Linux host forensics and live response for servers, workstations, containers and cloud VMs. Covers UAC (Unix-like Artifacts Collector) triage, volatile data commands (ps, ss, lsof, /proc), auth logs (/var/log/auth.log, /var/log/secure), systemd journal (journalctl), wtmp/btmp/lastlog, auditd (audit.log, ausearch, aureport), bash/zsh history caveats, file timelines with stat and find -newermt, deleted-but-open files and deleted executables via /proc/<pid>/fd and /proc/<pid>/exe, container (Docker overlay2, containerd) and cloud VM specifics, and read-only image mounting (ewfmount, losetup --read-only, mount -o ro,noload). Use when asked to "triage a Linux box", "check SSH logins", "who ran what as root", "find files changed since", "recover a deleted binary", or when running /forensics on Linux.
---

# Linux forensics

## When to use

- A Linux server, workstation, container host or cloud VM is suspected
  compromised (web shell, crypto-miner, SSH brute force, rogue cron job,
  unexpected outbound traffic).
- You must collect volatile data before containment, or analyse a UAC/
  tarball/disk image offline.
- An alert from `hunt-linux-persistence`, `hunt-webshells` or
  `hunt-k8s-runtime` needs host-level confirmation.

Memory capture and analysis belong to `memory-forensics`; persistence
hunting depth to `hunt-linux-persistence`; custody to `evidence-handling`.

## Ground rules

1. **Hash + acquisition time + who before any analysis.** Every collected
   archive, log export or image gets a SHA-256 and an evidence-log row.
2. **Memory before anything invasive.** Capture RAM (LiME/AVML) before
   running broad `find`/`lsof` sweeps, killing processes, or rebooting. A
   reboot destroys deleted-but-running binaries, `/proc/`, tmpfs and
   in-memory-only malware.
3. **Trust nothing on the box.** A rootkit can lie to `ps`, `ls`, `ss` and
   `netstat`. Prefer statically linked trusted binaries from read-only media,
   compare `/proc/` with tool output, and confirm with memory analysis or a
   network-side view.
4. **Two sources per claim.** A login needs auth log + wtmp/journal; an
   execution needs history/auditd + file/process evidence.
5. **UTC everywhere.** Record `date -u`, `timedatectl` output and the
   difference against a trusted reference at collection time. Classic syslog
   lines carry no year and no zone.
6. **Write nothing to the suspect file system.** Send output to an external
   disk or a network share/listener; do not install packages on the host.

## Workflow

1. **Contain without destroying state.** Prefer network isolation (security
   group, host firewall from console, switch port) over shutdown. Containment
   needs incident-commander approval (`incident-response`, `/contain`).
2. **Record context:** `date -u; hostname; uname -a; uptime; timedatectl`.
3. **Capture memory** (`memory-forensics`).
4. **Collect volatile data** (commands below) to external storage, hashing
   each output.
5. **Run UAC** with an IR profile for logs, configs, persistence locations,
   user histories and a bodyfile.
6. **Image the disk** if scope warrants (cloud: snapshot the volume).
7. **Analyse offline:** logs -> logins and privilege use; persistence;
   file timeline around the anchor event; suspicious binaries to
   `malware-triage`.
8. **Build the timeline** (`timeline-analysis`) and record findings.

## Live response

### UAC (Unix-like Artifacts Collector)

```bash
# IR triage profile, output to mounted external storage; run as root
./uac -p ir_triage /mnt/usb/case01/
# Full profile including file hashing and bodyfile (slower)
./uac -p full /mnt/usb/case01/
```

UAC is shell-based, works across Linux distros, AIX, BSD, macOS and
Solaris, and writes an acquisition log plus hashes of collected files.
Profile names and artifact sets change between releases - list them with
`./uac --help` and check `profiles/` in your copy.

### Volatile data (run from trusted binaries, output to external media)

```bash
OUT=/mnt/usb/case01/volatile; mkdir -p "$OUT"
date -u                                   > "$OUT/date_utc.txt"
{ uptime; who -a; w; }                    > "$OUT/users.txt" 2>&1
ps -eo pid,ppid,user,lstart,etimes,args --forest > "$OUT/ps.txt"
{ ss -tanp; ss -uanp; }                   > "$OUT/sockets.txt" 2>&1   # TCP/UDP with owning process
{ ip addr; ip route; ip neigh; }          > "$OUT/net.txt" 2>&1
lsof -nP                                  > "$OUT/lsof.txt" 2>/dev/null
lsmod                                     > "$OUT/lsmod.txt"
cat /proc/mounts                          > "$OUT/mounts.txt"
{ iptables-save; nft list ruleset; }      > "$OUT/firewall.txt" 2>&1
systemctl list-units --type=service --state=running > "$OUT/services.txt"
systemctl list-timers --all               > "$OUT/timers.txt"
for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u "$u" 2>/dev/null | sed "s/^/$u: /"; done > "$OUT/crontabs.txt"
sha256sum "$OUT"/* > "$OUT/SHA256SUMS"
```

### Process inspection via /proc

```bash
PID=1234
tr '\0' ' ' < /proc/$PID/cmdline; echo      # real argv (can be overwritten by the process)
ls -l /proc/$PID/exe /proc/$PID/cwd          # binary path; "(deleted)" = binary removed from disk
tr '\0' '\n' < /proc/$PID/environ            # environment (LD_PRELOAD, proxy vars, SSH_CONNECTION)
cat /proc/$PID/status | grep -E 'Name|PPid|Uid|Gid'
cat /proc/$PID/maps                          # mapped files; anonymous rwx regions are suspicious
ls -l /proc/$PID/fd                          # open files and sockets
```

Hidden-process check: compare PIDs present as `/proc/<n>` directories with
`ps` output; a PID that exists in `/proc/` but not in `ps` is a rootkit
indicator (T1014). Process name in `ps` (`comm`) can be spoofed (T1036);
trust `/proc/<pid>/exe`.

### Deleted-but-open files and deleted executables

```bash
# Running processes whose binary was deleted (classic dropper behaviour)
ls -l /proc/*/exe 2>/dev/null | grep '(deleted)'
# Open file handles to deleted files (logs, staging archives, payloads)
lsof +L1 2>/dev/null
ls -l /proc/*/fd 2>/dev/null | grep '(deleted)'
# Recover while the process still runs - copy to evidence media, then hash
cp /proc/$PID/exe /mnt/usb/case01/recovered_${PID}.bin
cp /proc/$PID/fd/4 /mnt/usb/case01/recovered_${PID}_fd4.bin
sha256sum /mnt/usb/case01/recovered_*
```

Also check memfd-backed executables: `/proc/<pid>/exe` pointing to
`/memfd:<name> (deleted)` indicates fileless execution (T1620).

## Logs

| Source | Debian/Ubuntu | RHEL/Fedora/Alma/Rocky | Contains |
|---|---|---|---|
| Authentication | `/var/log/auth.log` | `/var/log/secure` | sshd accept/fail, sudo, su, PAM, useradd |
| General syslog | `/var/log/syslog` | `/var/log/messages` | Services, kernel, cron (often) |
| systemd journal | `/var/log/journal/` (persistent) or `/run/log/journal/` (volatile) | same | Structured, UTC microsecond timestamps |
| Login records | `/var/log/wtmp`, `/var/log/btmp`, `/var/log/lastlog`, `/run/utmp` | same | Successful, failed, last logins; current sessions |
| Audit | `/var/log/audit/audit.log` | same | EXECVE, SYSCALL, USER_LOGIN, rule keys |
| Package history | `/var/log/dpkg.log`, `/var/log/apt/history.log` | `dnf history`, `/var/log/dnf.log` | Installed tools (compilers, miners, netcat) |
| Web servers | `/var/log/apache2/`, `/var/log/nginx/` | `/var/log/httpd/`, `/var/log/nginx/` | Web shell access (`hunt-webshells`) |
| Cloud init | `/var/log/cloud-init.log`, `cloud-init-output.log` | same | User-data execution at boot |

Version notes: recent Debian releases rely on the journal and do not install
rsyslog by default, so `auth.log` may not exist. Some newer distributions
replace `wtmp`/`lastlog` with `wtmpdb` and `lastlog2` SQLite databases
(Y2038 fix) - check `/var/lib/wtmpdb/` and `/var/lib/lastlog/` and use the
matching `wtmpdb last` / `lastlog2` tools.

```bash
# SSH logins accepted / failed (auth.log style)
grep -E 'sshd\[[0-9]+\]: (Accepted|Failed|Invalid user)' /var/log/auth.log*
zgrep -h 'sudo:' /var/log/auth.log* | grep -v 'pam_unix'      # sudo commands with COMMAND=
# Journal: offline directory, UTC, one unit, a window
journalctl -D /mnt/case/var/log/journal --utc -u ssh -u sshd --since "2025-03-01 00:00" --until "2025-03-02 00:00"
journalctl -D /mnt/case/var/log/journal --list-boots          # reboots / gaps
journalctl -D /mnt/case/var/log/journal --utc -o json _COMM=sudo
# Login records from an offline image
last -F -f /mnt/case/var/log/wtmp
lastb -F -f /mnt/case/var/log/btmp
# auditd: executions and keyed rules (keys depend on the local rule set)
ausearch -if /mnt/case/var/log/audit/audit.log -m EXECVE -i --start 03/01/2025 00:00:00
ausearch -if /mnt/case/var/log/audit/audit.log -k <rule_key> -i
aureport -if /mnt/case/var/log/audit/audit.log --login --failed -i
```

Tune: SSH unit name (`ssh` vs `sshd`), log rotation suffixes (`.1`, `.gz`),
`ausearch` date format follows the analyst workstation locale.

Look for log tampering (T1070.002): truncated files with recent mtime, gaps
in journal sequence, `wtmp` entries with zeroed records, utmpdump anomalies,
`auditd` stopped (`SERVICE_STOP` / `DAEMON_END` records).

## Shell history

- Files: `~/.bash_history`, `~/.zsh_history`, `~/.local/share/fish/fish_history`,
  `/root/.bash_history`, plus `~/.python_history`, `~/.mysql_history`,
  `~/.lesshst`, `~/.viminfo` (files edited, search terms).
- Bash writes history **at shell exit** by default; a killed or still-running
  shell leaves nothing on disk (memory analysis: `linux.bash` plugin).
- No timestamps unless `HISTTIMEFORMAT` was set; then lines are preceded by
  `#<epoch>` comments.
- Concurrent shells overwrite each other unless `shopt -s histappend`.
- `HISTCONTROL=ignorespace` drops commands typed with a leading space;
  attackers also use `unset HISTFILE`, `HISTFILE=/dev/null`, `history -c`,
  `ln -sf /dev/null ~/.bash_history` (T1070.003).
- Non-interactive shells (web shells, cron, `ssh host 'cmd'`) do not write
  history - use auditd, process accounting (`lastcomm` if `acct` enabled)
  or web logs instead.
- zsh extended history format: `: <epoch>:<duration>;<command>`.

A missing or zero-length history for an account that clearly logged in is
itself a finding.

## Persistence (pointer)

Check at minimum: cron (`/etc/crontab`, `/etc/cron.*`, `/var/spool/cron/`),
systemd units and timers (`/etc/systemd/system/`, `~/.config/systemd/user/`),
`~/.ssh/authorized_keys` (T1098.004), `/etc/ld.so.preload`, shell rc files
(`/etc/profile.d/`, `~/.bashrc`), PAM modules, sudoers (`/etc/sudoers.d/`),
new UID 0 accounts in `/etc/passwd`, kernel modules, `rc.local`, udev rules,
and package-manager hooks. Detection logic and full location list:
`hunt-linux-persistence`.

## File timeline

```bash
# MAC(B) times of one file; Birth shown on ext4/xfs/btrfs with statx-aware coreutils (version-dependent)
stat /usr/bin/suspicious
# Files modified in a window on one file system, sorted, with mtime
find / -xdev -newermt "2025-03-01 10:00" ! -newermt "2025-03-01 14:00" -type f -printf '%TY-%Tm-%Td %TT %u %m %s %p\n' 2>/dev/null | sort
# Same, by inode change time (ctime survives touch-based timestomping)
find / -xdev -newerct "2025-03-01 10:00" ! -newerct "2025-03-01 14:00" -type f -printf '%C+ %p\n' 2>/dev/null | sort
# Executables in world-writable locations
find /tmp /var/tmp /dev/shm -type f -perm -u+x -printf '%T+ %u %p\n' 2>/dev/null
# ext4 crtime for one inode on an image partition (read-only)
debugfs -R 'stat <123456>' /dev/loop0p1
```

- `find -newermt` uses the analyst shell's local time zone - set `TZ=UTC`.
- `touch -d` can fake atime/mtime but not ctime (T1070.006); a file whose
  mtime is years old but ctime is during the incident was likely timestomped
  or freshly copied with preserved times.
- `relatime`/`noatime` mounts make atime unreliable as "last accessed".
- Running `find` on a live system can update directory atimes; prefer offline
  analysis or UAC's bodyfile, then `mactime` (`timeline-analysis`).
- Verify package-owned files: `debsums -c` (Debian) or `rpm -Va` (RHEL)
  shows modified binaries; run from a trusted copy against offline images.

## Containers and cloud VMs

- **Docker/containerd:** `docker ps -a`, `docker inspect <id>` (image,
  mounts, privileged flag, capabilities, entrypoint), `docker diff <id>`
  (files added/changed vs image), container logs in
  `/var/lib/docker/containers/<id>/<id>-json.log`, writable layer in
  `/var/lib/docker/overlay2/<id>/diff`. Kubernetes nodes: `crictl ps -a`,
  `crictl inspect`, pod logs under `/var/log/pods/`.
- Preserve before the orchestrator reschedules or deletes the pod: cordon
  the node, remove the pod's labels from the service selector or apply a
  deny NetworkPolicy (approval required), then `docker export`/copy the
  upper dir. `docker commit` creates a new image and records less than you
  think - prefer export plus `inspect` JSON.
- Container escape indicators (T1611): privileged containers, host PID/
  network namespaces, host path mounts of `/`, `/var/run/docker.sock`.
  Depth: `hunt-k8s-runtime`.
- **Cloud VMs:** snapshot the volume(s) and attach to an isolated forensic
  instance read-only; capture instance metadata, attached IAM role/managed
  identity, security groups, and control-plane logs (`ir-cloud-aws`,
  `ir-azure-entra`, `hunt-cloud-control-plane`). Serial console output can
  survive when SSH is gone. Ephemeral/instance-store disks vanish on stop.

## Mounting images read-only

```bash
# E01: expose the raw stream via FUSE
ewfmount case01.E01 /mnt/ewf                         # -> /mnt/ewf/ewf1
# Attach read-only with partition scanning
LOOP=$(losetup --read-only --find --show --partscan /mnt/ewf/ewf1)
lsblk "$LOOP"; mmls /mnt/ewf/ewf1                    # partition layout
# ext4: ro + noload (skip journal replay, which would write)
mount -o ro,noload,noexec,nodev "${LOOP}p1" /mnt/case
# XFS: ro + norecovery (+ nouuid if the UUID clashes with the analysis host)
mount -o ro,norecovery,nouuid "${LOOP}p2" /mnt/case2
# Raw image with known offset (sectors * 512)
mount -o ro,noload,loop,offset=$((2048*512)) disk.raw /mnt/case
```

LVM inside an image: set the loop device read-only first, then `pvscan`,
`vgscan`, `vgchange -ay <vg>`; avoid any LVM repair commands. Unmount and
`losetup -d` when finished; record the mount commands in your notes.

## Verdict table

| Verdict | Evidence that moves it |
|---|---|
| True Positive | Unexplained login + privilege use + persistence or malicious binary corroborated by logs and file/process evidence |
| Benign True Positive | Activity maps to a configuration-management run (Ansible/Puppet/Chef), approved admin session or change ticket |
| False Positive | Scanner/monitoring user, package update, or log misparse explains the signal |
| Needs more data | Logs rotated/journal volatile, history absent, no auditd - capture memory, pull SIEM copies, cloud and network logs |

## False positives & benign look-alikes

- SSH brute-force noise in `auth.log` on internet-facing hosts - only
  `Accepted` lines after failures from the same source matter.
- Binaries in `/tmp/` from installers, package builds, JIT runtimes.
- `(deleted)` exe after a package upgrade of a running daemon (check
  `dpkg.log`/`dnf` history for the same time).
- Configuration-management agents creating cron entries, users and keys.
- Container runtimes and snap/flatpak producing many overlay mounts and
  memfd usage.

## Pitfalls

- Rebooting or "cleaning" the host before memory and `/proc/` capture.
- Mounting an image without `ro,noload`/`norecovery` - journal replay changes
  the evidence and its hash.
- Reading syslog times without knowing the host's time zone and year.
- Treating an empty `.bash_history` as "nothing happened".
- Trusting `ps`/`ss` on a host with a suspected kernel or LD_PRELOAD rootkit.
- Forgetting rotated and compressed logs (`*.1`, `*.gz`) and the journal.
- Cloud autoscaling terminating the instance mid-investigation - set
  termination protection / scale-in protection first (with approval).

## Output

- Volatile data folder with `SHA256SUMS`, UAC archive, image hashes.
- Login, privilege-use and execution findings as rows in the incident
  timeline CSV (`timeline-analysis`); evidence-log rows (`evidence-handling`).
- Recovered binaries to `malware-triage`; IOCs to `threat-intel-ioc` / `/ioc`;
  persistence leads to `hunt-linux-persistence`; hardening gaps to
  `hardening-linux`. Entry point `/forensics`; agent forensic-analyst.

## References

- MITRE ATT&CK: T1070.002 Clear Linux or Mac System Logs, T1070.003 Clear
  Command History, T1070.006 Timestomp, T1014 Rootkit, T1036 Masquerading,
  T1620 Reflective Code Loading, T1098.004 SSH Authorized Keys, T1053.003
  Cron, T1543.002 Systemd Service, T1611 Escape to Host.
- RFC 3227; NIST SP 800-86.
- UAC project documentation (tclahr/uac on GitHub).
- man pages: journalctl(1), ausearch(8), aureport(8), last(1), find(1),
  losetup(8), mount(8), ewfmount(1).
- Red Hat documentation: System auditing with auditd.
