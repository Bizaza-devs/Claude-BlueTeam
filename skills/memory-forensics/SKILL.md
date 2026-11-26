---
name: memory-forensics
description: "Memory acquisition and analysis for Windows and Linux incident response. Covers acquisition with WinPmem, DumpIt, Magnet RAM Capture, LiME and AVML, hypervisor snapshots (VMware .vmem/.vmss/.vmsn, Hyper-V, KVM/virsh dump), and the Volatility 3 workflow: windows.info, pslist/psscan/pstree, cmdline, netscan, malfind, dlllist, ldrmodules, handles, svcscan, hollowprocesses and other windows.malware plugins, vadyarascan, filescan/dumpfiles, registry plugins, Linux plugins (linux.pslist, linux.bash, linux.sockstat, linux.check_modules), symbol table (ISF, dwarf2json) problems, plus MemProcFS as an alternative. Use when asked to \"capture RAM\", \"analyse a memory dump\", \"find injected code\", \"process hollowing\", \"hidden process\", \"fileless malware\", \"Cobalt Strike beacon in memory\", or \"Volatility symbol error\"."
---

# Memory forensics

## When to use

- Suspected fileless or injected malware (T1055, T1620), credential theft
  from LSASS (T1003.001), rootkits (T1014), or C2 implants that do not touch
  disk.
- Before containment actions that would destroy volatile state (reboot,
  reimage, killing processes, EDR "remediate").
- An EDR alert needs confirmation of what was actually running and
  connected at a point in time.
- Encrypted volumes (BitLocker/LUKS) are unlocked on a live host - memory can
  contain keys needed later.

Disk artifacts: `windows-forensics`, `linux-forensics`. Extracted payloads:
`malware-triage`. Signatures: `yara-rules`.

## Ground rules

1. **Acquire first, analyse later.** Capture memory before any other live
   response tooling that allocates lots of RAM or kills processes. Record the
   UTC capture start/end time, tool name + version, and who ran it.
2. **Hash + acquisition time + who before any analysis.** SHA-256 the image
   as written and again after every transfer (`evidence-handling`).
3. **A memory finding needs a second view.** Confirm an injected region with
   a second plugin (malfind + vadinfo/ldrmodules + YARA hit or disassembly)
   and, where possible, with disk/EDR/network evidence. One plugin hit is a
   lead, not a verdict.
4. **Smear is real.** Live acquisition takes time while memory changes;
   inconsistent structures (a process in pslist with no threads, broken
   VADs) can be acquisition artifacts. Note them; do not over-interpret.
5. **Never run extracted code.** Dumped PEs/shellcode go to `malware-triage`
   inside an isolated VM.

## Workflow

1. **Decide the acquisition path:** hypervisor snapshot (least intrusive) >
   EDR-native memory capture > in-guest tool from external media.
2. **Acquire** to external storage or a network share, never to the suspect
   disk if avoidable. Hash.
3. **Identify the image:** `windows.info` (or `banners.Banners` for Linux);
   fix symbols before anything else.
4. **Process landscape:** pslist vs psscan vs pstree; parent/child sanity;
   cmdline.
5. **Network:** netscan - map connections to PIDs; pivot to IOCs.
6. **Code injection / hiding:** malfind, ldrmodules, hollowprocesses and
   other `windows.malware.*` plugins; vadyarascan with your rule set.
7. **Persistence and config:** svcscan, registry plugins, handles (mutexes,
   named pipes).
8. **Extract** suspicious regions/files (`-o outdir`, `--dump`), hash them,
   and hand off.
9. **Record** each finding in the incident timeline with the image time
   (process create times from memory are UTC).

## Acquisition

### Windows

| Tool | Notes |
|---|---|
| WinPmem | Open source; writes raw or AFF4 depending on build. Legacy `winpmem_mini_x64_rc2.exe <out.raw>`; the newer Go rewrite uses subcommands (`winpmem.exe acquire <out.raw>`) - check `--help` of your build |
| DumpIt (Magnet / Comae) | Single executable; recent versions write a Microsoft crash dump (`.dmp`) that Volatility and WinDbg both read |
| Magnet RAM Capture | GUI, raw output; good for non-specialist hands-on-keyboard collection |
| EDR live response | Many EDRs offer a memory or process dump action - check output format and whether pagefile is included |

- Collect `C:\pagefile.sys` and `C:\swapfile.sys` too (MemProcFS can use the
  pagefile; Volatility 3 support is limited).
- `hiberfil.sys` is a compressed older memory snapshot; convert with
  Volatility 3's hibernation layer or MemProcFS (version-dependent) - useful
  when the system was hibernated or Fast Startup is on.
- VBS/HVCI/Credential Guard: some acquisition drivers fail or produce
  incomplete images; keep a fallback tool and record failures.

### Linux

```bash
# AVML (Microsoft): static binary, no kernel module; reads /dev/crash, /proc/kcore or /dev/mem
./avml /mnt/usb/case01/host01.lime
./avml --compress /mnt/usb/case01/host01.lime.compressed   # convert later with avml-convert
# LiME: kernel module built for the EXACT running kernel (build on a matching system, not the suspect host)
insmod ./lime-$(uname -r).ko "path=/mnt/usb/case01/host01.lime format=lime"
sha256sum /mnt/usb/case01/host01.lime
```

Kernel lockdown / Secure Boot can block `/dev/mem`, `/proc/kcore` and
unsigned modules - record the failure and fall back to hypervisor capture.

### Hypervisor and cloud

| Platform | Method | Analyse |
|---|---|---|
| VMware Workstation/ESXi | Suspend or snapshot the VM -> `.vmem` + `.vmss` (suspend) or `.vmsn` (snapshot) | Keep `.vmem` and the `.vmss`/`.vmsn` together in one folder; Volatility uses the metadata file to build the layer |
| Hyper-V | Checkpoint -> `.vmrs` (2016+) / `.bin` (older) | Convert to a crash dump with Microsoft tooling (e.g. `vm2dmp` / Hyper-V debugging tools); support varies by version |
| KVM/libvirt | `virsh dump --memory-only --format elf <domain> /evidence/mem.elf` | Volatility reads ELF core dumps |
| VirtualBox | `VBoxManage debugvm <vm> dumpvmcore --filename mem.elf` | ELF core |
| Public cloud | Usually no hypervisor memory export to tenants; use in-guest tools (AVML/WinPmem) or EDR | Snapshot disks separately (`ir-cloud-aws`, `ir-azure-entra`) |

Snapshot-based capture pauses the guest briefly - avoids smear and leaves no
tool footprint in the guest.

## Volatility 3 workflow (Windows)

```bash
# Identify OS build, kernel base, symbols in use; first run downloads PDB symbols (needs internet) - see Symbols below
vol -f mem.raw windows.info
# Process views: linked list vs pool scan vs tree
vol -f mem.raw windows.pslist
vol -f mem.raw windows.psscan
vol -f mem.raw windows.pstree
vol -f mem.raw windows.cmdline
# Network artefacts (pool scanning; includes closed sockets)
vol -f mem.raw windows.netscan
# Injected/executable private memory, unlinked DLLs, DLL list per process
vol -f mem.raw windows.malfind --pid 4321
vol -f mem.raw windows.ldrmodules --pid 4321
vol -f mem.raw windows.dlllist --pid 4321
# Handles (mutants, named pipes, files, registry keys) and services
vol -f mem.raw windows.handles --pid 4321
vol -f mem.raw windows.svcscan
# YARA across process memory (rule file from yara-rules)
vol -f mem.raw windows.vadyarascan --yara-file rules.yar --pid 4321
# File objects in memory and extraction
vol -f mem.raw windows.filescan
vol -f mem.raw -o ./dump windows.dumpfiles --virtaddr 0xfa8001234560
# Registry: hives, a key, UserAssist
vol -f mem.raw windows.registry.hivelist
vol -f mem.raw windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"
vol -f mem.raw windows.registry.userassist
# Machine-readable output for timelines
vol -r csv -f mem.raw windows.pstree > pstree.csv
```

**Version note:** Volatility 3 2.x has reorganised detection plugins. In
recent releases several live under `windows.malware.*` (for example
`windows.malware.malfind`, `windows.malware.hollowprocesses`,
`windows.malware.ldrmodules`, `windows.malware.psxview`), with older names
kept as deprecated aliases for a period. Run `vol -h` to see exactly which
plugins and names your build provides. `hollowprocesses`, `psxview`,
`cmdscan`/`consoles`, `mftscan` and similar arrived in 2.x releases; PTE-based
injection scanners such as `ptemalfind` exist only in some builds/community
plugin sets - use them where available, do not assume them.

Other useful plugins: `windows.getsids`, `windows.privileges`,
`windows.envars`, `windows.vadinfo`, `windows.modules` / `windows.modscan`,
`windows.driverscan`, `windows.ssdt`, `windows.callbacks`, `windows.sessions`,
`windows.netstat`, `timeliner.Timeliner` (all timestamped artefacts).

## Reading the results

| Observation | Plugins | What it can mean | Next step |
|---|---|---|---|
| Process in psscan, not in pslist | pslist vs psscan (psxview) | Terminated process still in pool memory (benign) **or** DKOM-unlinked process (T1014) | Check exit time; if no exit time and threads exist -> hiding |
| Wrong parent | pstree | `lsass.exe`/`services.exe` not child of `wininit.exe`; `svchost.exe` not child of `services.exe`; Office spawning `cmd`/`powershell` | cmdline, user SID, start time vs boot |
| Duplicate system process | pslist | Second `lsass.exe`, misspelt names (`scvhost.exe`), system binary from wrong path (T1036) | dlllist path, dumpfiles, hash |
| `PAGE_EXECUTE_READWRITE` private region with MZ header or shellcode | malfind | Injected PE/shellcode (T1055) | Disassemble, vadyarascan, dump, `malware-triage` |
| DLL with False in InLoad/InInit/InMem | ldrmodules | Unlinked/reflectively loaded DLL (T1620) | Compare to dlllist; dump the VAD |
| Image base mapped file differs from PEB path | hollowprocesses | Process hollowing (T1055.012) | Dump both, compare with on-disk binary |
| Handle to `\Device\NamedPipe\...` with random or known-bad name | handles | C2 pipe / post-exploitation framework pipe | Cross-check Sysmon 17/18, `hunt-lateral-movement` |
| Process handle to `lsass.exe` with read access from unusual process | handles | Credential dumping (T1003.001) | EDR, Sysmon 10 |
| Service with binary in user-writable path or `ServiceDll` anomalies | svcscan | Persistence (T1543.003) | Registry, `hunt-windows-persistence` |
| Connection from `rundll32`/`regsvr32`/`notepad` | netscan | Injected implant or LOLBin proxy (T1218) | Owner PID -> malfind |
| Unknown driver, SSDT/callback hooks | modscan, driverscan, ssdt, callbacks | Rootkit (T1014) | Dump driver, verify signature |

## MemProcFS alternative

MemProcFS mounts a memory image as a virtual file system - fast for
browsing and bulk export.

```powershell
# Windows: mount as M:, enable forensic mode (timeline, CSVs, findevil)
MemProcFS.exe -device C:\case\mem.raw -forensic 1
# Optional: add pagefile for more complete virtual memory (check syntax for your version)
MemProcFS.exe -device C:\case\mem.raw -pagefile0 C:\case\pagefile.sys -forensic 1
```

Useful paths (forensic mode): `M:\forensic\timeline\` (timeline CSVs),
`M:\forensic\csv\` (process, net, handles, services), `M:\forensic\findevil\`
(heuristic injection/anomaly findings), `M:\name\` and `M:\pid\` (per process
memory, modules, VADs), `M:\registry\`. Linux builds mount via FUSE. Treat
findevil output like any automated hit - verify.

## Linux analysis

```bash
vol -f host01.lime banners.Banners              # identify exact kernel string
vol -f host01.lime linux.pslist
vol -f host01.lime linux.pstree
vol -f host01.lime linux.psaux                  # command lines
vol -f host01.lime linux.bash                   # bash history from memory, incl. unsaved commands
vol -f host01.lime linux.lsof --pid 1234
vol -f host01.lime linux.sockstat               # sockets per process (version-dependent)
vol -f host01.lime linux.malfind
vol -f host01.lime linux.lsmod
vol -f host01.lime linux.check_modules          # modules hidden from the module list
vol -f host01.lime linux.check_syscall          # syscall table hooks
vol -f host01.lime linux.envars
vol -f host01.lime linux.elfs --pid 1234 --dump  # dump ELF images (flag names vary by version)
```

Also `linux.check_idt`, `linux.tty_check`, `linux.keyboard_notifiers`,
`linux.hidden_modules` (newer releases), `linux.mountinfo`.

## Symbols (most common failure)

- **Windows:** Volatility 3 downloads the kernel PDB from the Microsoft
  symbol server on first use and caches an ISF file in its `symbols`
  directory. Offline analysis workstations need pre-downloaded symbol packs
  (published by the Volatility Foundation) or a one-time online run.
  Error `Unsatisfied requirement ... symbol_table_name` = symbols not found.
- **Linux:** needs an ISF built with `dwarf2json` from the **exact** kernel's
  `vmlinux` with debug info (distro debug-symbol packages: `-dbg`/`-debuginfo`/
  `dbgsym`) plus `System.map`. Match the `banners.Banners` string exactly; a
  minor build mismatch produces garbage or no output. Community ISF
  repositories exist for common distro kernels - verify the banner match.
- Use `isfinfo` to list ISF files Volatility can see; `-s <dir>` to add a
  symbol directory.

## Verdict table

| Verdict | Evidence that moves it |
|---|---|
| True Positive | Injected/hollowed code or hidden process confirmed by two plugins and a YARA/disassembly/IOC match, or tied to a malicious network connection |
| Benign True Positive | RWX regions belong to a known JIT/security product, verified by module path and signer |
| False Positive | Plugin artefact from smear or terminated process; legitimate software with expected behaviour |
| Needs more data | Symbols unresolved, image incomplete (VBS, acquisition errors), pagefile missing - re-acquire or use EDR telemetry |

## False positives & benign look-alikes

- malfind hits in .NET, Java, JavaScript engines (browsers), and EDR/AV
  processes that legitimately use RWX/JIT memory.
- psscan entries for processes that exited cleanly (exit time set).
- ldrmodules "False" columns for the main executable mapping and for some
  WoW64 and .NET native images.
- Security products hooking/injecting into every process.
- netscan entries in CLOSED/TIME_WAIT state long after the process exited.

## Pitfalls

- Acquiring memory after running a dozen live-response tools (overwritten
  free pages, extra processes).
- Writing the dump to the suspect disk, overwriting deleted-file evidence.
- Separating `.vmem` from its `.vmss`/`.vmsn` metadata.
- Building LiME on the suspect host (installs compilers/headers, changes disk).
- Treating Volatility 2 profiles/plugins guidance as valid for Volatility 3
  (different names and options).
- Reading process times without confirming they are UTC in your output.
- Uploading memory-dumped payloads to public sandboxes - see `malware-triage`
  TLP rules.

## Output

- Memory image + hash + acquisition notes (tool, version, start/end UTC,
  operator) logged via `evidence-handling`.
- Plugin outputs as CSV/JSON in the case folder; key findings as rows in the
  incident timeline (`timeline-analysis`).
- Dumped regions/files with SHA-256 for `malware-triage`; network IOCs and
  mutex/pipe names to `threat-intel-ioc`; YARA rules to `yara-rules`.
  Entry point `/forensics`; agent forensic-analyst.

## References

- MITRE ATT&CK: T1055 Process Injection, T1055.012 Process Hollowing,
  T1620 Reflective Code Loading, T1003.001 LSASS Memory, T1014 Rootkit,
  T1036 Masquerading, T1543.003 Windows Service, T1218 System Binary Proxy
  Execution.
- Volatility 3 documentation (Volatility Foundation) and `vol -h`.
- MemProcFS wiki (ufrisk/MemProcFS on GitHub).
- AVML (microsoft/avml) and LiME (504ensicsLabs/LiME) READMEs.
- "The Art of Memory Forensics" (Ligh, Case, Levy, Walters).
- NIST SP 800-86; RFC 3227 order of volatility.
