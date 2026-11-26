---
name: yara-rules
description: Writing, testing and deploying YARA rules for defenders - file and memory signatures for malware families, tools and web shells found during IR or hunting. Covers rule structure (meta, strings, condition), text / hex / regex strings and modifiers (ascii, wide, nocase, fullword, xor, base64), conditions (uint16(0) == 0x5A4D, filesize, counts, offsets, for loops), the pe, math and hash modules (imphash, imports, sections, entropy, signatures), performance and atoms, goodware testing against false positives, YARA-X (yr) notes, retro-hunting across files, EDR fleets and memory (Volatility, Velociraptor), and naming / metadata conventions. Use when asked to "write a YARA rule", "turn this sample into a signature", "scan the estate for this malware", "why is my YARA rule slow", or "YARA false positives".
---

# YARA rules for defenders

A YARA rule describes what makes a family or tool recognisable, not what makes
one sample unique. Hash lists already cover single samples; YARA earns its keep
when the next build still matches and the operating system's own files do not.

## When to use

- A sample from an incident (`malware-triage`) needs a signature to sweep the estate.
- Hunting across file shares, web roots, mail attachments or memory for a known family or tool.
- Building a rule set for an EDR, mail gateway, sandbox or scanner (Velociraptor, THOR/Loki-style scanners).
- Reviewing a public rule before deploying it.

## Ground rules

- **No rule ships without a goodware run.** Scan a clean corpus (at minimum a
  clean Windows `System32`/`SysWOW64`, Program Files of a standard build, and
  common installers) and record zero hits - or explain each hit.
- **No rule ships without a positive set.** At least the sample(s) it was built
  from plus, ideally, one other variant of the family; record hashes in `meta`.
- **Hash + acquisition time + source before analysis** of any sample
  (`evidence-handling`). Work on samples only inside an isolated analysis VM;
  never execute them on a production host to "test" a rule.
- **A YARA match is a lead, not a verdict.** Confirm by triage (`malware-triage`)
  before containment, especially for broad (`generic`/`suspicious`) rules.
- **Scanning production systems is a change.** Memory and full-disk scans load
  CPU and I/O; schedule them and get approval for critical servers.

## Workflow

1. **Triage the sample** (`malware-triage`): file type, packer, imports,
   strings, configuration, related samples. Identify what is *specific to the
   family* (unique mutex, PDB path fragment, C2 URI format, crypto constants,
   custom code sequences) versus what is generic (compiler stubs, common libraries).
2. **Pick 5-15 candidate strings**: unusual readable strings (error messages,
   format strings, command names), byte sequences from distinctive code, and
   structural properties (imports, sections, size).
3. **Write the condition** with a cheap structural pre-check (file magic,
   `filesize`) and a threshold over string groups (`2 of ($s*)`) so one
   recompiled string does not break the rule.
4. **Test positives**: all known samples and variants must match.
5. **Test goodware**: zero hits on the clean corpus; tighten strings that hit.
6. **Check performance**: no warnings from the compiler about slow strings;
   time a scan of a large directory.
7. **Document** (`meta`) and version the rule in the detection repo
   (`detection-engineering`); deploy to the scanning platform.
8. **Retro-hunt** across files and memory, triage hits, feed results to
   `threat-intel-ioc` and the incident timeline.

## Rule anatomy

```yara
import "pe"

rule MAL_Win_ExampleLoader_Nov26 : loader windows
{
    meta:
        description = "Detects ExampleLoader family by config marker, C2 URI format and decryption routine"
        author      = "Blue Team"
        date        = "2026-11-20"
        reference   = "internal case IR-2026-0142"
        hash1       = "<sha256 of sample 1>"
        hash2       = "<sha256 of sample 2>"
        score       = 80
        tlp         = "TLP:AMBER"

    strings:
        // readable, family-specific strings
        $s1 = "cfg_marker_v2" ascii
        $s2 = "/api/%s/check?id=%08x" ascii wide
        $s3 = "Global\\ExampleLoaderMtx" ascii wide
        // code: decryption loop (bytes from disassembly; wildcards over registers/offsets)
        $c1 = { 8A 04 0? 34 ?? 88 04 0? 4? 3B ?? 72 F? }
        // noisy alone, useful in combination
        $w1 = "VirtualProtect" ascii fullword
        $w2 = "WinHttpOpen" ascii fullword

    condition:
        uint16(0) == 0x5A4D
        and filesize < 2MB
        and (
            (2 of ($s*) and $c1)
            or (all of ($s*))
            or ($c1 and 1 of ($s*) and all of ($w*))
        )
}
```

Placeholders in `meta` (hashes) must be filled with real values; never publish
invented hashes or references.

## Strings

| Kind | Syntax | Notes |
|---|---|---|
| Text | `$a = "text"` | default ASCII, case-sensitive |
| Wide (UTF-16LE) | `$a = "text" wide` / `ascii wide` | Windows API strings are often wide; add both if unsure |
| Case-insensitive | `nocase` | costs performance; use only when case really varies |
| Whole word | `fullword` | delimited by non-alphanumerics; cuts FPs on short words |
| XOR | `xor` or `xor(0x01-0xff)` | matches single-byte XOR-encoded variants |
| Base64 | `base64`, `base64wide` | matches the string base64-encoded (3 alignments); avoid short strings |
| Private | `private` | matches but is not reported in output |
| Hex | `{ 4D 5A ?? ?? [2-8] (6A 40 \| 68 00 30 00 00) }` | `??` wildcard byte, `?A` nibble wildcard, `[n-m]` jump, `( \| )` alternatives, `~00` not-byte |
| Regex | `$r = /https?:\/\/[a-z0-9.-]{4,64}\/gate\.php/ nocase` | anchor with a literal prefix; avoid `.*` and leading wildcards |

## Conditions

| Expression | Meaning |
|---|---|
| `uint16(0) == 0x5A4D` | MZ header (PE). ELF: `uint32(0) == 0x464C457F`. ZIP/OOXML: `uint32(0) == 0x04034B50` |
| `filesize < 5MB` | size bound (also `KB`) |
| `#s1 > 3` | count of matches of `$s1` |
| `@s1[1] < 0x400` | offset of the first match |
| `$s1 at 0`, `$s1 in (0..1024)` | positional matches |
| `any of them`, `2 of ($s*)`, `all of ($w*)` | sets |
| `for any i in (0..pe.number_of_sections - 1) : ( ... )` | loop over module arrays |
| `for all of ($s*) : ( @ < 0x10000 )` | apply a condition to every string in a set |
| `none of ($fp*)` | exclusion strings (newer YARA versions; else `not any of ($fp*)`) |

## Modules

```yara
import "pe"
import "math"
import "hash"

rule SUSP_PE_HighEntropy_Section_RWX_Unsigned
{
    meta:
        description = "Hunting rule: unsigned PE with a writable+executable high-entropy section (packer/loader heuristic)"
        author = "Blue Team"
        date = "2026-11-20"
        score = 40
    condition:
        uint16(0) == 0x5A4D
        and filesize < 10MB
        and pe.number_of_signatures == 0
        and for any i in (0..pe.number_of_sections - 1) : (
            (pe.sections[i].characteristics & pe.SECTION_MEM_EXECUTE) != 0
            and (pe.sections[i].characteristics & pe.SECTION_MEM_WRITE) != 0
            and math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) > 7.2
        )
}
```

Useful functions and fields:

- `pe.imphash() == "<md5>"` - import hash (cluster related builds; brittle across compilers).
- `pe.imports("kernel32.dll", "VirtualAllocEx")`, `pe.exports("ServiceMain")`, `pe.is_dll()`.
- `pe.number_of_signatures`, `pe.signatures[i].issuer`, `pe.signatures[i].subject`, `pe.signatures[i].serial`.
- `pe.timestamp`, `pe.pdb_path` (where supported), `pe.rich_signature`, `pe.sections[i].name`.
- `math.entropy(offset, size)`, `math.entropy(0, filesize)`.
- `hash.sha256(0, filesize) == "<lowercase hex>"` - exact-sample rules only; prefer hash lists.
- Other modules: `elf`, `dotnet`, `macho`, `time`, `console` (debug output).

## Performance (atoms)

YARA does not scan for whole strings; it extracts short **atoms** (up to 4
bytes) from each string, searches for those, and only verifies full strings
where an atom hits. Bad atoms = slow scans everywhere.

- Strings should be at least 4 bytes of distinctive content. Avoid `{ 00 00 00 00 }`,
  `{ FF FF FF FF }`, `{ 90 90 90 90 }`, `"MZ"` as a string (use `uint16(0)` instead).
- Do not start hex strings with wildcards or jumps; put the most unusual bytes first or in the middle.
- Regex: give it a literal of 4+ characters; avoid `/.*x/`, `/[a-z]+foo/` at the start, and unbounded `.*` / `{n,}` quantifiers.
- `nocase`, `xor` and `base64` multiply atoms - use them on long, specific strings only.
- All strings of all rules are searched before conditions are evaluated, so a
  cheap `filesize`/magic check does not skip string scanning - it does skip
  expensive module loops and limits false positives.
- Compile with `yarac` and read warnings (e.g. "string is slowing down scanning").
  YARA-X reports similar warnings.

## Testing against goodware

```bash
# Positives: every known sample must match (inside the isolated analysis VM)
yara -s -r rules/mal_exampleloader.yar samples/positive/

# Goodware: expect zero output; -r recursive, -p threads, -w suppress warnings only after reading them
yara -r -p 8 rules/mal_exampleloader.yar /mnt/goodware/Windows/System32/ /mnt/goodware/ProgramFiles/

# Count and time a large corpus scan
time yara -r -p 8 rules/ /mnt/goodware/ | wc -l

# Compile-time checks (warnings for slow strings)
yarac rules/mal_exampleloader.yar /tmp/compiled.yarc
```

Goodware sources: a clean, patched Windows image of each version you run,
Linux distribution packages, your own software build artifacts, common
installers. Tools that help: yarGen (builds candidate strings while excluding a
goodware string database), YARA-CI (runs rules against a goodware corpus on
GitHub pull requests), VirusTotal Retrohunt (if licensed) for both FP and variant checks.

## YARA-X notes

YARA-X is VirusTotal's Rust rewrite of YARA; CLI `yr` (`yr scan`, `yr check`,
`yr fmt`, `yr compile`). It is designed to be largely compatible with YARA
rules, but:

- It is stricter: some constructs legacy YARA accepted (e.g. ambiguous or
  malformed regexes, certain escape sequences, duplicate identifiers) produce
  errors - run `yr check` on the whole rule set before switching.
- Some legacy modules are not available or behave differently (check the YARA-X
  docs for the current module list); rules using them must be adapted.
- Error messages and slow-pattern warnings are more detailed - use them to fix
  performance issues even if you deploy on classic YARA.
- Keep the rule set compatible with whichever engine your EDR / scanner embeds;
  test on that engine, not only on your workstation.

## Retro-hunting

| Target | How | Notes |
|---|---|---|
| Files on one host | `yara -r -p 4 rules.yar C:\Users\` | read-only; exclude huge VM/backup files |
| Fleet files | Velociraptor `Generic.Detection.Yara.Glob` / `Windows.Detection.Yara.Process` artifacts, or EDR's YARA feature | throttle CPU; scope globs (user profiles, web roots, ProgramData) |
| Process memory (live) | `yara -p 4 rules.yar <pid>` (needs admin/root) | unpacked payloads are visible in memory; avoid touching lsass unless approved |
| Memory image | Volatility 3 `yarascan.YaraScan` / `windows.vadyarascan.VadYaraScan` with `--yara-file` | preferred: no live-system impact (`memory-forensics`) |
| Disk image | mount read-only, scan with `yara -r` | on a forensic copy (`windows-forensics`, `linux-forensics`) |
| Mail / web roots | scan attachments store, `wwwroot`, upload dirs | web-shell rules (`hunt-webshells`) |
| Historic corpus | VirusTotal Retrohunt / internal sample store | variant discovery, not estate coverage |

Report each hit with: host, path, file hash, size, timestamps, matched rule and
strings (`-s`), and scan time. Collect the file through evidence handling
before deleting anything.

## Naming and metadata

Prefix by intent so consumers can route by severity:

| Prefix | Meaning | Typical score |
|---|---|---|
| `MAL_` | malware family, high confidence | 75-100 |
| `HKTL_` | hacking tool / offensive framework | 60-90 |
| `WEBSHELL_` | web shell | 70-100 |
| `EXPL_` | exploit code or exploitation artifacts | 60-90 |
| `SUSP_` | suspicious characteristics, hunting quality | 30-60 |
| `PUA_` | potentially unwanted / dual-use admin tool | 20-50 |

Pattern: `<PREFIX>_<OS/FileType>_<Family/Tool>_<Variant/Date>` (e.g.
`HKTL_Win_Mimikatz_Strings_Nov26`). Required meta: `description`, `author`,
`date`, `reference` (case ID or public report title), `hash1..n`, `score`;
optional `modified`, `tlp`, `mitre` (e.g. `"T1003.001"`). This aligns with
widely used public conventions (e.g. Florian Roth's YARA style guide).

## False positives & benign look-alikes

| Pattern | Benign source | Mitigation |
|---|---|---|
| API-name strings (`VirtualAlloc`, `CreateRemoteThread`) | Every installer, game, AV product | Never as the sole condition; combine with family-specific strings |
| Packer heuristics (UPX, high entropy) | Legitimate packed software, installers | `SUSP_` only; exclude signed binaries |
| Offensive tool strings | Security products, red team tooling, AV signature files | Expect hits in AV quarantine/definition folders; exclude those paths in scans |
| Web-shell keywords (`eval(`, `base64_decode`) | CMS plugins, frameworks | Require combination with request-parameter access and obfuscation |
| Strings in documentation | Analyst notes, threat reports, the rule file itself | Exclude the scanning tool's own directories |

| Verdict | Evidence |
|---|---|
| True Positive | Matched strings are family-specific, file context fits (location, timestamps, parent), triage confirms |
| Benign True Positive | Real tool, sanctioned use (red team, admin), documented |
| False Positive | Match on generic strings / goodware - tighten rule, add to goodware corpus |
| Needs more data | Match on packed/partial file or memory region; collect and analyse (`malware-triage`) |

## Pitfalls

- Rules built from a single sample's random-looking strings (compiler-generated
  GUIDs, timestamps) - match only that build.
- Forgetting `wide` - Windows malware stores many strings as UTF-16LE.
- Over-using `nocase` and regex - slow rules get disabled by the platform team.
- Using `hash.*` or `pe.imphash()` as the main logic - use hash IOCs instead.
- Not testing on the target engine (EDR embedded YARA versions lag behind).
- Scanning memory of protected processes or critical servers without approval.
- Publishing rules with real victim names, internal paths or TLP:RED data in `meta`.

## Output

- `.yar` rule file with complete metadata, positive and goodware test results,
  compiler warnings resolved, deployment scope.
- Retro-hunt report: hits table (host, path, hash, rule, strings, time) with
  triage verdicts; coverage statement (hosts and paths scanned, failures).
- Hand-offs: `malware-triage` (sample analysis), `memory-forensics`,
  `hunt-webshells`, `threat-intel-ioc` (indicators and sharing),
  `detection-engineering` (versioning, review), `incident-response` for confirmed hits.

## References

- YARA documentation (Writing YARA rules; modules: pe, math, hash, elf, dotnet)
- YARA-X documentation (differences from YARA, CLI `yr`)
- Florian Roth, YARA style guide and performance guidelines (Neo23x0); yarGen
- YARA-CI (VirusTotal); VirusTotal Retrohunt documentation
- Volatility 3 documentation (yarascan plugins); Velociraptor artifact reference
- MITRE ATT&CK: https://attack.mitre.org/techniques/T1027/, https://attack.mitre.org/techniques/T1505/003/
