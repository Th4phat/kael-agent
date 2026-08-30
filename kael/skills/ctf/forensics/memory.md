---
name: ctf-forensics-memory
description: Memory forensics in CTFs — Volatility 2/3 plugins, process and registry artifacts, network connections, code injection, rootkit detection, and the common flag-hunting workflow
---

# CTF Forensics — Memory

The "I have a memory dump, find the flag" challenge. Volatility is the workhorse. Volatility 3 (Python 3) is the current default; legacy challenges use Volatility 2 (Python 2 — only if absolutely necessary).

## 1. The 5-Minute Memory Triage

```bash
vol -f memory.raw windows.info        # for Windows; or
vol -f memory.raw linux.banner        # for Linux
# Or
vol -f memory.raw banners.Banners     # cross-platform
```

**Identify the OS:**
- `vol -f memory.raw windows.info` — shows kernel version, build
- `vol -f memory.raw linux.banner` — shows Linux kernel banner

## 2. Windows Memory Forensics (the 80% case)

### First-pass plugins
```bash
vol -f memory.raw windows.pslist            # process list
vol -f memory.raw windows.pstree            # process tree
vol -f memory.raw windows.cmdline           # command lines
vol -f memory.raw windows.netscan           # network connections
vol -f memory.raw windows.netstat           # alternative
vol -f memory.raw windows.registry.hivelist # registry hives
vol -f memory.raw windows.registry.printkey --key 'Software\Microsoft\Windows\CurrentVersion\Run'  # autorun
vol -f memory.raw windows.filescan          # file objects in memory
vol -f memory.raw windows.handles           # process handles
vol -f memory.raw windows.dlllist --pid <pid>   # DLLs of a process
vol -f memory.raw windows.cmdline --pid <pid>  # command line of a process
vol -f memory.raw windows.envars --pid <pid>    # environment variables
vol -f memory.raw windows.getsids --pid <pid>   # SIDs
vol -f memory.raw windows.vadinfo --pid <pid>   # VAD regions (memory layout)
vol -f memory.raw windows.malfind           # suspicious memory regions
vol -f memory.raw windows.modules           # kernel modules
vol -f memory.raw windows.driverscan        # driver scan
vol -f memory.raw windows.driverirp         # driver IRP hooks
vol -f memory.raw windows.ssdt               # SSDT hooks
vol -f memory.raw windows.sessions          # logon sessions
vol -f memory.raw windows.hashdump          # SAM hashes
vol -f memory.raw windows.cachedump         # MSCache v2
vol -f memory.raw windows.lsadump           # LSA secrets
vol -f memory.raw windows.crashinfo         # crash details
vol -f memory.raw windows.timeliner         # timeline
```

### Find the flag
The flag is often:
- **In a process's memory** (cmdline, environment, or a file it read)
- **In a file's content** (dumped from VAD regions)
- **In a registry value** (recent docs, userassist, shimcache, amcache)
- **In a network connection's buffer** (exfil URL or command)
- **In a process's command line**

```bash
# Scan all process memory for a string
strings -e l memory.raw | grep -iE "ctf|flag" | head -20

# Or vol plugin
vol -f memory.raw windows.vadyarascan --yara-file rules.yar
```

### File extraction
```bash
# Find files in memory
vol -f memory.raw windows.filescan | tee files.txt
# Extract a file (Volatility 3 doesn't always support dumpfiles; Volatility 2 does)
# Volatility 2:
vol -f memory.raw --profile=Win10x64_18362 dumpfiles -Q 0x... -o /tmp/dump
# Volatility 3: use windows.dumpfiles or filescan + manual carving
```

### YARA scan
```bash
# Scan for a YARA rule
vol -f memory.raw windows.vadyarascan --yara-file rules.yar
vol -f memory.raw windows.yarascan --yara-file rules.yar   # entire process
```

### Example YARA rule for "find the flag"
```yara
rule CTFFlag
{
    strings:
        $flag = /CTF\{[^}]+\}/
        $flag2 = /FLAG\{[^}]+\}/
        $flag3 = /flag\{[^}]+\}/
    condition:
        any of them
}
```

## 3. Linux Memory Forensics

```bash
vol -f memory.raw linux.pslist
vol -f memory.raw linux.pstree
vol -f memory.raw linux.bash               # bash history from memory
vol -f memory.raw linux.lsmod              # loaded kernel modules
vol -f memory.raw linux.lsof               # open files
vol -f memory.raw linux.proc.Maps --pid <pid>
vol -f memory.raw linux.malfind
vol -f memory.raw linux.netstat
vol -f memory.raw linux.tty_check          # suspicious tty sessions
```

**`linux.bash`** is the killer plugin — it recovers bash history from each process's heap. The flag is often in a command line.

```bash
# Find the user who ran something interesting
vol -f memory.raw linux.bash | head -50
```

### Other Linux artifacts
- `linux.proc.Maps` — process memory mappings
- `linux.proc.MemMap` — physical memory layout
- `linux.sockstat` / `linux.netstat` — network connections
- `linux.envars` — environment variables (often have secrets)
- `linux.keyboard_notifiers` — keyboard sniffer detection

## 4. macOS Memory Forensics

```bash
vol -f memory.raw mac.pslist
vol -f memory.raw mac.lsmod
vol -f memory.raw mac.lsof
vol -f memory.raw mac.netstat
vol -f memory.raw mac.bash
vol -f memory.raw mac.malfind
```

## 5. Network Connection Analysis

```bash
# Windows
vol -f memory.raw windows.netscan
# Linux
vol -f memory.raw linux.netstat
# Look for:
#  - Connections to suspicious IPs (paste into VirusTotal / abuse.ch)
#  - Listening services that shouldn't be there
#  - Connections to known C2 ports
```

## 6. Process Code Injection Detection

The classic "this is a memory dump of a Windows box, find the malware":

```bash
# 1. List processes; look for:
#   - Unsigned / unknown process names
#   - Processes with no parent
#   - cmd.exe / powershell.exe spawned by non-shell parents
vol -f memory.raw windows.pstree

# 2. Find suspicious memory regions
vol -f memory.raw windows.malfind
# Shows RWX regions, mismatched mapped files, suspicious allocation patterns

# 3. Dump a suspicious process for offline analysis
vol -f memory.raw windows.memmap --pid <pid> --dump
# Or, more reliably, dump using `vol -f memory.raw windows.pslist --pid <pid> --dump`
```

### Common injection signs
- `cmd.exe` / `powershell.exe` as a child of `winword.exe` / `excel.exe` / `outlook.exe` → likely phishing
- `svchost.exe` running without `-k` arguments → suspicious
- A process with `PAGE_EXECUTE_READWRITE` memory and no associated mapped file → shellcode

## 7. Registry Forensics

```bash
# Find the registry hives in memory
vol -f memory.raw windows.registry.hivelist
# Look at a specific key
vol -f memory.raw windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"
vol -f memory.raw windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"
# UserAssist (recently run programs)
vol -f memory.raw windows.registry.userassist
# Shimcache (program execution evidence)
vol -f memory.raw windows.registry.shimcache
# Amcache (program execution + metadata)
vol -f memory.raw windows.registry.amcache
```

**UserAssist, Shimcache, Amcache, Prefetch** are the four "what ran on this box" artifacts.

## 8. The "Hidden Process" Detection

Volatility's `psxview` (V2) / cross-view in V3 reveals processes that are hidden from the OS:

```bash
# Volatility 2
vol -f memory.raw --profile=Win10x64_18362 psxview
# Output: Process, pslist, psscan, thrdproc, pspcid, csrss, session
# A 'False' in pslist + 'True' in others = DKOM rootkit hiding
```

## 9. Credential Dumping from Memory

```bash
# SAM hashes (Windows)
vol -f memory.raw windows.hashdump
# LSA secrets
vol -f memory.raw windows.lsadump
# Cached domain logon
vol -f memory.raw windows.cachedump
# Mimikatz-style credential recovery
vol -f memory.raw windows.mimikatz      # if mimikatz plugin is installed
# Or use pypykatz (pure Python)
pypykatz rekall memory.raw    # or similar
```

## 10. Timeline Generation

```bash
# Volatility 2
vol -f memory.raw --profile=Win10x64_18362 timeliner
# Volatility 3
vol -f memory.raw windows.timeliner
# Or use Plaso (log2timeline) for cross-artifact timelines
log2timeline.py memory.raw timeline.plaso
psort.py timeline.plaso "date > '2024-01-01'" -o l2tcsv -w timeline.csv
```

## 11. The "Decrypt the Memory" Challenge

When the memory is encrypted (BitLocker, LUKS, VeraCrypt, custom):
1. Look for the **encryption key in memory** (FVE driver, dm-crypt, etc.)
2. **Hibernation file** (`hiberfil.sys`) can be converted to a memory dump with `imagecopy` or `hibr2dmp`
3. **Crash dump** (`MEMORY.DMP`) is the same as a memory dump

## Tooling

```bash
# Volatility 3
pip install volatility3
vol --help

# Volatility 2 (Python 2 — for legacy challenges)
git clone https://github.com/volatilityfoundation/volatility
python2 vol.py -f memory.raw --profile=Win7SP1x64 pslist

# pypykatz (Mimikatz in pure Python)
pip install pypykatz
pypykatz rekall memory.raw
```

## Common Pitfalls

- **Wrong profile** (V2) — `--profile=Win10x64_18362`; the wrong profile gives garbage or crashes
- **Volatility 3 doesn't have all V2 plugins** — use the equivalent V3 name (e.g. `windows.pslist` instead of `pslist`)
- **Forgetting to set the symbol table** (V3) — for Linux, you need the right `linux-banner` symbol table; download with `vol -f memory.raw linux.banner`
- **Dumping a process with `pslist` doesn't give a usable executable** — use `windows.memmap --dump` and reconstruct the PE headers
- **The flag is XOR'd in memory** — search for `CTF` after XOR-decoding each candidate byte
- **Strings in non-ASCII encoding** — `strings -e l` (UTF-16LE, the Windows default)

## One-Liner Cheat Sheet

```bash
# Windows process tree
vol -f memory.raw windows.pstree

# Windows network connections
vol -f memory.raw windows.netscan

# Linux bash history
vol -f memory.raw linux.bash

# Find any string that looks like a flag
strings -e l memory.raw | grep -E "CTF\{|FLAG\{|flag\{"

# YARA scan
vol -f memory.raw windows.vadyarascan --yara-file flag.yar

# Registry autorun
vol -f memory.raw windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"

# Hashdump
vol -f memory.raw windows.hashdump
```
