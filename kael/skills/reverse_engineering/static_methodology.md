---
name: Static Analysis Methodology
description: Triage-first reverse engineering workflow for malware analysis
category: reverse_engineering
priority: high
---

# Static Analysis Methodology

## Overview

This skill guides you through static analysis of malware samples using a triage-first approach. Always perform static analysis before dynamic execution to understand what you're dealing with.

## Mandatory Workflow

### Phase 1: Initial Triage (ALWAYS START HERE)

**Step 1: File Classification**
```
Use: file_triage(sample_path)
```

**What to look for:**
- File type (PE, ELF, script, document)
- File size (sanity check, > 500MB is suspicious)
- Entropy levels:
  - < 1.0 = Compressed or empty sections
  - 1.0-6.0 = Normal executable
  - > 7.0 = Packed or encrypted (HIGH PRIORITY for unpacking)
- Packer detection (UPX, MPRESS, Themida, etc.)
- Hash values for reputation lookups

**Decision Point:**
- If entropy > 7.0 or packer detected → Skip to Phase 3 (Unpacking)
- If entropy normal → Continue to Phase 2

---

### Phase 2: String & IOC Extraction

**Step 2: Extract Strings**
```
Use: extract_strings(sample_path)
```

**What to look for:**
- **URLs/IPs/Domains** = Network IOCs (potential C2)
- **File paths** = Dropper behavior, persistence locations
- **Registry keys** = Persistence mechanisms
- **Mutex names** = Process synchronization, single-instance locks
- **Crypto artifacts** = AES S-box, Base64 tables (encryption used)
- **Emails** = Exfiltration targets or C&C contacts

**Red Flags:**
- Multiple HTTP/HTTPS URLs = Likely downloader/C2 client
- System32 paths + WriteProcessMemory imports = Code injection
- AppData/Startup paths = Persistence
- Base64/AES constants = Encrypted payloads or C2 traffic

---

### Phase 3: Signature Matching

**Step 3: YARA Scan**
```
Use: yara_scan(sample_path, use_bundled_rules=True)
```

**What to look for:**
- **Malware family matches** = Known threat (Cobalt Strike, Meterpreter, Emotet)
- **Technique matches** = Anti-debug, anti-VM, code injection
- **Packer matches** = Confirms packer detection from triage
- **Crypto matches** = Encryption usage

**If YARA matches known family:**
- Document the family name
- Research known TTPs for that family
- Prioritize looking for family-specific IOCs

---

### Phase 4: Disassembly (For Unpacked Samples)

**Step 4: Radare2 Analysis**
```
Use: radare2_analyze(sample_path, analysis_depth="deep")
```

**What to look for:**
- **Entry point** = Where execution starts
- **Suspicious functions:**
  - Names with "decrypt", "decode", "unpack", "inject"
  - XOR loops = Decryption routines
- **Imports:**
  - VirtualAllocEx, WriteProcessMemory = Process injection
  - CreateRemoteThread, NtCreateThreadEx = Remote thread creation
  - URLDownloadToFile, InternetOpen = Download capability
  - RegSetValueEx = Registry modification
  - IsDebuggerPresent = Anti-debugging
- **Anti-analysis techniques:**
  - CPUID instruction = VM detection
  - RDTSC instruction = Timing checks
  - IsDebuggerPresent calls = Debugger detection

**Skip this step if:**
- Sample is packed (entropy > 7.0)
- Sample is scripted (Python, JavaScript, PowerShell)
- Quick triage is sufficient for your goals

---

## Decision Trees

### Is the Sample Packed?

```
file_triage shows entropy > 7.0 or packer detected?
  ↓ YES → Go to "Unpacking Strategy" skill
  ↓ NO  → Continue with radare2_analyze
```

### Should I Run It Dynamically?

```
Static analysis reveals:
  - Network IOCs (URLs, IPs) → YES, monitor network
  - File dropper behavior (CreateFile, WriteFile) → YES, watch filesystem
  - Process injection APIs → YES, capture memory
  - No suspicious behavior → MAYBE, quick sandbox run to confirm
  - Script/document → YES, scripts need execution context
```

### Do I Need to Unpack?

```
Packer detected OR entropy > 7.0?
  ↓ YES → Use unpack_generic tool
  ↓ NO  → Static analysis sufficient
```

---

## Common Patterns & What They Mean

### Pattern 1: Dropper
**Indicators:**
- URLDownloadToFile or InternetOpen imports
- CreateFile, WriteFile in GetTempPath
- WinExec or ShellExecute after download

**Action:** Dynamic analysis required to capture dropped payload

### Pattern 2: Injector
**Indicators:**
- VirtualAllocEx, WriteProcessMemory, CreateRemoteThread
- Process32First/Process32Next (process enumeration)
- OpenProcess with PROCESS_ALL_ACCESS

**Action:** Memory snapshot during execution to capture injected code

### Pattern 3: Cryptor/Packer
**Indicators:**
- High entropy (> 7.0)
- Small number of imports
- .text section with high entropy
- YARA matches for known packers

**Action:** Unpacking required before meaningful analysis

### Pattern 4: Persistence
**Indicators:**
- Registry Run keys in strings
- Scheduled task paths
- Startup folder paths
- Service creation APIs

**Action:** Document persistence mechanism, check sandbox for registry/file changes

---

## Tool Selection Guide

| Want to Know... | Use This Tool | Why |
|-----------------|---------------|-----|
| What is this file? | file_triage | Fast classification, no execution risk |
| What strings/IOCs does it contain? | extract_strings | Safe, high-value intel |
| Does it match known malware? | yara_scan | Signature matching, attribution |
| How does it work internally? | radare2_analyze | Deep analysis, but slow |
| What's inside the packer? | unpack_generic | Extract hidden payloads |

---

## Efficiency Tips

1. **Always start with file_triage** - 2 seconds, tells you if sample is worth analyzing
2. **Run extract_strings in parallel with YARA** - Both are fast, no dependencies
3. **Skip radare2 for scripts** - Disassembly doesn't help with Python/JS/PS1
4. **Don't unpack if not packed** - Wastes time, no benefit
5. **Stop if EICAR or test file** - file_triage MD5 will match known test files

---

## Example Workflow

**Scenario: Unknown PE file**

```
1. file_triage(sample.exe)
   → PE32, 45KB, entropy 7.2, UPX detected
   → Decision: High entropy + UPX = PACKED

2. extract_strings(sample.exe)
   → Few strings (expected for packed), but found "http://evil.com"
   → Decision: Network IOC present, will need dynamic analysis

3. yara_scan(sample.exe)
   → Matches: UPX_Packer, Generic_Trojan_Downloader
   → Decision: Likely a downloader, confirms unpacking needed

4. unpack_generic(sample.exe, method="upx")
   → Success: unpacked_upx.bin extracted
   → Decision: Analyze unpacked version

5. file_triage(unpacked_upx.bin)
   → PE32, 120KB, entropy 5.4 (normal)
   → Decision: Now safe for disassembly

6. radare2_analyze(unpacked_upx.bin)
   → Found: URLDownloadToFile, WinExec imports
   → Found: Function "download_and_execute" at 0x401000
   → Decision: Confirmed dropper behavior

7. Next: Dynamic analysis to capture payload
```

---

## Output Format

After static analysis, always summarize:

```
## Static Analysis Summary

**File Type:** PE32 executable
**Size:** 45,234 bytes
**Entropy:** 7.2 (packed)
**Packer:** UPX detected
**Hashes:**
- MD5: a1b2c3d4...
- SHA256: e5f6g7h8...

**Key Findings:**
- Downloader functionality (URLDownloadToFile)
- C2 URL: http://evil.com/payload.exe
- Persistence via HKCU\Software\Microsoft\Windows\CurrentVersion\Run
- Anti-debugging not detected

**YARA Matches:**
- UPX_Packer
- Generic_Trojan_Downloader

**Recommendation:** Dynamic analysis required to capture downloaded payload
```

---

## Safety Notes

- Static analysis is SAFE - no code execution
- Use file_triage first to detect file bombs (zip bombs, etc.)
- YARA rules may have false positives - verify with other tools
- Radare2 analysis can take 30+ seconds on large files
- Always check entropy before deciding to unpack

---

## Next Steps

After completing static analysis:
- If packed → Use "Unpacking Strategy" skill
- If needs execution → Use "Dynamic Analysis Workflow" skill
- If network IOCs found → Use "C2 Identification" skill
- Ready to summarize → Use "Report Synthesis" skill
