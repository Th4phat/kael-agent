---
name: Memory Forensics
description: Process memory analysis for unpacked payloads and injected code
category: reverse_engineering
priority: low
---

# Memory Forensics

## Overview

Memory forensics captures malware behavior that only exists in memory - unpacked payloads, injected code, and decrypted configurations.

## When to Use

**ALWAYS use when:**
- Static analysis found process injection APIs (WriteProcessMemory, CreateRemoteThread)
- Sample is packed with in-memory unpacking (Themida, VMProtect)
- Sandbox detected process_vm_writev or ptrace syscalls
- Need to capture unpacked payload after runtime decryption

**SKIP when:**
- Sample is not packed (entropy < 6.0)
- No injection indicators
- Static unpacking was successful
- Sample crashed immediately (no time to inject)

---

## Usage

```
Use: memory_snapshot(
    run_dir="/workspace/.re-runs/<sha256>/",
    detect_injection=True,
    extract_pe=True
)
```

**Run AFTER sandbox_detonate completes**

---

## What It Captures

1. **Process memory dumps** (gcore)
   - Full memory state of each process
   - Heap, stack, loaded modules

2. **Extracted PE files**
   - Searches for MZ headers in memory
   - Validates PE structure
   - Extracts up to 10MB per PE

3. **Injection detection**
   - Shellcode patterns
   - Suspicious memory regions
   - Non-file-backed executable pages

---

## Interpreting Results

### Success: Injected Payload Found

```json
{
  "extracted_pes": [
    {
      "address": "0x400000",
      "size": 32768,
      "type": "PE",
      "extracted_to": "/workspace/.re-runs/.../extracted_pe_400000.bin"
    }
  ]
}
```

**Next steps:**
1. Run file_triage on extracted PE
2. Run yara_scan for family identification
3. Run extract_strings for IOCs

---

### No Injection Found

```json
{
  "extracted_pes": [],
  "injected_code": []
}
```

**Possible reasons:**
- Injection hadn't occurred yet (increase sandbox timeout)
- No injection behavior (false positive from static analysis)
- Process crashed before injection

---

## Timing Matters

**For in-memory unpackers:**
```
sandbox_detonate(sample.exe, timeout=10, snapshot_memory=True)
```
- Short timeout (10-30s) is sufficient
- Unpacker runs immediately
- Capture before malware exits

**For process injectors:**
```
sandbox_detonate(sample.exe, timeout=60, snapshot_memory=True)
```
- Longer timeout (60-120s)
- Wait for injection to complete
- Monitor syscalls for injection timing

---

## Example Workflow

```
Step 1: Static analysis detected CreateRemoteThread import

Step 2: sandbox_detonate(sample.exe, snapshot_memory=True, timeout=60)
  → Syscalls: process_vm_writev to PID 5678 at 45.2s

Step 3: memory_snapshot(run_dir="/workspace/.re-runs/abc123...")
  → Extracted: extracted_pe_7f000000.bin (45KB)

Step 4: file_triage(extracted_pe_7f000000.bin)
  → PE32 DLL, Cobalt Strike Beacon

Step 5: extract_strings(extracted_pe_7f000000.bin)
  → C2: agent.evil.com
```

---

## Limitations

- Requires CAP_SYS_PTRACE capability
- Process must still be running (not crashed)
- May miss short-lived injections
- Cannot dump from kernel space

---

## Next Steps

- Extracted PE found → Analyze it (file_triage, yara_scan, extract_strings)
- No extraction → Assume no memory-only payload
- Ready to report → Document memory artifacts
