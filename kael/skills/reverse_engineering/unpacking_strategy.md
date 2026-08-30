---
name: Unpacking Strategy
description: Multi-method approach to unpacking and decrypting malware
category: reverse_engineering
priority: high
---

# Unpacking Strategy

## Overview

This skill guides you through unpacking packed or encrypted malware to reveal the true payload. Unpacking is critical because packed samples hide their real behavior from static analysis.

## When to Unpack

**ALWAYS attempt unpacking if:**
- Entropy > 7.0 (indicates encryption/packing)
- YARA detected a known packer (UPX, MPRESS, Themida, etc.)
- Very few imports (< 10 for a normal executable)
- Small .text section but large overall file size
- Suspicious section names (.UPX0, .vmp0, .themida)

**SKIP if:**
- Entropy < 6.0 (likely not packed)
- Already unpacked in previous step
- Sample is a script (no packing concept for Python/JS)

---

## Detection: Is It Packed?

Use file_triage results to determine:

```json
{
  "entropy": 7.4,           // > 7.0 = PACKED
  "packer_detected": true,
  "packer_name": "UPX",
  "suspicious_indicators": [
    "High entropy in .text section: 7.8"
  ]
}
```

---

## Unpacking Methods

The tool supports 4 methods. Use "auto" to try all.

### Method 1: Auto (Recommended)
```
Use: unpack_generic(sample_path, method="auto")
```

**What it does:**
- Tries all methods in sequence
- Returns all successful extractions
- Best for unknown packers

**Use when:** You don't know which packer was used

---

### Method 2: UPX (Fast)
```
Use: unpack_generic(sample_path, method="upx")
```

**What it does:**
- Uses official UPX unpacker (`upx -d`)
- Works ONLY for UPX-packed files
- Very fast (< 1 second)

**Use when:**
- YARA matched "UPX_Packer"
- Entropy > 7.0 AND strings contain "UPX0", "UPX1"

**Success rate:** 95% for UPX, 0% for others

---

### Method 3: XOR Brute Force (Moderate)
```
Use: unpack_generic(sample_path, method="xor")
```

**What it does:**
- Tries common single-byte XOR keys (0x00, 0xFF, 0x42, 0x55, etc.)
- Checks if result starts with MZ (PE) or \x7fELF
- Extracts valid results

**Use when:**
- Custom packer or obfuscator
- Static analysis found XOR loops
- No known packer detected

**Success rate:** 30% for simple XOR, 0% for multi-byte or rolling XOR

---

### Method 4: Overlay Extraction
```
Use: unpack_generic(sample_path, method="overlay")
```

**What it does:**
- Extracts data after the end of the PE structure
- Common for installers and droppers
- Does NOT decompress, just extracts

**Use when:**
- File has "overlay" in suspicious indicators
- File size much larger than PE sections combined

**Success rate:** 100% if overlay exists, but may not be executable

---

### Method 5: Binwalk (Slow but Comprehensive)
```
Use: unpack_generic(sample_path, method="binwalk")
```

**What it does:**
- Scans for embedded files (PE, ELF, ZIP, etc.)
- Extracts everything it finds
- Can produce many false positives

**Use when:**
- Multi-stage dropper suspected
- Other methods failed
- Time is not critical

**Success rate:** 80% for embedded files, many false positives

---

## Interpreting Results

### Success: Unpacked Payload

```json
{
  "success": true,
  "detected_packers": ["upx"],
  "unpacked_files": [
    {
      "method": "upx",
      "output_path": "/workspace/.re-artifacts/unpacked_upx.bin",
      "size": 122880
    }
  ],
  "total_unpacked": 1
}
```

**Next steps:**
1. Run file_triage on unpacked file
2. Compare entropy (should be lower, 4.0-6.0 range)
3. Re-run full static analysis on unpacked version

---

### Failure: No Extraction

```json
{
  "success": true,
  "detected_packers": ["themida"],
  "unpacked_files": [],
  "total_unpacked": 0,
  "message": "No unpacked files extracted..."
}
```

**Possible causes:**
1. **Commercial packer** (Themida, VMProtect) - Tool doesn't support
2. **Custom packer** - Need specialized unpacker
3. **Malformed sample** - Intentionally broken to prevent analysis
4. **Not actually packed** - False positive from entropy

**Next steps:**
- Try memory-based unpacking (sandbox + memory_snapshot)
- Accept that static analysis is limited
- Focus on dynamic analysis

---

## Multi-Stage Unpacking

Some malware has multiple packing layers:

```
Stage 1: UPX-packed dropper
  ↓ unpack_generic(stage1, method="upx")
Stage 2: XOR-encrypted payload
  ↓ unpack_generic(stage2, method="xor")
Stage 3: Final payload (clear)
```

**Workflow:**
```
1. unpack_generic(sample.exe, method="auto")
   → Extracted: unpacked_upx.bin

2. file_triage(unpacked_upx.bin)
   → Entropy still 7.1 (still packed!)

3. unpack_generic(unpacked_upx.bin, method="xor")
   → Extracted: xor_42.bin

4. file_triage(xor_42.bin)
   → Entropy 5.2 (normal, unpacking complete)

5. Continue with static analysis on xor_42.bin
```

**Rule:** If entropy is still > 7.0 after unpacking, try again with different method.

---

## Memory-Based Unpacking

Some packers unpack in memory, not to disk. Use dynamic execution to capture:

```
Step 1: sandbox_detonate(packed.exe, snapshot_memory=True, timeout=10)
  → Let packer unpack itself in memory

Step 2: memory_snapshot(run_dir="/workspace/.re-runs/<hash>")
  → Extracts PE files from memory dump
  → Result: extracted_pe_400000.bin

Step 3: file_triage(extracted_pe_400000.bin)
  → Entropy 5.4 (successfully unpacked from memory)
```

**Use when:**
- Static unpacking fails
- Known in-memory packer (Themida, VMProtect)
- Packer has anti-tampering checks

---

## Decision Tree

```
Is entropy > 7.0 OR packer detected?
  ↓ NO → Skip unpacking
  ↓ YES
    ↓
Is packer UPX/MPRESS/ASPack?
  ↓ YES → unpack_generic(method="upx")
  ↓ NO
    ↓
Try auto method
  ↓
Did it extract anything?
  ↓ YES → Analyze unpacked file
  ↓ NO
    ↓
Try memory-based unpacking
  ↓
Did it work?
  ↓ YES → Analyze memory dump
  ↓ NO → Proceed with dynamic analysis, accept limited static intel
```

---

## Common Packer Profiles

### UPX (Easy)
**Detection:** YARA rule, "UPX0" strings, entropy 7.5+
**Method:** `method="upx"`
**Success Rate:** 95%
**Notes:** Most common packer, easiest to unpack

### MPRESS (Easy)
**Detection:** ".MPRESS1" section, entropy 7.8+
**Method:** `method="upx"` (UPX tool works on MPRESS)
**Success Rate:** 70%
**Notes:** Similar to UPX

### Themida/WinLicense (Hard)
**Detection:** ".themida" section, very high entropy 7.9+
**Method:** Memory-based only
**Success Rate:** 50% (requires perfect timing)
**Notes:** Commercial packer with anti-debugging

### VMProtect (Hard)
**Detection:** ".vmp0" section, entropy 7.9+
**Method:** Memory-based only
**Success Rate:** 30%
**Notes:** Virtualization-based obfuscation

### Custom XOR (Moderate)
**Detection:** XOR loops in disassembly, moderate entropy 6.5-7.5
**Method:** `method="xor"`
**Success Rate:** 30%
**Notes:** Hit-or-miss depending on key complexity

---

## Validation: Is Unpacking Successful?

After unpacking, verify with file_triage:

| Metric | Packed | Unpacked (Success) |
|--------|--------|-------------------|
| Entropy | > 7.0 | 4.0-6.0 |
| Imports | < 10 | 20+ |
| Sections | Suspicious names | Normal (.text, .data, .rdata) |
| Strings | Few/encrypted | Many readable |

**If entropy is still > 7.0:** Try another method or accept it's multi-stage

---

## Example Workflows

### Example 1: Simple UPX Packer

```
1. file_triage(sample.exe)
   → Entropy: 7.6, Packer: UPX

2. unpack_generic(sample.exe, method="upx")
   → Success: unpacked_upx.bin

3. file_triage(unpacked_upx.bin)
   → Entropy: 5.1 (normal)

4. extract_strings(unpacked_upx.bin)
   → 250 strings (previously had 12)
   → Found: "http://evil.com/c2"

5. radare2_analyze(unpacked_upx.bin)
   → 45 functions identified
   → Suspicious: "decrypt_config" at 0x401234
```

### Example 2: Multi-Layer Packer

```
1. file_triage(sample.exe)
   → Entropy: 7.8, Packer: Custom

2. unpack_generic(sample.exe, method="auto")
   → Extracted: overlay.bin (method=overlay)

3. file_triage(overlay.bin)
   → Entropy: 7.5 (still packed!)

4. unpack_generic(overlay.bin, method="xor")
   → Extracted: xor_55.bin

5. file_triage(xor_55.bin)
   → Entropy: 5.3 (unpacking complete!)
```

### Example 3: Memory-Based Unpacking

```
1. file_triage(sample.exe)
   → Entropy: 7.9, Packer: Themida

2. unpack_generic(sample.exe, method="auto")
   → No files extracted (Themida too complex)

3. sandbox_detonate(sample.exe, snapshot_memory=True, timeout=10)
   → Let it unpack itself

4. memory_snapshot(run_dir="/workspace/.re-runs/abc123...")
   → Extracted: extracted_pe_400000.bin

5. file_triage(extracted_pe_400000.bin)
   → Entropy: 5.6, PE32, normal imports
   → Success!
```

---

## Troubleshooting

### Issue 1: UPX Fails with "NotPackedException"
**Cause:** File is not actually UPX packed
**Solution:** Try method="auto" instead

### Issue 2: XOR Brute Force Finds Nothing
**Cause:** Multi-byte XOR key or more complex encryption
**Solution:** Try memory-based unpacking or accept limitation

### Issue 3: Binwalk Extracts 50+ Files
**Cause:** False positives from signature matching
**Solution:** Filter by size (> 10KB) and file type (PE/ELF only)

### Issue 4: Entropy Still High After Unpacking
**Cause:** Multi-layer packing
**Solution:** Re-run unpacking on extracted file

---

## Performance Tips

1. **Try UPX first** if detected - It's instant
2. **Skip XOR for large files** (> 10MB) - Takes too long
3. **Use binwalk as last resort** - Slow and noisy
4. **Memory unpacking needs only 10-30s timeout** - Packer unpacks quickly
5. **Analyze unpacked files in parallel** - Independent paths

---

## Output Artifacts

Unpacked files go to: `/workspace/.re-artifacts/`

```
/workspace/.re-artifacts/
├── unpacked_upx.bin          # UPX unpacking
├── xor_42.bin                # XOR key 0x42
├── xor_ff.bin                # XOR key 0xFF
├── overlay.bin               # PE overlay
└── binwalk_temp/             # Binwalk extractions
    ├── file1.bin
    └── file2.bin
```

**Important:** Re-run file_triage on ALL extracted files

---

## Success Metrics

**Good unpacking:**
- Entropy drops from 7+ to 5-6
- Import count increases 5-10x
- String count increases 10-20x
- Readable function names in disassembly

**Bad unpacking:**
- Entropy still > 7.0
- Still few imports
- Extracted file smaller than original
- Not a valid PE/ELF

---

## Next Steps

After unpacking:
- **Always** re-run file_triage on unpacked file
- **Always** re-run extract_strings (now meaningful)
- **Consider** re-running yara_scan (may match family now)
- **Consider** radare2_analyze (now reveals real code)
- If entropy still high → Try another unpacking method
- If unpacking fails → Proceed to dynamic analysis
