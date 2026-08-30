---
name: Report Synthesis
description: Generating comprehensive malware research reports
category: reverse_engineering
priority: high
---

# Report Synthesis

## Overview

After completing analysis, generate a comprehensive report that documents all findings in a structured, actionable format.

## When to Generate Report

**Generate report when:**
- All analysis phases complete (static + dynamic)
- IOCs have been extracted
- C2 infrastructure identified (if applicable)
- Ready to share findings with team

---

## Report Generation

```
Use: generate_research_report(
    sample_sha256="<hash>",
    analysis_data=<JSON string of all results>
)
```

### Preparing analysis_data

Collect results from all tools into a single JSON structure:

```json
{
  "file_triage": { ... },
  "strings": { ... },
  "yara": { ... },
  "radare2": { ... },
  "sandbox": { ... },
  "c2_beacon": { ... },
  "protocol": { ... },
  "unpack": { ... },
  "memory": { ... }
}
```

---

## Report Contents

The generated report includes:

### 1. Executive Summary
- Sample identification (hash)
- Malware family (if identified)
- Key findings (dropper, backdoor, ransomware, etc.)
- Threat level

### 2. File Triage
- File type and size
- All hashes (MD5, SHA1, SHA256, ssdeep)
- Entropy analysis
- Packer detection

### 3. Static Analysis
- String extraction summary
- YARA matches
- Disassembly highlights
- Suspicious APIs

### 4. Dynamic Analysis
- Execution results
- Filesystem changes
- Network activity
- Syscall analysis

### 5. Behavioral Analysis
- C2 beaconing patterns
- Protocol details
- Persistence mechanisms

### 6. Unpacking Results
- Methods attempted
- Payloads extracted
- Multi-stage chain

### 7. Memory Forensics
- Memory dumps captured
- Injected code found
- Extracted PEs

### 8. IOCs
- Network IOCs (IPs, domains, URLs)
- File IOCs (hashes, paths)
- Host IOCs (registry, mutexes)

### 9. Recommendations
- Detection rules
- Blocking actions
- Mitigation steps

---

## Output Files

The tool creates:

1. **Markdown Report** - Human-readable analysis
   - `/workspace/reports/<sha256>_report.md`

2. **JSON Report** - Machine-readable data
   - `/workspace/reports/<sha256>_report.json`

3. **Artifacts Tarball** - All analysis artifacts
   - `/workspace/reports/<sha256>_artifacts.tar.gz`
   - Contains: PCAP, strace logs, memory dumps, unpacked files

---

## Report Quality Checklist

Before finalizing, verify report includes:

- [x] Sample hash (SHA256)
- [x] File type and size
- [x] Malware family (if identified)
- [x] All network IOCs (IPs, domains)
- [x] All file IOCs (hashes of sample + dropped files)
- [x] C2 infrastructure details (if applicable)
- [x] Persistence mechanisms (if found)
- [x] Behavioral summary
- [x] Recommendations

---

## Example Summary Section

```markdown
## Executive Summary

This sample (a1b2c3d4e5f6...) is a **Cobalt Strike Beacon** delivered via a UPX-packed dropper.

**Key Findings:**
- Drops secondary payload (stage2.dll)
- Establishes HTTPS C2 to 192.0.2.100:443
- Beacons every 120 seconds
- Uses process injection (CreateRemoteThread)
- Persists via Run registry key

**Threat Level:** HIGH - Active C2 communication, evasion techniques

**Recommendations:**
- Block 192.0.2.100 at firewall
- Hunt for beacon User-Agent: "MozillaBot/1.0"
- Scan for file hash: abc123def456...
```

---

## Sharing Reports

**Internal Distribution:**
- Security Operations Center (SOC)
- Incident Response team
- Threat Intelligence team
- Network Security (for blocking rules)

**External Sharing:**
- Sanitize internal IPs and hostnames
- Remove victim-specific information
- Share via ISAC/ISAO channels
- Publish to threat intelligence platforms

---

## Archive Artifacts

The tarball includes:
- Original sample
- Unpacked payloads
- Dropped files
- PCAP files
- Strace/ltrace logs
- Memory dumps
- All JSON analysis results

**Retention:** Keep for 90 days minimum for threat hunting

---

## Next Steps

After report generation:
- Share report with security team
- Implement blocking rules
- Add IOCs to detection systems
- Archive analysis artifacts
- Update threat intelligence database
