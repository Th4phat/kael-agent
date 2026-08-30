---
name: Dynamic Analysis Workflow
description: Safe sandbox execution with comprehensive forensic capture
category: reverse_engineering
priority: high
---

# Dynamic Analysis Workflow

## Overview

This skill guides you through controlled malware execution in an isolated sandbox environment. Dynamic analysis reveals runtime behavior that static analysis cannot detect.

## When to Run Dynamically

**ALWAYS run if:**
- Sample is a script (Python, JavaScript, PowerShell, Bash)
- Static analysis found network IOCs (URLs, IPs)
- Static analysis found file dropper indicators
- Sample uses obfuscation or encryption
- You need to confirm static analysis findings

**SKIP if:**
- File is clearly a document/data file (not executable)
- Static analysis already answered all questions
- Sample is > 500MB (sandbox timeout risk)

---

## Pre-Flight Checklist

Before detonation, verify:

1. ✅ **Static analysis complete** - You should know what the sample might do
2. ✅ **File size reasonable** - < 500MB to avoid timeouts
3. ✅ **Architecture compatible** - PE needs Wine, ARM needs QEMU
4. ✅ **Output directory exists** - /workspace/.re-runs/ will be created automatically

---

## Sandbox Execution Modes

### Mode 1: Controlled Network (DEFAULT)
```
Use: sandbox_detonate(sample_path, network_mode="controlled")
```

**What happens:**
- Network traffic is CAPTURED but not blocked
- Iptables logs all outbound connections
- PCAP file records all packets
- DNS queries are logged

**Use when:**
- You want to identify C2 infrastructure
- Sample needs network to reveal behavior
- You're analyzing downloaders/trojans

---

### Mode 2: Network Off
```
Use: sandbox_detonate(sample_path, network_mode="off")
```

**What happens:**
- No network capture (faster)
- Sample cannot connect externally
- Useful for offline ransomware analysis

**Use when:**
- Sample doesn't need network (local encryption, etc.)
- Quick behavior check
- Known to be non-networked malware

---

### Mode 3: Quick Mode
```
Use: sandbox_detonate(sample_path, quick_mode=True, timeout=30)
```

**What happens:**
- Skips strace/ltrace (much faster)
- Still captures network and filesystem
- Reduced forensic detail

**Use when:**
- You just need confirmation of execution
- Sample is slow to analyze
- Initial triage run

---

## What Gets Captured

### 1. Execution Metadata
- Exit status (normal, timeout, crash)
- Duration
- Command used to run sample

### 2. Filesystem Changes
- **Created files** - Dropped payloads, config files
- **Modified files** - /etc/hosts, startup scripts
- **Deleted files** - Anti-forensics, log cleaning

### 3. Network Activity
- **PCAP file** - Full packet capture in /workspace/.re-runs/<sha256>/traffic.pcap
- **Connections** - Destination IPs and ports
- **DNS queries** - Domains resolved

### 4. System Calls (if not quick_mode)
- **strace log** - All syscalls with timestamps
- **ltrace log** - Library function calls
- **Interesting syscalls highlighted:**
  - process_vm_writev = Process injection
  - execve = Code execution
  - open on sensitive paths = Persistence
  - connect/sendto = Network activity

---

## Interpreting Results

### Exit Status Meanings

| Status | Meaning | Action |
|--------|---------|--------|
| 0 | Normal exit | Check what it did (filesystem, network) |
| timeout | Ran for full duration | Common for backdoors, check network |
| -1 | Crashed | May have anti-sandbox, try memory snapshot |
| 127 | Execution failed | Wrong architecture or missing dependencies |

---

### Filesystem Changes Analysis

**Pattern 1: Dropper Detected**
```
Created files:
  - /tmp/payload.dll
  - /tmp/stage2.exe
```
**Action:** Re-run static analysis on dropped files (multi-stage malware)

**Pattern 2: Persistence Detected**
```
Modified files:
  - /home/user/.bashrc
  - /etc/cron.d/malware
```
**Action:** Document persistence mechanism for report

**Pattern 3: Configuration Extracted**
```
Created files:
  - /tmp/config.json (C2 servers, encryption keys)
```
**Action:** Parse config, extract IOCs

---

### Network Activity Analysis

**Pattern 1: C2 Beaconing**
```
Network shows:
  - Regular connections every 60 seconds
  - Same destination IP
  - Small packet sizes
```
**Action:** Use c2_beacon_detect tool to confirm

**Pattern 2: Data Exfiltration**
```
Network shows:
  - Large outbound transfer (MB+)
  - HTTP POST or custom protocol
  - After filesystem read operations
```
**Action:** Use protocol_dissect to extract payload

**Pattern 3: Download Behavior**
```
Network shows:
  - HTTP GET request
  - Followed by file creation
  - Then execution of new file
```
**Action:** Multi-stage malware, analyze dropped payload

---

### Syscall Analysis

**High-Value Syscalls:**

| Syscall | Indicates | Follow-Up |
|---------|-----------|-----------|
| process_vm_writev | Process injection | Memory snapshot |
| ptrace | Debugger/injection | Memory snapshot |
| execve | Code execution | Check what was executed |
| connect | Network connection | Check destination IP |
| open + /etc/hosts | Persistence | Filesystem diff |
| open + .bashrc | Persistence | Filesystem diff |

---

## Multi-Stage Detection

If sandbox detects dropped files, analyze them recursively:

```
Step 1: sandbox_detonate(stage1.exe)
  → Dropped: /tmp/stage2.dll

Step 2: file_triage(/tmp/stage2.dll)
  → PE32 DLL, entropy 5.4

Step 3: extract_strings(/tmp/stage2.dll)
  → Found: C2 domain evil.com

Step 4: sandbox_detonate(/tmp/stage2.dll)  # If it's executable
  → Network: Connected to evil.com:443

Step 5: c2_beacon_detect(stage2_traffic.pcap)
  → Beaconing every 300 seconds
```

**Continue until no more stages found.**

---

## Timeout Strategy

**Default timeout: 60 seconds**

Adjust based on sample type:

| Sample Type | Recommended Timeout | Reason |
|-------------|---------------------|--------|
| Dropper | 30s | Drops payload quickly |
| Ransomware | 120s | Needs time to encrypt |
| Backdoor | 60-120s | Check for beaconing |
| Script | 30s | Usually fast |
| Unknown | 60s | Safe default |

**Set timeout:**
```
sandbox_detonate(sample_path, timeout=120)
```

---

## Memory Snapshot Decision

Add memory capture when:

```
Use: sandbox_detonate(sample_path, snapshot_memory=True)
```

**When to use:**
- Static analysis found process injection APIs
- Suspect code unpacking in memory
- Sample crashes (capture state before crash)
- Known packer that unpacks in memory

**Warning:** Memory snapshots add 10-30 seconds overhead

**Follow-up:**
```
memory_snapshot(run_dir="/workspace/.re-runs/<sha256>")
```

---

## Network Analysis Pipeline

After sandbox execution with network:

**Step 1: Check if PCAP has data**
```
Result shows: "pcap_size_bytes": 0 → No network activity
Result shows: "pcap_size_bytes": > 0 → Proceed to analysis
```

**Step 2: Detect beaconing patterns**
```
c2_beacon_detect(pcap_path="/workspace/.re-runs/<sha256>/traffic.pcap")
```

**Step 3: Dissect protocols**
```
protocol_dissect(pcap_path="/workspace/.re-runs/<sha256>/traffic.pcap")
```

---

## Example Workflows

### Workflow 1: Unknown Dropper

```
1. Static analysis revealed: URLDownloadToFile import
2. sandbox_detonate(sample.exe, network_mode="controlled", timeout=60)
   → Filesystem: Created /tmp/payload.exe
   → Network: HTTP GET to evil.com/payload.exe
3. file_triage(/tmp/payload.exe)
   → Ransomware signature detected
4. extract_strings(/tmp/payload.exe)
   → Bitcoin address found
5. Do NOT execute payload (ransomware confirmed)
```

### Workflow 2: Suspected Injector

```
1. Static analysis found: CreateRemoteThread, WriteProcessMemory
2. sandbox_detonate(sample.exe, snapshot_memory=True, timeout=60)
   → Exit: Normal
   → Syscalls: process_vm_writev to PID 5678
3. memory_snapshot(run_dir="/workspace/.re-runs/abc123...")
   → Extracted: injected_pe_7f000000.bin
4. file_triage(injected_pe_7f000000.bin)
   → Cobalt Strike Beacon detected
```

### Workflow 3: Network Backdoor

```
1. Static analysis found: socket, connect, send imports
2. sandbox_detonate(sample.exe, network_mode="controlled", timeout=120)
   → Network: Regular traffic to 1.2.3.4:443
3. c2_beacon_detect(traffic.pcap)
   → Beaconing every 60 seconds with 0.05 jitter
   → Confidence: HIGH
4. protocol_dissect(traffic.pcap)
   → HTTP POST with base64 encoded data
   → User-Agent: Mozilla/5.0 (custom string)
```

---

## Common Issues & Solutions

### Issue 1: Sample Doesn't Execute
```
Error: "Cannot run sample: PE binary requires wine64"
```
**Solution:** Verify Wine is installed, or sample is for wrong architecture

### Issue 2: No Network Activity Captured
```
pcap_size_bytes: 0
```
**Possible causes:**
- Sample requires arguments to trigger network
- Sample checks for internet connectivity first
- Network mode was "off"

### Issue 3: Sandbox Times Out Immediately
```
Exit status: timeout, Duration: 0.1 seconds
```
**Cause:** Sample detected sandbox (anti-analysis)
**Solution:** Check for anti-VM techniques in static analysis

### Issue 4: Permission Denied
```
Error: "Failed to start tcpdump"
```
**Solution:** Verify Docker container has CAP_NET_ADMIN capability

---

## Safety Rules

1. **Never exfiltrate samples** - Keep everything in /workspace/
2. **Log C2 traffic, don't replay** - PCAP is for analysis only
3. **Isolate multi-stage payloads** - Each stage in separate directory
4. **Check filesystem diff** - Malware may modify critical files
5. **Timeout is your friend** - Don't let ransomware run indefinitely

---

## Output Artifacts

After sandbox execution, you'll have:

```
/workspace/.re-runs/<sha256>/
├── traffic.pcap           # Network capture
├── strace.log            # Syscall trace
├── ltrace.log            # Library call trace
├── report.json           # Execution metadata
└── file_diff.json        # Filesystem changes
```

**Save these paths** - You'll need them for c2_beacon_detect and protocol_dissect

---

## Next Steps

After dynamic analysis:
- Network activity detected → Use "C2 Identification" skill
- Memory injection detected → Use "Memory Forensics" skill
- Dropped files found → Re-run static analysis on new files
- Analysis complete → Use "Report Synthesis" skill

---

## Performance Tips

1. **Use quick_mode for initial runs** - Confirm execution before full forensics
2. **Start with 60s timeout** - Increase only if needed
3. **Skip memory snapshot unless needed** - Adds significant overhead
4. **Run network analysis separately** - Don't block on protocol dissection
5. **Analyze dropped files in parallel** - Independent analysis paths
