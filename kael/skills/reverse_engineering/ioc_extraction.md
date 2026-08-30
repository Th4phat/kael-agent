---
name: IOC Extraction
description: Comprehensive indicator of compromise extraction for threat intelligence
category: reverse_engineering
priority: medium
---

# IOC Extraction

## Overview

Indicators of Compromise (IOCs) are artifacts that identify malicious activity. Extracting IOCs enables detection, blocking, and threat hunting across the organization.

## IOC Categories

### 1. File IOCs
- **MD5, SHA1, SHA256** - File hashes
- **ssdeep, TLSH** - Fuzzy hashes (detect variants)
- **File names** - Dropped files, payloads
- **File sizes** - Known malware sizes
- **PDB paths** - Debug symbols (attribution)

### 2. Network IOCs
- **IP addresses** - C2 servers, download sites
- **Domain names** - C2 domains, phishing sites
- **URLs** - Full paths to payloads
- **Ports** - Non-standard ports used
- **User-Agent strings** - Custom HTTP headers

### 3. Registry IOCs
- **Registry keys** - Persistence locations
- **Registry values** - Configurations, settings
- **Common paths:**
  - `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
  - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
  - `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`

### 4. File System IOCs
- **File paths** - Installation locations, temp files
- **Mutex names** - Single-instance locks
- **Service names** - Malicious services
- **Scheduled task names** - Persistence via tasks

### 5. Behavioral IOCs
- **API call sequences** - Process injection patterns
- **Command line arguments** - Execution parameters
- **Network patterns** - Beaconing intervals
- **Protocol characteristics** - Custom C2 protocols

---

## Extraction Sources

### From extract_strings Tool
```
Use: extract_strings(sample_path)
```

**Automatically categorizes:**
- URLs and domains
- IP addresses
- File paths
- Registry keys
- Email addresses
- Mutex names

**Example output:**
```json
{
  "urls": ["http://evil.com/payload.exe"],
  "ip_addresses": ["192.0.2.100", "203.0.113.50"],
  "file_paths": ["C:\\Windows\\System32\\malware.dll"],
  "registry_keys": ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
  "mutexes": ["Global\\MalwareMutex2023"]
}
```

### From sandbox_detonate Tool
```
Network IOCs:
- Connections made (IPs, domains, ports)
- DNS queries
- HTTP User-Agents

File IOCs:
- Dropped files (paths, hashes)
- Modified files
- Deleted files
```

### From radare2_analyze Tool
```
Behavioral IOCs:
- Imported API functions
- Suspicious function sequences
- Anti-analysis techniques
```

### From c2_beacon_detect + protocol_dissect
```
Protocol IOCs:
- Beaconing intervals
- Custom headers
- URI patterns
- Payload structures
```

---

## IOC Quality Levels

### High-Quality IOCs (High Confidence, Low False Positives)
- **File hashes** (MD5, SHA1, SHA256) - Exact match, 0% false positives
- **C2 IP addresses** - Direct C2 communication observed
- **Mutex names** - Unique to malware
- **PDB paths** - Debug info, attribution
- **Custom User-Agent strings** - Unique to campaign

**Use for:** Blocking, detection rules

### Medium-Quality IOCs (Good Confidence)
- **Domains** - May be compromised legitimate sites
- **File paths** - Common paths may overlap with legitimate software
- **Registry keys** - Standard persistence locations
- **Fuzzy hashes** (ssdeep) - Detects variants but needs tuning

**Use for:** Hunting, correlation

### Low-Quality IOCs (Context Dependent)
- **Common ports** (80, 443) - Too generic
- **Generic strings** ("config.dat") - High false positive rate
- **Common API calls** - Used by legitimate software
- **Generic filenames** ("update.exe") - Too common

**Use for:** Context only, not standalone detection

---

## IOC Prioritization

**Priority 1: Must Document**
- All file hashes (MD5, SHA256, ssdeep)
- All C2 infrastructure (IPs, domains, ports)
- Unique identifiers (mutexes, service names)
- Dropped payload hashes

**Priority 2: Should Document**
- Registry persistence keys
- File paths for dropped files
- User-Agent strings
- URL patterns
- DNS queries

**Priority 3: Nice to Have**
- Common API calls
- Generic file names
- Behavioral patterns
- Protocol characteristics

---

## IOC Format Standards

### STIX/TAXII Format (Recommended)
```json
{
  "type": "indicator",
  "pattern": "[file:hashes.SHA256 = 'abc123...']",
  "valid_from": "2026-06-14T00:00:00Z"
}
```

### OpenIOC Format
```xml
<Indicator>
  <IndicatorItem>
    <Context document="FileItem" search="FileItem/Md5sum"/>
    <Content>abc123def456</Content>
  </IndicatorItem>
</Indicator>
```

### Simple List Format (Quick)
```
# MD5 Hashes
a1b2c3d4e5f6...

# SHA256 Hashes
abc123def456...

# IP Addresses
192.0.2.100
203.0.113.50

# Domains
evil.com
c2-server.net
```

---

## Extraction Workflow

```
Step 1: Static IOCs
  - file_triage → File hashes
  - extract_strings → Network IOCs, file paths, registry keys
  - yara_scan → Malware family (context for IOCs)

Step 2: Dynamic IOCs
  - sandbox_detonate → Network connections, dropped files
  - c2_beacon_detect → C2 infrastructure
  - protocol_dissect → Protocol details

Step 3: Memory IOCs
  - memory_snapshot → Injected payloads, extracted PEs

Step 4: Consolidate
  - Deduplicate (same IP from multiple sources)
  - Categorize by type
  - Prioritize by quality
  - Add context (where found, confidence level)
```

---

## Example: Complete IOC Set

```markdown
## Indicators of Compromise

### File IOCs
**Sample Hash:**
- MD5: a1b2c3d4e5f6789...
- SHA1: f1e2d3c4b5a6...
- SHA256: abc123def456...
- ssdeep: 768:abc123...

**Dropped Files:**
- `C:\Users\Public\payload.dll` (SHA256: xyz789...)
- `C:\Windows\Temp\update.exe` (SHA256: def456...)

### Network IOCs
**C2 Infrastructure:**
- 192.0.2.100:443 (Primary C2)
- 203.0.113.50:8080 (Secondary C2)
- evil-cdn.com (C2 domain)
- download.attacker.net (Payload delivery)

**URLs:**
- http://evil-cdn.com/api/v1/status (Check-in)
- http://download.attacker.net/payload.exe (Stage 2)

**User-Agent:**
- MozillaBot/1.0 (Custom, high confidence)

### Host IOCs
**Registry Keys:**
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater`

**Mutexes:**
- `Global\MalwareMutex2023`

**File Paths:**
- `%APPDATA%\Microsoft\Windows\Templates\config.dat`
- `%TEMP%\~update.tmp`

### Behavioral IOCs
**Persistence:**
- Startup folder: `C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\`

**Network Pattern:**
- HTTPS beaconing every 120 seconds to 192.0.2.100:443

**Process Injection:**
- Targets: explorer.exe, svchost.exe
- Method: CreateRemoteThread + WriteProcessMemory
```

---

## IOC Validation

Before publishing IOCs, verify:

1. **No PII** - Remove usernames, local paths with usernames
2. **No internal IPs** - Filter RFC1918 addresses (10.x, 192.168.x, 172.16.x)
3. **Deduplicated** - Same IOC from multiple sources = list once
4. **Contextualized** - Note confidence level, where found
5. **Timestamped** - When was IOC observed

---

## IOC Sharing

**Internal Use:**
- SIEM integration
- Firewall/IPS rules
- EDR detection rules
- Threat hunting queries

**External Sharing:**
- Public threat intelligence feeds
- ISAC/ISAO groups
- Vendor intelligence programs
- Open-source intelligence platforms

**Sanitize before sharing:**
- Remove victim organization info
- Generalize local paths
- Remove internal IP addresses
- Add attribution context

---

## Tools Summary

| Want to Extract... | Use This Tool | Output |
|-------------------|---------------|--------|
| Strings, paths, domains | extract_strings | Categorized IOCs |
| File hashes | file_triage | MD5, SHA1, SHA256, ssdeep, TLSH |
| Network connections | sandbox_detonate | IPs, ports, DNS queries |
| C2 infrastructure | c2_beacon_detect | Beaconing IPs, intervals |
| Protocol details | protocol_dissect | HTTP headers, payloads |
| Dropped file hashes | sandbox_detonate + file_triage | SHA256 of each dropped file |

---

## Next Steps

- IOCs extracted → Document in report
- High-confidence IOCs → Share with security team immediately
- Ready to finalize → Use "Report Synthesis" skill
