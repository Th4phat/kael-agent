---
name: C2 Infrastructure Identification
description: Detecting and analyzing command-and-control infrastructure
category: reverse_engineering
priority: medium
---

# C2 Infrastructure Identification

## Overview

Command-and-control (C2) infrastructure is how malware communicates with its operators. Identifying C2 servers is critical for blocking, attribution, and understanding campaign scope.

## When to Use These Tools

**Use c2_beacon_detect when:**
- Sandbox captured network traffic (PCAP exists)
- Suspect regular beaconing behavior
- Need to distinguish C2 from legitimate traffic

**Use protocol_dissect when:**
- Need to understand C2 protocol details
- Want to extract command/response data
- Analyzing custom protocols

---

## Step 1: Beacon Detection

```
Use: c2_beacon_detect(pcap_path, min_interval_sec=1.0, max_interval_sec=3600.0)
```

### What It Detects

**Beaconing patterns indicate:**
- Regular "heartbeat" connections to same destination
- Low jitter (consistent timing)
- Small packet sizes (check-in traffic)

### Interpreting Results

**High Confidence Beacon:**
```json
{
  "destination": "1.2.3.4:443",
  "protocol": "TCP",
  "packet_count": 45,
  "statistics": {
    "avg_interval_sec": 60.0,
    "jitter_sec": 0.8,
    "coefficient_of_variation": 0.013
  },
  "confidence": "high"
}
```

**What this means:**
- Malware checks in every 60 seconds
- Very consistent timing (jitter < 1 second)
- Strong indicator of C2 infrastructure

**Medium/Low Confidence:**
- Higher jitter (irregular timing)
- May be legitimate background services
- Needs protocol analysis to confirm

---

## Step 2: Protocol Analysis

```
Use: protocol_dissect(pcap_path, extract_payloads=True)
```

### HTTP/HTTPS C2

**Indicators:**
```json
{
  "type": "http_request",
  "method": "POST",
  "uri": "/api/checkin",
  "headers": {
    "User-Agent": "Mozilla/5.0 (Custom)",
    "Cookie": "session=base64encodeddata"
  }
}
```

**Red flags:**
- POST to suspicious URIs (/api/update, /gate.php, /panel/)
- Base64-encoded cookies or parameters
- Custom User-Agent strings
- Missing common headers (Accept-Language, etc.)

### DNS Tunneling

**Indicators:**
```json
{
  "type": "dns_query",
  "domain": "aGVsbG8ud29ybGQ.evil.com"
}
```

**Red flags:**
- Subdomain with Base32/Base64 characters
- Long subdomains (> 30 characters)
- High frequency of DNS queries to same domain
- Unusual TLD (.tk, .xyz, .top)

### Raw TCP C2

**Indicators:**
```json
{
  "type": "raw_tcp",
  "dst": "1.2.3.4:8080",
  "payload_preview": "AAAABBBBCCCCDDDD...",
  "is_printable": false
}
```

**Analysis:**
- Binary protocol (not printable)
- Check for XOR patterns
- Look for repeating headers
- Compare request/response sizes

---

## C2 Patterns by Malware Type

### Pattern 1: Cobalt Strike Beacon
- **Beaconing:** Regular intervals (60-300s)
- **Protocol:** HTTPS POST
- **URI:** /api/, /foobar/, /submit.php
- **Jitter:** Low (< 10%)
- **User-Agent:** Often mimics legitimate browser

### Pattern 2: Metasploit Meterpreter
- **Beaconing:** Variable intervals
- **Protocol:** HTTPS or custom TCP
- **Payload:** Often SSL/TLS encrypted
- **Behavior:** Long-lived connections

### Pattern 3: Ransomware Check-In
- **Beaconing:** 1-3 times only
- **Protocol:** HTTP GET or POST
- **Purpose:** Report encryption success, get payment address
- **Timing:** Immediate after infection

### Pattern 4: Backdoor/RAT
- **Beaconing:** Very regular (30-600s)
- **Protocol:** HTTP/HTTPS or custom
- **Payload:** Command requests, file exfiltration
- **Persistence:** Beaconing continues until removal

---

## Confidence Scoring

### High Confidence C2 (Report Immediately)
- Regular beaconing with CV < 0.15
- Known malware family matched (YARA)
- Suspicious protocol patterns
- Base64/encoded payloads
- Non-standard ports (not 80/443)

### Medium Confidence (Further Investigation)
- Irregular beaconing (CV 0.15-0.30)
- Suspicious domains but low traffic
- Single connection to unknown IP
- Standard ports but unusual protocol

### Low Confidence (Likely Legitimate)
- High jitter (CV > 0.30)
- Known CDN/cloud provider IPs
- Standard HTTP with normal headers
- Common domains (googleapis.com, microsoft.com)

---

## IOC Extraction

From C2 analysis, extract:

**Network IOCs:**
- C2 IP addresses
- C2 domains
- C2 ports
- URL patterns
- User-Agent strings

**Protocol IOCs:**
- URI patterns
- Custom headers
- Encryption keys (if found)
- Session tokens
- Magic bytes in custom protocols

---

## Example Analysis

### Scenario: Unknown Backdoor

```
Step 1: sandbox_detonate(sample.exe)
  → PCAP: 1.2 MB captured

Step 2: c2_beacon_detect(traffic.pcap)
  → Found 1 beacon:
    - Destination: 192.0.2.100:443
    - Interval: 120s ± 2s
    - Confidence: HIGH

Step 3: protocol_dissect(traffic.pcap)
  → HTTP POST requests to /api/v1/status
  → User-Agent: "MozillaBot/1.0"
  → Payload: Base64-encoded JSON
  → Response: 32-byte hex string

Step 4: Document findings:
  - C2 Server: 192.0.2.100:443
  - Protocol: HTTPS (HTTP over TLS)
  - Check-in interval: 2 minutes
  - Custom protocol with Base64 encoding
  - Response appears to be command ID
```

---

## Decision Tree

```
Did sandbox capture network traffic?
  ↓ NO → Can't analyze C2
  ↓ YES
    ↓
Is PCAP size > 0 bytes?
  ↓ NO → No network activity
  ↓ YES
    ↓
Run c2_beacon_detect
  ↓
Any beacons detected?
  ↓ NO → Check protocol_dissect for one-time connections
  ↓ YES
    ↓
Confidence level?
  ↓ HIGH → Document C2 infrastructure
  ↓ MEDIUM → Run protocol_dissect to confirm
  ↓ LOW → Likely false positive, skip
```

---

## Reporting C2 Findings

**Always include:**
1. IP address and port
2. Domain name (if DNS query seen)
3. Protocol type (HTTP/HTTPS/TCP/UDP)
4. Beaconing interval and jitter
5. Confidence level
6. Sample request/response (if protocol dissected)

**Example:**
```
## C2 Infrastructure

**Primary C2:**
- IP: 192.0.2.100
- Port: 443
- Protocol: HTTPS
- Domain: evil-cdn.com
- Beaconing: Every 120 seconds (±2s)
- Confidence: HIGH

**Communication Pattern:**
- HTTP POST to /api/v1/status
- User-Agent: MozillaBot/1.0
- Payload: Base64-encoded system info
- Response: 32-byte command ID

**Recommendations:**
- Block IP 192.0.2.100 at firewall
- Add evil-cdn.com to DNS blacklist
- Monitor for similar User-Agent strings
```

---

## Next Steps

- C2 identified → Document in final report
- Multiple C2 servers → Note campaign infrastructure
- Custom protocol → Document protocol format
- Ready to report → Use "Report Synthesis" skill
