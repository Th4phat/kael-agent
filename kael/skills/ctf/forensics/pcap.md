---
name: ctf-forensics-pcap
description: Network forensics in CTFs — tshark/Wireshark command-line, USB HID keyboard capture decoding, HTTP/2/TLS, PCAP carving, and common CTF network challenges
---

# CTF Forensics — PCAP & Network

The "I have a network capture, find the flag" challenge. PCAPs hide:
- Plaintext credentials / cookies
- Files transferred over FTP / SMB / HTTP / SMTP
- Custom protocol traffic (and the message structure)
- DNS exfil (base32 / base64 in subdomains)
- USB HID keyboard/mouse captures (rubber ducky, Bash Bunny)
- VoIP / RTP audio
- Timing-based channels (TCP timestamps, ICMP payloads)

## 1. The 5-Minute PCAP Triage

```bash
file capture.pcap            # what is this?
tshark -r capture.pcap -q -z conv,tcp       # TCP conversations
tshark -r capture.pcap -q -z conv,udp       # UDP conversations
tshark -r capture.pcap -q -z io,phs         # protocol hierarchy
tshark -r capture.pcap -q -z endpoints,ip   # IP endpoints
tshark -r capture.pcap -Y "http" -T fields -e http.request.uri | head -20
tshark -r capture.pcap -Y "dns" -T fields -e dns.qry.name | head -20
tshark -r capture.pcap -Y "ftp" -T fields -e ftp.request.command -e ftp.request.arg
tshark -r capture.pcap -Y "smb" -T fields -e smb.file
tshark -r capture.pcap -Y "smtp" -T fields -e smtp.data.fragment
tshark -r capture.pcap -Y "icmp" -T fields -e data.data
```

**Quick stats:**
```bash
capinfos capture.pcap          # file format, packet count, duration
tcpdump -r capture.pcap -nn   # quick read
```

## 2. HTTP / Web PCAP

### Extract HTTP objects (files)
```bash
tshark -r capture.pcap --export-objects "http,/tmp/http_objects/"
# Or:
wireshark capture.pcap &   # GUI: File → Export Objects → HTTP
```

### Extract specific files
```bash
# Find a file by content-type or path
tshark -r capture.pcap -Y 'http.content_type contains "image"' -T fields -e http.request.uri
# Save to disk
tshark -r capture.pcap -Y "http.request.uri contains 'flag.txt'" -T fields -e http.file_data
```

### Cookies / Authorization headers
```bash
tshark -r capture.pcap -Y 'http.cookie' -T fields -e http.cookie
tshark -r capture.pcap -Y 'http.authorization' -T fields -e http.authorization
```

## 3. TLS / HTTPS

If the PCAP has the **pre-master secret log** (`SSLKEYLOGFILE`), you can decrypt TLS:
```bash
SSLKEYLOGFILE=/path/to/keys.log tshark -r capture.pcap -o "tls.keylog_file:/path/to/keys.log" -Y "http"
```

If you don't have the keys, look for:
- TLS server name (SNI) in the ClientHello
- Certificate info
- **Server's certificate** itself (if exported, often leaks the public key)
- **Encrypted SNI (ESNI)** — newer; harder
- **JA3 fingerprint** — if the CTF is "find the malware", JA3 is the key

## 4. DNS Exfiltration

The flag is base32 / base64 / hex-encoded in DNS queries to a domain the attacker controls (e.g. `BAAAAA.exfil.com`).

```bash
# Extract all DNS queries
tshark -r capture.pcap -Y "dns.qry.name" -T fields -e dns.qry.name | sort -u > dns.txt
# Strip the suffix and concatenate
grep "exfil.com" dns.txt | awk -F'.' '{print $1}' | sort -u
# Or use tshark to compute the actual subdomain
```

**Wireshark filter:** `dns.qry.name matches "exfil"`

## 5. USB HID Keyboard Capture (the 2024+ common challenge)

A USB keyboard sends 8-byte HID reports: `modifier`, `reserved`, `key1`, `key2`, ..., `key6`. The `key1`-`key6` are usage IDs from the USB HID Usage Tables.

### Decode
```bash
# Extract the HID data
tshark -r capture.pcap -Y "usb.transfer_type == 0x01" -T fields -e usb.capdata
# 8 bytes per report, no separator; you may need to manually split
```

```python
# Python decoder
HID_MAP = {
    0x04: 'a', 0x05: 'b', 0x06: 'c', 0x07: 'd', 0x08: 'e', 0x09: 'f', 0x0a: 'g',
    0x0b: 'h', 0x0c: 'i', 0x0d: 'j', 0x0e: 'k', 0x0f: 'l', 0x10: 'm', 0x11: 'n',
    0x12: 'o', 0x13: 'p', 0x14: 'q', 0x15: 'r', 0x16: 's', 0x17: 't', 0x18: 'u',
    0x19: 'v', 0x1a: 'w', 0x1b: 'x', 0x1c: 'y', 0x1d: 'z',
    0x1e: '1', 0x1f: '2', 0x20: '3', 0x21: '4', 0x22: '5', 0x23: '6', 0x24: '7',
    0x25: '8', 0x26: '9', 0x27: '0',
    0x28: '\n', 0x29: '<ESC>', 0x2a: '<BACKSPACE>', 0x2b: '\t',
    0x2c: ' ', 0x2d: '-', 0x2e: '=', 0x2f: '[', 0x30: ']', 0x31: '\\',
    0x33: ';', 0x34: "'", 0x36: ',', 0x37: '.', 0x38: '/',
    0x39: '<CAPSLOCK>',
    0x4f: '<RIGHT>', 0x50: '<LEFT>', 0x51: '<DOWN>', 0x52: '<UP>',
    # shift variants handled by modifier bit
}

def decode_hid(data: bytes) -> str:
    out = []
    for i in range(2, 8):
        key = data[i]
        if key == 0: continue
        shift = (data[0] & 0x22) != 0   # left or right shift held
        ch = HID_MAP.get(key, f'<KEY 0x{key:02x}>')
        if shift:
            ch = ch.upper() if len(ch) == 1 else ch
        out.append(ch)
    return ''.join(out)
```

**Tool: `tshark` with a Lua post-dissector or `ctf-usb-keyboard-parser` (pre-made).**

## 6. USB Mouse Capture (rare, but exists)

Mouse reports: `buttons, x_low, x_high, y_low, y_high` (older) or 8-byte HID with multiple axes (newer). Decode and plot to PNG:
```python
# Decode absolute or relative coordinates, draw a picture
# Common CTF: the flag is the shape of the mouse movement
```

## 7. SMB / FTP / SMTP

### SMB
```bash
# List files
tshark -r capture.pcap -Y "smb2" -T fields -e smb2.filename
# Extract files
tshark -r capture.pcap --export-objects "smb2,/tmp/smb/"
# Browse in Wireshark
```

### FTP
```bash
# FTP is plaintext; tshark extracts commands and data
tshark -r capture.pcap -Y "ftp" -T fields -e ftp.request.command -e ftp.request.arg -e ftp.response.code -e ftp.response.arg
# Data channel is on a separate port; the PORT or PASV command tells you which
```

### SMTP
```bash
tshark -r capture.pcap -Y "smtp.data.fragment" -T fields -e tcp.payload
# Or use the IMAP/POP3 if mail is being read
```

## 8. Custom / Industrial Protocols

For SCADA, Modbus, S7comm, DNP3, BACnet, OPC UA — Wireshark has dissectors for all of them. The flag is often in a register / coil / property value.

```bash
tshark -r capture.pcap -Y "modbus" -T fields -e modbus.data
tshark -r capture.pcap -Y "s7comm" -T fields -e s7comm.data
```

## 9. PCAP Carving (extract files from a pcap without tshark)

```bash
# Use foremost on the raw PCAP
foremost -i capture.pcap -o /tmp/carved/

# Use binwalk
binwalk -e capture.pcap

# Manual: search for known file signatures in the pcap with xxd + grep
xxd capture.pcap | grep -E "ffd8 ff|8950 4e47|2550 4446|7f45 4c46|504b 0304"
```

## 10. Timing / Side-Channel Channels

```bash
# ICMP payloads: tshark -Y "icmp" -T fields -e data
# TCP timestamp diffs: tshark -Y "tcp.flags.syn == 1" -T fields -e tcp.options.timestamp.tsval
# Inter-packet delays: tshark -r capture.pcap -T fields -e frame.time_delta
```

## 11. VoIP / SIP

```bash
# Extract RTP audio
rtpbreak -r capture.pcap -d /tmp/rtp/
# Or use Wireshark: Telephony → RTP → Stream Analysis → Save payload
# Decode G.711 (ulaw/alaw) to WAV
sox -t ul -r 8000 input.raw output.wav
```

## 12. Common CTF Network Patterns

| Pattern | Tool |
|---|---|
| HTTP file download | `tshark --export-objects http` |
| DNS exfil | tshark → decode base32/64 in subdomains |
| TLS encrypted | Look for pre-master secret log; if not, look at cleartext metadata |
| USB keyboard | HID usage ID → ASCII |
| FTP file | `tshark` to find PORT/PASV + data stream |
| SMB file | `tshark --export-objects smb2` |
| TCP stream with flag in it | `tshark -q -z follow,tcp,ascii,<stream_index>` |
| VoIP | Wireshark → decode + sox |
| Wireless (Wi-Fi) | WPA handshake → crack with aircrack-ng; if you have the password, decrypt with airdecap-ng |

## Tooling

```bash
# Wireshark / tshark
sudo apt install wireshark tshark

# tcpdump
sudo apt install tcpdump

# NetworkMiner (Windows / Linux, GUI)
# https://www.netresec.com/?page=NetworkMiner

# aircrack-ng
sudo apt install aircrack-ng

# foremost, binwalk (for pcap carving)
sudo apt install foremost binwalk
```

## Common Pitfalls

- **PCAP is huge (gigabytes)** — use `tshark -Y <filter>` to slice early; `capinfos` for file size
- **TLS looks empty** — check for SSLKEYLOGFILE or a server's private key
- **Encrypted traffic with no keys** — give up on the bytes; pivot to side-channels (timing, packet sizes, IP destinations)
- **USB captures with multiple devices** — separate by device address
- **The flag is split across packets** — use `tshark -z follow,tcp,ascii,N` to reassemble a TCP stream
- **Timestamps in seconds, not microseconds** — PCAP-NS is the default; some PCAPs are PCAP-TS (seconds), which messes up timing analysis. Use `editcap --time-stamp-type` to fix.

## One-Liner Cheat Sheet

```bash
# Reassemble a TCP stream
tshark -r capture.pcap -q -z follow,tcp,ascii,0

# Reassemble a UDP stream
tshark -r capture.pcap -q -z follow,udp,ascii,0

# All HTTP request URIs
tshark -r capture.pcap -Y 'http.request' -T fields -e http.request.method -e http.host -e http.request.uri

# All DNS queries
tshark -r capture.pcap -Y 'dns' -T fields -e dns.qry.name

# All TLS SNI
tshark -r capture.pcap -Y 'tls.handshake.extensions_server_name' -T fields -e tls.handshake.extensions_server_name

# Find all "FLAG" mentions in payloads
tshark -r capture.pcap -Y 'data contains "FLAG"' -T fields -e data.data

# USB HID keyboard (when tshark shows "USB HID" reports)
tshark -r capture.pcap -Y 'usb.capdata' -T fields -e usb.capdata | head -20
```
