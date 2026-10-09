---
name: ctf-scan-mode
description: CTF challenge scan mode — full workflow from challenge triage to flag capture, with category dispatch and reporting conventions
category: scan_modes
priority: critical
---

# CTF Scan Mode

## Mission

You are working on a Capture-The-Flag (CTF) challenge. Your goal is to capture the **flag string** (usually formatted as `flag{...}`, `CTF{...}`, `picoCTF{...}`, `HTB{...}`, or a challenge-specific prefix) and report it back. Unlike production pentests, the success criterion is the flag itself, not a vulnerability report.

## Mandatory Workflow

Always follow this sequence. Skip steps only when explicitly justified.

### Phase 0: Triage (REQUIRED)
```
1. Read the challenge description TWICE. Every word is a hint.
2. Identify the category: web | pwn | reversing | crypto | forensics | osint | misc
3. Identify the target type: URL, file, network service, image, memory dump, PCAP, document
4. Identify constraints: source code provided? docker image? remote service only?
5. If a file is given: file, checksec, strings, exiftool
6. If a URL is given: curl -I, then save the source
```

### Phase 1: Category Dispatch
Based on Phase 0, load the right skill and tool. Use `load_skill` to pull the category skill into context:
- **Web (use canonical pentest skills)**: `sql_injection`, `xss`, `ssti`, `ssrf`, `authentication_jwt`, `deserialization`
- **Pwn (CTF-specific)**: `ctf/pwn/recon`, `ctf/pwn/stack`, `ctf/pwn/heap`, `ctf/pwn/formats_and_misc`
- **Reversing (CTF-specific)**: `ctf/reversing/static`, `ctf/reversing/dynamic`, `ctf/reversing/langs`
- **Crypto (CTF-specific)**: `ctf/crypto/rsa`, `ctf/crypto/symmetric`, `ctf/crypto/other`
- **Forensics (CTF-specific)**: `ctf/forensics/disks`, `ctf/forensics/pcap`, `ctf/forensics/memory`, `ctf/forensics/stego`
- **OSINT (CTF-specific)**: `ctf/osint/methodology`, `ctf/osint/encodings`, `ctf/osint/misc`

Then pick the right tool from `ctf_tools`:
- `cyberchef_decode` — multi-layer encoding chain
- `pwn_exploit` — pwntools-based exploit template
- `pwn_checksec` — binary protections
- `crypto_rsa_solver` — RSA attack dispatcher
- `crypto_symmetric_solver` — block cipher mode attacks
- `forensics_metadata` — exiftool + binwalk wrapper
- `forensics_pcap_extract` — tshark object extraction
- `osint_lookup` — username / domain / IP pivots

### Phase 2: Discovery
For each category, run the "First 60 Seconds" workflow defined in the skill. Document every input/output you generate — CTF challenges are often about chaining tools.

### Phase 3: Exploitation
Build the smallest possible PoC that produces the flag. Prefer:
- **Reuse over reinvention** — `phpggc`, `ysoserial`, `pwntools`, `z3` are first-class citizens
- **One-liners** — most CTF primitives have a one-liner
- **Symbolic execution** when stuck (angr, z3, sage)
- **Pre-built CTF scripts** — `cryptohack`, `pwncollege`, `ctf-wiki` are gold

### Phase 4: Validation
```
The flag is captured ONLY if:
1. The string matches a flag format: `flag{...}`, `CTF{...}`, `picoCTF{...}`, `HTB{...}`
   (or the challenge's specific prefix)
2. The flag was extracted through the chain of actions, not a single lucky guess
3. The chain is reproducible (another agent could re-run it)

If any of these is false, keep going.
```

### Phase 5: Report
The deliverable is the **flag string + the shortest path to obtain it**. The "report" is:
```
1. Challenge: <name> (category: <web|pwn|...>)
2. Vulnerability class: <sqli|xss|ssti|...>
3. Target: <URL|file:hash|socket:host:port>
4. Steps:
   a. <Triage action>
   b. <Discovery action>
   c. <Exploit action>
   d. <Flag capture>
5. Flag: flag{...}
6. Time spent: <minutes>
```

## Decision Trees

### "Which category is this?"
```
URL or web request?           → web
Binary, file, or service?    → check `file` and `strings` first
    if ELF / PE / Mach-O:    → pwn or reversing
    if jar / dll / pyc:     → reversing
Encrypted text + keys:       → crypto
PCAP, disk image, memory:    → forensics
Image, audio, document:      → forensics (stego)
External resource to find:   → osint
Nothing fits:                → misc
```

### "Should I use static or dynamic RE?"
```
- Code has obvious branches with strings?    → static (decompile + read)
- Packed or obfuscated?                      → dynamic (run + dump)
- Anti-debug present?                        → dynamic (or static with frida)
- VM-based obfuscation?                      → static (decode the dispatch) + z3
```

### "Should I use pwn or reversing for this binary?"
```
- Binary reads input and you control it?      → pwn (likely exploitable)
- Binary takes a key/serial and checks it?    → reversing (crackme)
- Binary connects to a network service?       → pwn (likely) or reversing (RAT)
- Both?                                      → start with reversing, then pwn the protocol
```

### "Should I use online or local crypto tools?"
```
- Small n / e / c?                           → factordb first, then local
- Need interactive oracle?                   → local (or remote script)
- Lattice attack?                             → local sage
- z3 / SAT?                                  → local
- Just decode a string?                       → local
```

## Target Model

- **CTF challenges are cooperative** — the binary or service is meant to be broken; you have full permission
- **The flag is the goal** — you don't need to write a responsible-disclosure report
- **Speed matters** — most CTFs are 24-72 hours; efficient tooling is critical
- **Writeups exist** — for major CTFs, writeups are public within hours; the agent's job is to derive the flag, not to copy the writeup

## Safety / Ethics Rules

1. **Only attack CTF targets** — the URL/host must be in scope
2. **Don't attack the CTF infrastructure** — submitting flags too aggressively can get you banned
3. **Don't pivot to real-world systems** — the leaked password is for the CTF, not for the user's actual email
4. **Log everything** — every command, every output, every step. CTF reports need to be reproducible.
5. **Respect rate limits** — most CTFs have anti-bruteforce on login / submit pages
6. **Don't leak other teams' flags** — if you find them, leave them alone

## Tooling Quick Reference

```bash
# Web
curl, sqlmap, nuclei, ffuf, jwt_tool, mitmproxy, pwntools (HTTP)

# Pwn
pwntools, gdb+pwndbg, ROPgadget, one_gadget, angr, pwninit, glibc-all-in-one

# Reversing
ghidra, cutter, radare2, gdb+pwndbg, frida, angr, unicorn, jadx, cfr, ilspycmd

# Crypto
sage, pycryptodome, gmpy2, sympy, z3, hlextend, jwt_tool, phpggc, ysoserial, marshalsec

# Forensics
vol, tshark, wireshark, binwalk, foremost, scalpel, steghide, zsteg, exiftool, jsteg, autospy

# OSINT
sherlock, maigret, holehe, subfinder, amass, theHarvester, exiftool

# Misc
everything else

# Access (challenge only reachable over a ws:// / wss:// gateway, no raw host:port)
wsrx  # load_skill(["wsrx"]) — bridges the WebSocket to a local 127.0.0.1:PORT for nc/pwntools
```

## Common Pitfalls

- **Reading the challenge wrong** — most CTF writeups are "I missed the obvious hint in the description"
- **Spending 30 minutes on static analysis** when dynamic would take 2 — try gdb first
- **Forgetting to check the obvious** — the flag is sometimes in the source HTML, the binary's strings, the email's headers
- **Not writing the exploit reproducibly** — if the flag comes from a one-off, the report is unverifiable
- **Brute-forcing when a smarter path exists** — RSA `e=3` doesn't need brute; Coppersmith doesn't need brute
- **Overcomplicating** — most CTFs are solvable in <2 hours by an expert; if you've been at it for 4 hours, you're missing something

## Remember

- **Be efficient** — every minute counts in a CTF
- **Be thorough** — flag in the metadata is a common CTF
- **Be reproducible** — your report should let anyone re-derive the flag
- **Be adaptive** — pivot on every clue, even tangents
- **Document everything** — every command, every output, every step

## Example Complete Walkthrough

```markdown
## Challenge: "Web Login" (web)

**Phase 0: Triage**
- URL: http://target/challenge
- Description: "Bypass the login"
- First request: `curl -I http://target/challenge` → 200 OK, no auth headers

**Phase 1: Category Dispatch**
- Load skill: `sql_injection` (canonical pentest skill — not `ctf/web/sqli`)
- Tool: `cyberchef_decode`, `pwn_exploit` (for pwntools HTTP)

**Phase 2: Discovery**
- View source → form action `/login` with POST username/password
- Test SQLi: `username=admin'-- -&password=anything` → "Welcome admin"
- The query is likely `SELECT * FROM users WHERE name='...' AND password='...'`
- Bypass: comment out the password check

**Phase 3: Exploitation**
```python
import requests
r = requests.post('http://target/login', data={'username': "admin'-- -", 'password': 'x'})
print(r.text)
```

**Phase 4: Validation**
- Response contains "flag{...}" — matches expected format
- Reproducible: re-run the same request → same flag

**Phase 5: Report**
- Vulnerability class: SQL injection (auth bypass via comment)
- Steps: 1) form identified, 2) `'` triggered error, 3) `admin'-- -` returned the flag
- Flag: `flag{sql_1nj3ction_b4s1cs}`
- Time spent: 5 minutes
```

## Subagents

For complex challenges, spawn specialists:
- `web-specialist` — for SQLi/XSS/SSTI/SSRF/etc. web challenges
- `pwn-specialist` — for binary exploitation
- `re-specialist` — for reverse engineering
- `crypto-specialist` — for crypto challenges
- `forensics-specialist` — for stego/PCAP/memory/disk
- `osint-specialist` — for OSINT challenges

Each loads the relevant skills and tools. The root agent coordinates.
