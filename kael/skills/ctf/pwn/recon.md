---
name: ctf-pwn-recon
description: Pwn challenge triage — checksec, file/strings, pwntools template, libc identification, libc-database search, and the first-5-minutes workflow
---

# CTF Pwn — Recon & Setup

Every pwn challenge starts the same way. The first five minutes are **recon and tooling setup**, and skipping this step is the #1 cause of failed pwns.

## 1. Identify the Binary

```bash
file chall
# Typical output:
# chall: ELF 64-bit LSB pie executable, x86-64, dynamically linked, ... GNU/Linux 3.2.0
# Note: PIE / no-PIE / 32-bit / 64-bit / statically / dynamically linked

checksec --file=./chall
# Or pwn checksec
pwn checksec ./chall

# Useful quick queries
file chall
readelf -h chall           # ELF header (entry, arch, flags)
readelf -l chall           # segments (NX, RWX)
readelf -d chall           # dynamic (needed libs, RPATH, RUNPATH)
```

**The checksec flags that matter:**
- `RELRO`: `Full` (good) / `Partial` (GOT overwrite possible) / `No` (trivially overwritable)
- `Stack Canary`: `found` (need a leak) / `not found` (smash freely)
- `NX`: `enabled` (no shellcode on stack/heap) / `disabled` (RWE, shellcode OK)
- `PIE`: `enabled` (need a leak) / `not enabled` (base is fixed)
- `ASLR`: enforced by kernel, not visible to checksec; `cat /proc/sys/kernel/randomize_va_space`

## 2. Glance at the Strings (90-second behavior probe)

```bash
strings -n 6 chall | head -100
# Look for:
#   "Enter input: "      — input prompt format
#   "flag.txt"           — flag file path (often hardcoded)
#   "system"             — already a system() in the binary (one-byte win)
#   "/bin/sh"            — string already in the binary
#   "libc.so.6"          — libc version from dynamic section
#   "flag{...}"          — sometimes the flag is accidentally compiled in
strings -a chall | grep -iE "flag|ctf|hack|input|name"
nm chall | grep -E " T | t "   # exported function names
objdump -d chall | grep -E "<[a-zA-Z_]+>:" | head -30
```

## 3. Run It (safely)

```bash
echo "AAAA" | ./chall
# Most CTF pwn binaries are cooperative — they read input, do something, and exit.
# Watch for:
#   - Input buffer size mismatch
#   - Format string output (try "AAAA %p %p %p %p %p %p")
#   - Stack trace / crash / "Segmentation fault"
#   - Output that includes your input back (potential leak)
```

**Run inside a container with `setarch` to disable ASLR for initial dev:**
```bash
setarch $(uname -m) -R ./chall       # x86_64 / i386
linux64 setarch x86_64 -R ./chall    # on macOS-style multi-arch
```

## 4. Identify the Libc

Critical for any ROP / ret2libc.

```bash
# 1. From the binary's NEEDED
ldd chall
# → libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6

# 2. From a leak (preferred — that's the version running on the server)
# Send "%7$p" or similar and parse the libc address (last 12 bits == last 12 bits of the leaked address)
# Then: libc-database search / online

# 3. From the build ID (if exposed)
readelf -n chall
# Build ID: ... = a hash of the binary. Pair with the libc's build ID.

# 4. libc-database lookup
python3 -c "import pwn; pwn.libcdb.search_by_build_id('BUILDID')"
python3 -c "import pwn; pwn.libcdb.search_by_symbol_offsets({'puts': 0x7f6a0, 'printf': 0x64e10})"
```

**Online libc databases:**
- https://libc.rip (best — paste 2+ symbol offsets)
- https://libc.blukat.me
- https://libc.nullbyte.cat

## 5. pwntools Template (canonical, use this skeleton)

```python
#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./chall')
libc = elf.libc                    # auto-loads matching libc
# libc = ELF('/path/to/libc.so.6')  # explicit if you know the version

def conn():
    if args.REMOTE:
        # If the target is only given as ws:// / wss:// (no raw host:port),
        # bridge it first: load_skill(["wsrx"]) →
        #   wsrx connect --host 127.0.0.1 --port 13337 "wss://.../instance" &
        # then remote('127.0.0.1', 13337) below.
        return remote('host', 1337)
    elif args.GDB:
        return gdb.debug('./chall', gdbscript='continue\n')
    else:
        return process('./chall')

io = conn()

# --- your exploit here ---
io.sendline(b"AAAA")
io.interactive()
```

**Run modes:**
```bash
python3 exploit.py             # local
python3 exploit.py REMOTE     # remote
python3 exploit.py GDB         # local + gdb attach
```

## 6. Cyclic Pattern (find the offset instantly)

```python
from pwn import *
print(cyclic(200).decode())
# Send this payload; on crash, the saved EIP/RIP gives the offset
print(cyclic_find(0x61616164))   # 0x61616164 is "daaa" — first 4 bytes of the saved RIP
```

Or as a one-liner:
```bash
python3 -c "from pwn import *; print(cyclic(200).decode())" | ./chall
gdb ./chall
# in gdb with pwndbg: r < <(python3 -c "from pwn import *; print(cyclic(200).decode())")
# pwndbg prints: "Invalid read at 0x6161616161616161" → offset is cyclic_find(0x61616161)
```

## 7. GDB + pwndbg (the only sensible debugger setup)

```bash
# Install
git clone https://github.com/pwndbg/pwndbg /opt/pwndbg
echo "source /opt/pwndbg/gdbinit.py" >> ~/.gdbinit

# Useful pwndbg commands
gdb ./chall
#   starti                       # stop at first instruction
#   b main                       # break at main
#   c                            # continue
#   vmmap                        # show process memory map
#   telescope 0x404000 20        # show 20 qwords at address
#   regs                         # show all registers
#   stack 30                     # show top 30 stack entries
#   rop                          # search for ROP gadgets
#   search 'string'              # find a string in memory
#   find /bin/sh                 # find /bin/sh in mapped memory
#   checksec                     # re-run checksec at runtime (with libc / ld info)
#   retaddr                      # find all return addresses (RBP chain)
#   vvar                         # kernel symbols (bypasses for KASLR)
#   kbase                        # kernel base (if kernel pwn)
```

**GDB-scripting example (run binary, break at `main+0x40`, dump stack):**
```bash
gdb -batch -ex "set follow-fork-mode child" -ex "b *main+0x40" -ex "r <<< $(python3 -c 'print(cyclic(200))')" -ex "info reg" -ex "x/30gx \$rsp" ./chall
```

## 8. Ghidra Quick-CLI (decompile headless)

```bash
analyzeHeadless /tmp/ghidra_proj chall_proj -import chall -postScript decompile_all.java
# Or just open in GUI: ghidraRun
```

**Tips:**
- Press `G` to jump to address, `L` to rename a label
- "Defined strings" window is the same as `strings -tx`
- `Window → Decompile` (F5) is the closest thing to source
- Patch flow: `Right-click → Patch Instruction` (use with care in CTF)

## 9. Disassembler One-Liners

```bash
# Quick disasm of a function
objdump -d -M intel chall | awk '/<main>:/,/^$/' | head -50

# Search for specific syscall
objdump -d chall | grep -B1 "syscall"
objdump -d chall | grep -E "int 0x80|syscall" | head

# Find win functions
objdump -d chall | grep -E "<win>|<shell>|<flag>|<system>"
nm chall | grep -iE "win|shell|flag|admin|debug"

# Strings in .rodata with addresses (handy for ROP / shellcode)
objdump -s -j .rodata chall | head
```

## 10. Pre-Exploit Checklist

| Step | Tool | Output |
|---|---|---|
| 1 | `file`, `checksec` | Arch, protections |
| 2 | `strings`, `objdump` | Behavior hints |
| 3 | `run` once | Crash? Format string? |
| 4 | `nm` / `objdump` | Win function / imports |
| 5 | `ldd` / libcdb | Libc version |
| 6 | `gdb` + pwndbg | Set breakpoints, probe memory |
| 7 | `pwn template` | Skeleton exploit |

## Common Pitfalls

- **Forgot to disable ASLR locally but enabled remotely** — setarch/ASLR-disabled is for local dev only; the remote has ASLR on, so a leak is mandatory.
- **Wrong libc** — the libc on the server is rarely the one in `/lib/`. Always identify from a leak.
- **PIE base is randomized** — without a leak, no exploit works. Look for an info-leak primitive early.
- **No `win()` function** — many CTFs require a full ROP / ret2libc. Check `nm` for any "win" / "shell" / "flag" / "read_flag" symbol; if none, plan for ROP.
- **The binary forks** — use `gdb.attach(p)` on the child. Set `follow-fork-mode child`.
- **Canary is enabled** — you need a leak (often via `printf("%17$p")` to print the canary). Or use a 1-byte canary brute if the binary forks.
- **Statically linked** — no libc. Plan a static ROP (search for `pop rdi; ret`, `pop rsi; ret`, `mov rdi, rax; ... syscall`).
- **Forgetting `context.binary = elf = ELF('./chall')`** — pwntools defaults to i386 if you don't set context, and your exploit silently targets the wrong arch.

## Tooling Quick Install (Kali)

```bash
sudo apt install -y gdb python3-pip git
pip3 install pwntools
git clone https://github.com/pwndbg/pwndbg /opt/pwndbg
echo "source /opt/pwndbg/gdbinit.py" >> ~/.gdbinit
# Optional:
# Ghidra
# pwninit (auto-fetches matching libc, generates pwn template)
pip3 install pwninit
# pwninit ./chall      # generates exploit.py + libc
```
