---
name: ctf-reversing-static
description: Static reverse engineering for CTF challenges — Ghidra/IDA workflow, common encodings, license-key crackmes, algorithm reconstruction, custom VM, and unpacking
---

# CTF Static Reverse Engineering

The "reverse this binary" challenge. Goal: understand the logic, recover the algorithm, produce the correct input (or the flag directly). Static RE is the path of least resistance — run gdb only when static analysis hits a wall.

## 1. Triage Pipeline (first 5 minutes)

```bash
file chall                       # arch, OS, packed?
checksec --file=./chall          # protections
strings -n 6 chall | head -50    # visible strings
objdump -d -M intel chall | wc -l   # instruction count (a few thousand = crackme; millions = malware)
readelf -d chall                 # libraries, dynamic info
```

**The five questions to answer first:**
1. **Architecture?** i386 / amd64 / ARM / MIPS / PowerPC / WASM / EBC / custom
2. **Packed?** entropy > 7.0, suspicious sections, no readable strings → unpack first
3. **Statically or dynamically linked?** determines whether libc is in the binary
4. **What does it take as input?** argv, stdin, file, env, network?
5. **What does it print?** success message ("Correct!"), error, exit code, network response?

## 2. The Standard 5-Minute Crackme Walkthrough

Crackmes are the bread-and-butter of CTF reversing. 90% have this skeleton:

```c
int main(int argc, char *argv[]) {
    if (argc < 2) { puts("usage: ./chall <password>"); return 1; }
    if (check(argv[1])) {
        puts("Correct! The flag is CTF{...}");
        return 0;
    }
    puts("Wrong.");
    return 1;
}
```

### Step 1: Find the success branch
```bash
strings chall | grep -iE "correct|right|flag|good|invalid|wrong"
# Most CTF binaries leak the success string
```

### Step 2: Find the cross-references to that string
- In Ghidra: double-click the string in the "Defined Strings" window → see the XREF in the disassembler
- In radare2: `izz~Correct` then `axt @@ str.<address>` to find callers
- In IDA: `X` on the string

### Step 3: Read the check function
Open the function that contains the XREF. In Ghidra, press F5 to decompile. Read the C.

### Step 4: Reimplement the check in Python
```python
def check(input_bytes):
    # Whatever the decompile shows
    return True
```

### Step 5: Solve it
- If it's a length check → measure
- If it's a comparison → just print the expected
- If it's an algorithm → reimplement and reverse
- If it's a hash → brute (e.g. MD5 of common words)
- If it's an encryption (AES, RC4) → recover the key from the binary and decrypt

## 3. Common CTF Algorithm Patterns

### 3a. Char-by-char comparison (the trivial case)
```c
if (input[0] == 'C' && input[1] == 'T' && input[2] == 'F' && input[3] == '{' && ...) {
    puts("Correct");
}
```
**Solve:** `strings chall | grep CTF` may show the flag literally (compiler keeps the string). If not, just read the bytes from the disassembly.

### 3b. XOR with a known key
```c
for (i = 0; i < len; i++) {
    if ((input[i] ^ key[i % keylen]) != target[i]) return 0;
}
```
**Solve:** If you have the encoded target and the key, XOR → flag. If you have the encoded target and one known input byte, recover the key.

### 3b-bis. XOR with a generated keystream (the harder case)
```c
// Common in 2023-2024 CTFs: PRNG-based keystream
int s = 0x1337;
for (i = 0; i < len; i++) {
    s = s * 0x343fd + 0x269ec3;       // simple LCG
    keystream[i] = (s >> 16) & 0xff;
    if ((input[i] ^ keystream[i]) != target[i]) return 0;
}
```
**Solve:** Reimplement the PRNG, generate the keystream, XOR.

### 3c. Byte-swap / nibble-swap
```c
for (i = 0; i < len; i++) {
    transformed[i] = ((input[i] >> 4) | (input[i] << 4)) & 0xff;
}
```
**Solve:** Apply the inverse.

### 3d. Substitution table (S-box)
```c
static const uint8_t sbox[256] = {0x63, 0x7c, 0x77, 0x7b, ...};   // AES S-box
for (i = 0; i < len; i++) {
    if (sbox[input[i]] != target[i]) return 0;
}
```
**Solve:** Build the inverse S-box and apply. For AES, use the AES inverse S-box; for custom, build it from the data.

### 3e. AES (real cryptography)
```c
// AES-128-ECB
AES_ECB_encrypt(input, output, key);
if (memcmp(output, target, 16) == 0) ...
```
**Solve:** Read the key from `.rodata`, decrypt the target with `openssl enc -aes-128-ecb -d -K <key> -nosalt -nopad -in <target>`. Or use Python's `cryptography` library.

**AES-CTR mode (the 2024+ common case):**
```c
// CTR with a known nonce
// Target = AES_CTR_encrypt(key, nonce=0, input)
// To recover input, decrypt target with same key and nonce
```

### 3f. RC4
```c
// RC4 setup + PRGA
for (i = 0; i < len; i++) {
    if ((input[i] ^ rc4_next()) != target[i]) return 0;
}
```
**Solve:** Reimplement RC4 with the same key.

### 3g. Custom hash (the "rolling sum" type)
```c
uint32_t h = 0xcafebabe;
for (i = 0; i < len; i++) {
    h = (h << 5) - h + input[i];
}
if (h != target_hash) return 0;
```
**Solve:** Reimplement, then brute (Django's password hashers use this style).

### 3h. Time / clock dependent check
```c
time_t t = time(NULL);
if (input[0] == (t & 0xff) && ...) { ... }
```
**Solve:** Match the current time on the CTF server. Or use `LD_PRELOAD` to fake `time()`.

## 4. Tooling Workflows

### Ghidra
```
1. File → New Project → Non-Shared → Import File (chall) → double-click to analyze
2. Wait for analysis (~30s for medium binaries)
3. Defined Strings (Search → For Strings): look for "Correct", "Wrong", "flag"
4. XREF the success string → see check function
5. F5 to decompile
6. Edit function names (L) to track which is which
7. Search → For Scalars / For Instruction Patterns (e.g. "XOR AL, 0x42")
8. Patch (Right-click → Patch Instruction) — to neutralize checks
```

### radare2 (CLI, the no-install option)
```bash
r2 -A chall
[0x00000000]> afl              # list functions
[0x00000000]> s main           # seek to main
[0x00000000]> pdf             # print disassembly of current function
[0x00000000]> iz~Correct      # find the success string
[0x00000000]> axt @@ str.*    # find XREFs to all strings
[0x00000000]> VV              # visual mode (Vim-like)
# r2ghidra (Cutter) for decompile
```

### IDA Free / Pro
- Standard "F5 decompile" workflow
- Hex-Rays decompiler is the gold standard
- `Edit → Functions → Reconstruct` for stripped binaries

## 5. Unpacking / Deobfuscation

### UPX
```bash
file chall          # may say "UPX compressed"
upx -d chall -o chall.unpacked
```

### Custom packers
- **Entropy analysis** in Detect-It-Easy (DIE) or `binwalk -E chall`
- **Single-step unpacking** in gdb:
  1. Find `OEP` (Original Entry Point) — search for the unpacked magic (e.g. `MZ` again)
  2. Set a hardware breakpoint on the `OEP` candidate address
  3. Run; when the breakpoint hits, dump the process with `gcore`
  4. Fix imports with `ImpRec` or `Scylla` (PE) / `ld.so` patch (ELF)
- **Scylla** (PE) or **manual IAT rebuild** (ELF) — for imports

### String obfuscation (the common 2024+ pattern)
- Strings are XOR'd, AES'd, RC4'd, or split byte-by-byte in code
- `FLOSS` (FireEye Labs Obfuscated String Solver) auto-decodes
- `strings -e l` for wide strings, `-e b` for big-endian 16-bit
- Hook `printf` / `puts` calls in gdb to see the **decoded** version

### Control flow flattening
- All blocks are in a switch with a state variable
- Recover with `d810` (Ghidra plugin) or manual variable tracking

### OLLVM (obfuscator-llvm)
- Control-flow flattening, bogus control flow, instruction substitution
- `OLLVM-Deflat` or `symgrind2` deobfuscators
- Manual: trace the state variable, draw the actual CFG

## 6. Custom Virtual Machines (the 2023-2024 trend)

A CTF binary that:
- Parses input as bytecode
- Has a switch-based interpreter
- Each "opcode" is a case in a switch

**Solver approach:**
1. Find the bytecode parser — usually a function that reads the input as a sequence of bytes
2. Find the dispatch loop — a `while` or `for` with a `switch(opcode)` body
3. Document each opcode's semantics (read the case body in Ghidra)
4. Reimplement the VM in Python
5. Solve symbolically (Z3) or by direct code gen

**Symbolic execution for VM challenges:**
```python
from z3 import *
s = Solver()
# Allocate symbolic input bytes
flag = [BitVec(f"b{i}", 8) for i in range(40)]
state = ...   # VM state, symbolic
# Run the VM
for opcode in program:
    state = step(state, opcode, flag)
# Constrain final state to be "accept"
s.add(state.accepted == True)
s.check()
print(s.model())
```

## 7. Anti-Debug Bypasses

| Technique | Detection | Bypass |
|---|---|---|
| `ptrace(PTRACE_TRACEME, 0, 0, 0)` | Returns -1 if traced | Patch the call; use `LD_PRELOAD` to fake ptrace; gdb's `catch syscall ptrace` |
| `IsDebuggerPresent()` (PE) | Read PEB.BeingDebugged | Patch the call |
| `CheckRemoteDebuggerPresent()` | NT query | Patch |
| `NtQueryInformationProcess` with `ProcessDebugPort` | Returns -1 if not debugged | Patch return value |
| `int 0x2d` (Windows) | Triggers breakpoint only when debugged | NOP the int |
| Timing checks (`rdtsc`) | Compare cycles | NOP the comparison; set gdb to skip the timing code |
| `Sleep` with timeout | If under debugger, returns immediately | Patch the comparison |

**ELF equivalent:**
- `IsDebuggerPresent` is Windows-specific; ELF binaries use `ptrace` or `LD_DEBUG` checks
- `LD_PRELOAD` of a fake `ptrace` library

## 8. The "5-Minute Pattern Matcher" Workflow

When you've done 100 CTF reverses, the patterns jump out:
- `xor eax, 0x42` → XOR with 0x42
- `cmp al, 'C'` / `cmp al, 'T'` / `cmp al, 'F'` / `cmp al, '{'` → char-by-char string compare
- `mov [rbp-X], al; ...` followed by `mov al, [rbp-Y]` → variable assignment chain
- A loop with `add rax, rdx; rol rax, 13` → custom hash
- A long sequence of `cmp` against constants → constant table (S-box or similar)

When in doubt, **diff the binary with itself under different inputs** — `ltrace ./chall test` shows the libc calls, `strace ./chall test` shows the syscalls.

## Common Pitfalls

- **F5 decompile is misleading on packed code** — first unpack, then decompile
- **Strings are obfuscated** — try `strings -e l -e b -e L -e B`; try `floss`; hook the print call
- **The check uses `time(NULL)`** — your local time may not match the server's. Run on the server (remote) or accept the timestamp window
- **The binary uses an HMAC-like construction with a server secret** — you need the server secret; static RE will not work. Switch to dynamic analysis.
- **The check is in a shared library** — `LD_PRELOAD` or `gdb` to inspect; or `ltrace` for libc calls
- **Floating point** — IEEE-754 comparisons; `eax` reads as `int` but the value is `float`. Use `data.[0]` conversion in Ghidra's decompile.

## Tooling Quick Reference

```bash
file chall
checksec --file=./chall
strings -n 6 -a -e l chall
floss chall
ghidraRun     # GUI
r2 -A chall
objdump -d -M intel chall | less
ltrace ./chall test
strace ./chall test
```
