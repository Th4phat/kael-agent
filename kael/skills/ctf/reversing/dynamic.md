---
name: ctf-reversing-dynamic
description: Dynamic reverse engineering for CTF — gdb scripting, angr symbolic execution, unicorn emulation, frida hooks, and emulator-based unpackers
---

# CTF Dynamic Reverse Engineering

When static analysis is too slow or too lossy (obfuscation, anti-debug, runtime decryption). Use gdb for direct observation, frida for live hooks, unicorn for full emulation, and angr for symbolic solving.

## 1. gdb + pwndbg / GEF /peda (canonical dynamic workflow)

### Run + observe
```bash
gdb ./chall
(gdb) starti                 # break at first instruction
(gdb) b main
(gdb) c                      # continue
(gdb) info reg               # registers
(gdb) x/20gx $rsp            # stack
(gdb) x/s $rdi               # first argument as string
(gdb) disas main             # disassemble main
```

### Conditional breakpoints
```bash
(gdb) b *0x401234 if $rax == 0x1337
(gdb) b puts if strcmp((char*)$rdi, "Correct") == 0
(gdb) commands 1
  > print/x $rdi
  > x/s $rdi
  > continue
  > end
```

### Watchpoints (break on memory write)
```bash
(gdb) watch *(int*)0x404040            # break on write to address
(gdb) rwatch *(int*)0x404040           # break on read
(gdb) awatch *(int*)0x404040           # break on either
```

### Stepping
```bash
(gdb) si       # step one instruction
(gdb) ni       # step one instruction (skip calls)
(gdb) s        # step one source line
(gdb) n        # step one source line (skip calls)
(gdb) fin      # finish current function
(gdb) until *0x401300   # run until address
```

### Useful pwndbg commands
```bash
gdb-peda$ vmmap                # memory map
gdb-peda$ telescope 0x404040 20  # dereference 20 qwords
gdb-peda$ stack 30             # show 30 stack entries
gdb-peda$ rop                  # search for ROP gadgets
gdb-peda$ find /bin/sh         # find /bin/sh in memory
gdb-peda$ checksec             # recheck protections
gdb-peda$ plt                  # show PLT entries
gdb-peda$ got                  # show GOT entries
gdb-peda$ canary               # show stack canary
gdb-peda$ magic                # find a magic gadget
gdb-peda$ retaddr              # return addresses on stack
gdb-peda$ callstack            # backtrace
gdb-peda$ trace 0x401234       # trace hits of an address
gdb-peda$ tracecall puts       # trace calls to a function
gdb-peda$ traceinst            # trace every instruction (slow!)
gdb-peda$ procinfo             # /proc info
gdb-peda$ libc                 # find libc base
gdb-peda$ ld                   # find ld-linux base
gdb-peda$ heapinfo             # glibc heap summary
gdb-peda$ arena                # show main arena
gdb-peda$ bins                 # show all malloc bins
gdb-peda$ tcache               # show tcache
```

## 2. ltrace / strace (low-friction observation)

```bash
ltrace ./chall test
# 0x7f... puts("Correct!") = 8
# 0x7f... strcmp("test", "s3cr3t") = -42

strace ./chall test
# open("/etc/ld.so.cache", O_RDONLY) = 3
# read(3, ...)

# Filter for a syscall
strace -e open,read,write,connect ./chall
# Follow child processes
strace -f ./chall
# Write to a file
strace -o /tmp/trace.log ./chall
```

## 3. frida (live code instrumentation)

Frida hooks into a running process and lets you inject JavaScript that calls / replaces functions in the binary.

### Install
```bash
pip install frida-tools
# Binary: download matching frida-server from GitHub releases for the target's arch
```

### Basic hook — print all calls to `check`
```javascript
// hook.js
const base = Module.findBaseAddress('chall');
const check_addr = base.add(0x1234);  // offset of check()

Interceptor.attach(check_addr, {
    onEnter: function(args) {
        console.log('check(' + Memory.readUtf8String(args[0]) + ')');
        this.input_ptr = args[0];
        this.input_len = args[1].toInt32();
    },
    onLeave: function(retval) {
        console.log('  -> ' + retval);
        // If check returns 0 (wrong), patch the return to 1 (correct)
        retval.replace(1);
    }
});
```

```bash
frida -f ./chall -l hook.js --no-pause
```

### Hook printf/puts to see hidden strings
```javascript
const puts = new NativeFunction(Module.findExportByName(null, 'puts'), 'pointer', ['pointer']);
Interceptor.attach(puts, {
    onEnter: function(args) {
        console.log('puts: ' + Memory.readUtf8String(args[0]));
    }
});
```

### Trace a function and its args
```javascript
Interceptor.attach(Module.findExportByName(null, 'strcmp'), {
    onEnter: function(args) {
        console.log('strcmp(' + Memory.readUtf8String(args[0]) + ', ' + Memory.readUtf8String(args[1]) + ')');
    }
});
```

### Modify a global at runtime
```javascript
// Set a global "is_admin" to 1
const admin_addr = Module.findBaseAddress('chall').add(0x5040);
Memory.writeU8(admin_addr, 1);
```

### Use a Python script to control frida
```python
import frida
session = frida.attach('chall')
script = session.create_script(open('hook.js').read())
script.load()
# Wait for output
```

## 4. angr (symbolic execution — solves checks automatically)

`angr` is a Python framework that builds a symbolic representation of a binary, then explores paths to find inputs that reach a target address.

### The CTF canonical pattern: avoid "Correct", reach "Correct"
```python
import angr

# Load binary
proj = angr.Project('./chall', auto_load_libs=False)

# Build initial state
state = proj.factory.entry_state(
    args=['./chall', 'angr_input'],
    add_options={angr.options.LAZY_SOLVES, angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY, angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
)

# Create simulation manager
simgr = proj.factory.simulation_manager(state)

# Explore: find "Correct" and avoid "Wrong"
simgr.explore(find=lambda s: b'Correct' in s.posix.dumps(1),
              avoid=lambda s: b'Wrong' in s.posix.dumps(1))

if simgr.found:
    solution = simgr.found[0]
    flag = solution.posix.dumps(0)   # stdin
    print(flag)
```

### Stdin vs argv vs file input
```python
# Stdin
state = proj.factory.entry_state()
flag_chars = [state.solver.BVS(f'flag_{i}', 8) for i in range(N)]
state.posix.stdin.write(''.join(map(chr, flag_chars)))
simgr.explore(find=..., avoid=...)

# argv[1]
state = proj.factory.entry_state(args=['./chall'] + [b'\x00' * 100])

# File
state = proj.factory.full_init_state(
    fs={'flag.txt': angr.SimFile(name='flag.txt', content=bitvec_array)}
)
```

### Constrain + solve
```python
# Limit to printable
for c in flag_chars:
    state.solver.add(c >= 0x20)
    state.solver.add(c <= 0x7e)

# Length is exactly N
state.solver.add(state.solver.Or(
    state.posix.stdin.content[0][0] == ord('C'),
    ...
))
# Better: just constrain to the start of CTF{
for c, expected in zip(flag_chars, b'CTF{'):
    state.solver.add(c == expected)

print(state.solver.eval(''.join(map(chr, flag_chars)), cast_to=bytes))
```

### Hooking libc functions in angr
```python
# Skip slow / complex functions
class Skip(angr.SimProcedure):
    def run(self, *args, **kwargs): return 0
proj.hook_symbol('strcmp', Skip())
proj.hook_symbol('memcpy', Skip())
```

### When angr is too slow
- Limit the loop count with `LAZY_SOLVES`
- Hook the slow functions
- Use `Veritesting` (enabled by default in newer angr)
- Use `unicorn` directly to emulate (faster for some binaries)

## 5. unicorn (CPU emulation, fast)

`unicorn` is a CPU emulator (built on QEMU). It runs machine code in a controlled environment.

### Emulate a function from a binary
```python
from unicorn import *
from unicorn.x86_const import *
import struct

mu = Uc(UC_ARCH_X86, UC_MODE_64)

# Map memory
BASE = 0x400000
mu.mem_map(BASE, 0x100000)
mu.mem_map(0x1000000, 0x1000)        # stack
mu.mem_map(0x2000000, 0x1000)        # data

# Load binary
with open('./chall', 'rb') as f:
    code = f.read()
# ... (parse ELF, copy .text to BASE, etc.)

# Set up stack
mu.reg_write(UC_X86_REG_RSP, 0x1000800)
mu.reg_write(UC_X86_REG_RBP, 0x1000800)

# Hook to inspect
def hook_code(uc, address, size, user_data):
    if address == 0x401300:
        rax = uc.reg_read(UC_X86_REG_RAX)
        print(f"rax = {rax:#x}")
mu.hook_add(UC_HOOK_CODE, hook_code)

# Run
mu.emu_start(0x401000, 0x401500)
```

### Use `pwntools` + `unicorn` for emulator-driven pwn
- For pwn challenges where gdb is overkill, emulate the target function and inject the ROP
- For reversing, emulate the check function to see what input it accepts

## 6. Emulation Frameworks

| Tool | Use |
|---|---|
| `unicorn` | Raw CPU emulation, fast, no OS |
| `unicorn-engine/unicorn` | The C library, Python bindings |
| `qemu-user` | Run a binary in a "user-mode" emulated environment, can debug with gdb |
| `qemu-system` | Full system emulation (rarely needed for CTF) |
| `crosstool-NG` | Cross-compile to run a non-native binary |
| `gem5` | Detailed architecture simulation (rare in CTF) |
| `GHIDRA + p-code emulator` | For very weird architectures (EBC, custom) |

```bash
qemu-x86_64 -g 1234 ./chall
# Connect with gdb: target remote :1234
# Same disassembly as native
```

## 7. Hooking Anti-Debug (When You Can't Unpack)

Sometimes the binary is so heavily packed that gdb ptrace is detected. Workarounds:

1. **Use a different debugger** — `gdb` (ptrace) is the most-detected. `rr` (record-and-replay), `DynamoRIO`, or `qemu-user` are not detected by typical anti-debug.
2. **LD_PRELOAD a fake ptrace** — write a `fake_ptrace.c` that always returns 0:
   ```c
   long ptrace(int request, ...) { return 0; }
   ```
   `gcc -shared -fPIC fake_ptrace.c -o /tmp/fake_ptrace.so`
   `LD_PRELOAD=/tmp/fake_ptrace.so ./chall test`
3. **Patch the binary** — find the `IsDebuggerPresent` / `ptrace` call, NOP it.
4. **Use a hypervisor** — run in a VM with `libvmi` for in-guest memory inspection (heavyweight).

## 8. Network Reverse Engineering (binary talks to a server)

```bash
# Wireshark
wireshark capture.pcap

# Cutter/IDA with a remote-attached process
gdbserver :1234 ./chall
gdb -ex "target remote :1234"

# strace for syscalls
strace -f -e connect,sendto,recvfrom ./chall

# mitmproxy for HTTP
mitmproxy --mode reverse:http://target/
```

## 9. Decompiler Plugins

- **Ghidra**: `ghidra-analyzer-headless`, `ghidra-decompiler` (already in core), `simplify` (auto-cleanup), `ghidra-graphql` (programmatic)
- **IDA**: `HexRays decompiler`, `IDA Pro` (commercial)
- **Cutter / r2ghidra-dec**: free alternative, less powerful
- **Binary Ninja**: commercial, popular for 2024+ workflows

## Common Pitfalls

- **angr explodes on floating point** — constrain to integer-only paths or hook `printf("%f")`
- **angr is slow on large binaries** — bound the search depth, hook `printf`/`malloc`/`strcmp` to short-circuit
- **frida injects are detected** — some binaries check `/proc/self/maps` for `frida-agent`. Use `frida-gadget` (statically linked) or patch the check
- **unicorn needs the entire memory layout** — copy all sections of the ELF, set up the stack, set up any required data. Missing any of this = segfault
- **gdb stepping through heavily-obfuscated code** — use `until *address` instead of `si` to skip large obfuscation blocks
- **ltrace doesn't show PLT internal calls** — it shows the libc-level call. To see the binary's own functions, use gdb

## Tooling

```bash
# angr
pip install angr
python3 -c "import angr; p = angr.Project('/bin/ls'); print(p.arch, p.entry)"

# frida
pip install frida-tools
frida --version

# unicorn
pip install unicorn

# qemu-user (for non-native arch)
sudo apt install qemu-user qemu-user-static
qemu-x86_64 -g 1234 ./chall
```
