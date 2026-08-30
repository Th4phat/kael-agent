---
name: ctf-reversing-langs
description: CTF reversing for non-C languages — Python (pyc, pyinstaller, marshal), .NET (dnSpy, ilspycmd), Java (cfr, procyon), Go, Rust, and WebAssembly
---

# CTF Reverse Engineering — Non-C Binaries

Half of modern CTF reversing challenges are not C. Python, .NET, Java, Go, Rust, and WebAssembly are common — each has its own toolchain.

## 1. Python (`pyc`, `.pyo`, PyInstaller, marshal)

### File triage
```bash
file chall
# Python script, ASCII text           →  .py source
# Python bytecode 3.8                 →  .pyc, decompile with decompyle3 or uncompyle6
# data                                →  PyInstaller archive, extract with pyinstxtractor
```

### Decompile `.pyc` (CPython bytecode)
```bash
# CPython 3.8+: decompyle3 doesn't work; use pycdc or pylingual
pip install pylingual                  # 2023+ best decompiler (web)
# Local options:
pip install decompyle3                  # 3.7 only
git clone https://github.com/zrax/pycdc && cd pycdc && cmake . && make
./pycdc chall.pyc
```

### Recover source from `.pyc` (older 3.7 and 2.7)
```bash
pip install uncompyle6
uncompyle6 chall.pyc
# For 2.x: uncompyle6 works
# For 3.7: decompyle3 works
# For 3.8+: pylingual or pycdc only
```

### PyInstaller
```bash
pip install pyinstxtractor
pyinstxtractor.py chall.exe
# → chall.exe_extracted/  (contains a `_chall.pyc` or `chall.pyc` in PYZ archive)
# Or: pyinstxtractor.py -g chall.exe   # also extract the PYZ archive
python3 pyinstxtractor.py -g chall.exe
# The .pyc is then decompilable
```

### Manual extraction (when pyinstxtractor misses)
The PyInstaller archive is a giant blob with a CArchive. The `.pyc` files are inside. Use:
```python
import zlib, struct
with open('chall.exe', 'rb') as f: data = f.read()
# Find PYZ archive marker
idx = data.find(b'PYZ\0')
# Extract
```

### Marshal
Python's `marshal` is the bytecode serializer. Some challenges pre-compile Python with `compile()` and write the bytecode with `marshal.dump`. The result is not a `.pyc` (no magic header) — it's just bytes. Use `marshal.loads()`:
```python
import marshal, dis
with open('chall.bin', 'rb') as f: data = f.read()
# Skip 8 bytes header (challenge-specific)
code = marshal.loads(data[8:])
dis.dis(code)
```

### Python source-only protections
- `cython` (`.so`): reverse with `cython-decompiler` or just disassemble
- `nuitka` (compiled C from Python): reverse with Ghidra
- `pyarmor` / `pyobfuscate`: deobfuscate with `pyarmor-decrypt` or manually

## 2. .NET (`dll`, `exe`)

### Tools
- **dnSpy** (Windows, free) — the gold standard for .NET RE
- **ILSpy** (Windows, GUI)
- **ilspycmd** (CLI)
- **dotnet-ilspy** (CLI for .NET Core)

```bash
# Linux decompile
dotnet tool install -g ilspycmd
ilspycmd chall.dll
ilspycmd chall.dll -o output_dir
```

### Common CTF patterns
- **XOR'd strings** — search for byte arrays in the decompile; convert to string
- **Reflection.Emit / dynamic code** — load with `dnSpy`, set a breakpoint, watch the JIT-compiled code
- **ConfuserEx** — obfuscator. `de4dot -f chall.exe -o deobfuscated.exe`

## 3. Java (`jar`, `class`, `war`)

### Tools
- **cfr** (Class File Reader) — best modern decompiler
- **procyon** — alternative
- **JD-GUI** — GUI
- **jadx** — for Android (`apk`) and Java

```bash
# Decompile a class file
cfr chall.class

# Decompile a jar
cfr chall.jar --outputdir decompiled/

# Decompile an APK (Android)
jadx chall.apk
```

### Spring Boot fat-jar
- Rename `.jar` to `.zip`, extract
- `BOOT-INF/classes/...` contains the class files; decompile those
- `BOOT-INF/lib/` has the dependencies

### Java native (JNI) parts
- Decompile the Java first to find the native call
- Then reverse the `.so` / `.dll` with Ghidra

## 4. Go

### Tools
- **ghidra** with the Go plugin (auto-loaded in newer versions)
- **radare2** with Go support
- **redress** — Go binary redresser
- **go-re-toolkit** — for type recovery

### Common CTF Go challenges
- Strings are in a giant `go.string.*` table — search for the expected prefix
- Function names: `main.main` is the entry; the check is in `main.checkPassword` or similar
- Use `Ghidra` → `Window → Defined Strings` → `Filter: "Correct"` to find the success branch

```bash
# Strip Go symbols to make it harder
go build -ldflags="-s -w" chall.go
```

## 5. Rust

### Tools
- **Ghidra** with Rust support (limited)
- **IDA** with rust-demangler (built-in for newer versions)
- **cutter** (radare2 GUI) with rust-demangler

### Common Rust RE patterns
- Heavy use of `Result` and `Option` enums → lots of branching
- `panic!` strings are often plaintext
- The check function has a clear "if check succeeds" → "print success" → "exit" pattern
- Format strings: `println!("Correct: {}", flag)`

```bash
# Strip symbols to make it harder
cargo build --release
strip target/release/chall
```

## 6. WebAssembly (`.wasm`)

### Tools
- **wasm2wat** + **wat2wasm** (WABT)
- **wasm-decompile** (WABT)
- **ghidra** with WASM support
- **wasmtime** / **wasmer** to execute
- **Binaryen** for transformations

```bash
# Convert to text format
wasm2wat chall.wasm -o chall.wat

# Decompile to C-like
wasm-decompile chall.wasm -o chall.c

# Run with a runtime
wasmtime chall.wasm

# Analyze
wasm-objdump -h chall.wasm      # headers
wasm-objdump -d chall.wasm      # disassembly
```

### Common CTF WASM challenges
- WebAssembly for a CTF web challenge: serve the `.wasm` from a page, decompile the JavaScript glue
- WebAssembly for a binary challenge: standalone `.wasm`, run with `wasmtime` or `wasmer`
- Strings are in the data section, can be dumped with `wasm-objdump -s`

## 7. PowerShell (Windows)

```bash
# Strings and basic analysis
strings chall.ps1
# Decompile: PowerShell is interpreted; the "compiled" forms are .NET assemblies

# For PSScript-obfuscated files
# https://github.com/R3MRUM/PSDecode
python3 PSDecode.py chall.ps1
```

## 8. JavaScript (Node.js binary challenges)

```bash
# Bundle / package extract
# pkg: https://github.com/vercel/pkg
npx pkg extract chall

# bytenode: V8 snapshot
# bytenode can be reverted; use bytenode-unpacker

# node-protect, jsvmp, javascript-obfuscator
# javascript-obfuscator deobfuscate: webcrack
npx webcrack input.js -o output.js
```

### javascript-obfuscator
- Look for `_0x123456` variable names and `_0xabcd('xyz')` calls
- `webcrack` does AST-based deobfuscation
- Manual: rename variables, replace string array calls, evaluate the function
- Sometimes the obfuscation is just a control-flow flat; run the JS in a JS REPL with the strings substituted

## 9. SQL (CTF "reverse" with a SQL query)

Some challenges are "find the input that, when this SQL returns it, gets you the flag". The query is the algorithm.

```sql
-- Common pattern: input is X, query has checks
SELECT CASE
  WHEN substr(:input, 1, 4) != 'CTF{' THEN 'wrong'
  WHEN ... THEN 'correct'
  ELSE 'wrong'
END
```
**Solve:** just read the SQL; the answer is the literal string.

## 10. Other Languages

| Language | Tool |
|---|---|
| Swift | Hopper, Ghidra |
| Objective-C | Hopper, Ghidra |
| Haskell | Look for the `IO` wrapper around the check |
| Erlang BEAM | `erlang-otp` decompiler; pretty rare in CTF |
| Lua | `unluac` (decompiler for compiled Lua) |
| Perl | `B::Deparse` (for B-compiled code) |
| Ruby | `decompiler` is rare; usually it's `marshal.load` of bytecode; `RubyVM::InstructionSequence#disasm` |
| Dart / Flutter | `blutter` (Dart reverse) |
| Solidity (blockchain) | `slither`, `mythril` |

## Common Pitfalls

- **Python version mismatch** — `.pyc` from 3.10 won't decompile with 3.8's decompyle3. Match the version.
- **PyInstaller is a "single file"** — but the structure is documented; pyinstxtractor handles 90% of cases
- **.NET assembly is mixed-mode** — may have native DLLs inside. Decompile the .NET parts, reverse the native parts separately.
- **Java uses ProGuard / Allatori** — symbol renaming; you need to follow data flow, not symbols
- **Go binaries are large** — the binary has the entire runtime baked in. Use `addr2line` to map addresses to source lines if you have a build artifact.
- **WASM is bytecode, not native** — `wasm-decompile` gives a C-like output, but it's still not source. Hand-walking the linear code is often faster.
- **JavaScript obfuscator output is a `eval`** — replace `eval` with `console.log` and inspect the result

## Tooling

```bash
# Python
pip install uncompyle6 decompyle3 pylingual
git clone https://github.com/zrax/pycdc
git clone https://github.com/extremecoders-re/pyinstxtractor

# .NET
dotnet tool install -g ilspycmd
# or download dnSpy

# Java
wget https://github.com/leibnitz27/cfr/releases/latest/download/cfr.jar
java -jar cfr.jar chall.class

# Go
# Ghidra + Go plugin (built-in in 11.0+)
# redress
go install github.com/goretk/redress@latest
redress -mode=aggressive chall

# Rust
# Ghidra (limited) or IDA (with rust-demangler)

# WASM
git clone https://github.com/WebAssembly/wabt
cd wabt && make
./bin/wasm2wat chall.wasm -o chall.wat
./bin/wasm-decompile chall.wasm
```
