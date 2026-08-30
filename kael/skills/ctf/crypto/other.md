---
name: ctf-crypto-other
description: Non-RSA crypto CTFs — ECC, Diffie-Hellman, PRNG prediction, z3/SAT-based reversing, lattice (LLL), and the "implement this algorithm" challenge
---

# CTF Crypto — Other

Elliptic-curve crypto, Diffie-Hellman, PRNGs, z3/SAT reversing, and lattice attacks. Each has its own sub-skill; this file collects the CTF-relevant recipes.

## 1. Elliptic Curve Crypto (ECC)

### Quick sanity check
```python
# Verify the curve is on the standard list (or a custom twist of one)
# secp256k1 (Bitcoin), P-256, P-384, P-521, Curve25519 (X25519)
# Edwards25519, BN254, BLS12-381
from sage.all import *
p, a, b, Gx, Gy, n = ...   # from challenge
E = EllipticCurve(GF(p), [a, b])
G = E(Gx, Gy)
print(f"Curve order: {E.order()}")
print(f"G order: {G.order()}")
```

### Discrete log on weak curve
```python
# If the curve order is smooth (only small prime factors), Pohlig-Hellman solves it
from sympy.ntheory.residue_ntheory import discrete_log
from sage.all import *
n = E.order()
factors = factor(n)
# Pohlig-Hellman
m = 0
for p_i, e_i in factors:
    G_i = (n // p_i**e_i) * G    # subgroup generator
    P_i = (n // p_i**e_i) * P    # target in subgroup
    d_i = discrete_log(P_i, G_i, p_i**e_i)
    m = crt([m, d_i], [n // p_i**e_i, p_i**e_i])[0]
```

### Smart's attack (anomalous curve)
If `E.order() == p` (the curve is "anomalous"), the discrete log reduces to a p-adic log and is easy:
```python
# Sage one-liner
# (See: https://github.com/jvdsn/crypto-attacks/blob/master/attacks/ecc/smart_attack.py)
def smart_attack(P, Q, p):
    E = P.curve()
    assert E.order() == p
    # ... uses p-adic lifting
```

### Invalid curve attack
If the server doesn't validate the curve parameters in an EC point it receives, you can send a point on a curve of **smooth order** and recover the private key via Pohlig-Hellman.

```python
# 1. Find a curve E' with the same `a` and a custom `b` such that E' has smooth order
# 2. Send a point on E' to the server (server does scalar_mul(private_key, P))
# 3. Pohlig-Hellman on E' recovers the private key modulo the order of E'
# 4. Repeat with different E' to get the private key modulo LCM of all orders = the real order
```

### Singular curve (y^2 = x^3 + ax + b with discriminant 0)
Map to additive group; private key recovery is a single `log_p` operation. Smart's attack or a direct map.

### MOV attack (small embedding degree)
If the curve has small `k` such that `E[k]` is in `GF(p^k)*`, the discrete log reduces to a finite-field DLP, which is much easier when `k` is small.

```python
# Sage
k = E.order() // G.order()   # likely 1; the embedding degree
# Or compute the embedding degree directly
```

## 2. Diffie-Hellman

### Small subgroup attack
If the prime `p` has small factors, the DH key is recoverable by sending generator values whose order has only those small factors. Classic when `p` is `safe-prime`-ish but not quite.

### Invalid parameter attack
The server doesn't validate that the received public key is on the correct subgroup → send `1` (a small-subgroup element) and recover bits of the private key.

## 3. PRNG Prediction

### Linear Congruential Generator (LCG)
```python
# state_{n+1} = (a * state_n + c) mod m
# Given 3 outputs, recover (a, c, m) with lattice reduction
# Or: if m is known, two outputs are enough

def lcg_recover(states, m=None):
    # states = [s0, s1, s2, ...]
    diffs = [states[i+1] - states[i] for i in range(len(states)-1)]
    second_diffs = [diffs[i+1] - diffs[i] for i in range(len(diffs)-1)]
    # a = (s2 - s1) / (s1 - s0) mod m
    a = (states[2] - states[1]) * pow(states[1] - states[0], -1, m) % m
    c = (states[1] - a * states[0]) % m
    return a, c, m
```

### Mersenne Twister (MT19937)
```python
# Python's random uses MT19937
# Given 624 32-bit outputs, the state is recovered
# Symbol of the PRNG: outputs = untemper(state[i])
from randcrack import RandCracker
rc = RandCracker()
for _ in range(624): rc.submit(get_32bit_output())
print(rc.predict_getrandbits(32))
# pip install randcrack
```

### xorshift, xoshiro, Philox
- `xorshift32`: 32-bit state, recovered from 2 outputs
- `xorshift64`: 64-bit state, recovered from 3 outputs
- `xoshiro256**`: 256-bit state, recovered from ~5 outputs with lattice reduction

### LFSR (Linear Feedback Shift Register)
```python
# Standard: state is a binary vector, output is MSB, state shifts
# Given 2 * bitlen outputs, recover the feedback polynomial
# Use Berlekamp-Massey algorithm
def berlekamp_massey(s):
    n = len(s)
    C = [0] * n; B = [0] * n
    C[0] = 1; B[0] = 1
    L = 0; m = 1; b = 1
    for n_idx in range(n):
        d = s[n_idx]
        for i in range(1, L+1):
            d ^= C[i] & s[n_idx - i]
        if d == 0:
            m += 1
        elif 2*L <= n_idx:
            T = C[:]
            for i in range(m, n):
                C[i] ^= B[i - m]
            L = n_idx + 1 - L
            B = T
            b = d
            m = 1
        else:
            for i in range(m, n):
                C[i] ^= (d * pow(b, -1, 2)) * B[i - m]
            m += 1
    return L, C
# Sage has it built-in
```

## 4. z3 / SAT Solvers (for "Implement the inverse")

When the challenge is "given `c = f(x)` for some custom `f`, find `x`", encode `f` as a z3 problem.

### Template
```python
from z3 import *

def solve():
    s = Solver()
    # Symbolic input
    flag = [BitVec(f'b{i}', 8) for i in range(40)]
    # Constraints (e.g. printability)
    for c in flag:
        s.add(c >= 0x20, c <= 0x7e)
    # Symbolic execution of the challenge function
    state = list(flag)
    for op in program:
        if op == 'swap':
            state[op.a], state[op.b] = state[op.b], state[op.a]
        elif op == 'add':
            state[op.a] = state[op.a] + op.const
        # ...
    # Output constraints
    for i, expected in enumerate(target):
        s.add(state[i] == expected)
    if s.check() == sat:
        m = s.model()
        return bytes(m[c].as_long() for c in flag)
```

### Example: reversing a simple byte-substitution
```python
from z3 import *
s = Solver()
flag = [BitVec(f'b{i}', 8) for i in range(40)]
for c in flag:
    s.add(c >= 0x20, c <= 0x7e)

# Suppose the program does: for each byte b, output = (b * 7) ^ 0x42
# Find the input given the output:
target = bytes.fromhex('5b9c8d...')
for i in range(40):
    computed = (flag[i] * 7) ^ 0x42
    s.add(computed == target[i])

if s.check() == sat:
    m = s.model()
    print(bytes(m[c].as_long() for c in flag))
```

## 5. Lattice Attacks (LLL, BKZ, CVP, SVP)

Sage's LLL (`IntegerLattice.LLL`) is the workhorse. CTF lattice problems include:
- **Knapsack** (subset-sum) — recover the small solution with LLL
- **Hidden number problem** — recover a hidden value given modular relations
- **Coppersmith** (small root of a polynomial mod n) — see RSA skill
- **PRNG state recovery** with LLL on linear relations

### Knapsack (subset-sum) with LLL
```python
# Given: target = sum_{i in S} weights[i], find S
# Build lattice:
# [2   0   0   ...  0  weights[0]]
# [0   2   0   ...  0  weights[1]]
# ...
# [0   0   0   ...  2  weights[n-1]]
# [1   1   1   ...  1  target     ]
# LLL → shortest vector contains {0, ±1} entries indicating selection
```

### Hidden Number Problem (HNP)
```python
# Given: high_bits(a * t mod p) for known a, unknown t
# Recover t with LLL
# Standard: Boneh-Venkatesan
```

### CVP (Closest Vector Problem) for "find x such that |A*x - b| is small"
```python
# Sage
A = matrix(ZZ, ...)
b = vector(ZZ, ...)
# Use CVP via Babai or BKZ with embedding
```

## 6. The "Implement the Algorithm" Challenge

Common pattern: the challenge gives you a snippet of Python, says "this is the encryption", and asks you to reverse it.

```python
def encrypt(flag, key):
    out = []
    for i, c in enumerate(flag):
        k = key[i % len(key)]
        out.append(c ^ k)
    return bytes(out)
# To decrypt: same operation (XOR is symmetric)
```

**Solve:** read the encryption, write the decryption, call it.

The harder variant: the algorithm uses an obscure library (`pycryptodome`, `cryptography`, `gmpy2`, `numpy`, `galois`) and the "obvious" decryption is wrong. Read the docs / source. Look for:
- The default mode of operation
- The default padding scheme
- Whether `encrypt` is a one-shot or a stream

## 7. Common CTF Crypto Patterns (multi-layered)

```
flag
  → AES-CBC(key1, iv)  # layer 1
    → base64
      → XOR(key2)
        → base32
          → reversed
            → "AABBCCDDEEFFGGHH..."
```

**Approach:** identify the outermost layer from the data format (base64 ends in `=`, base32 in uppercase + padding, hex in `[0-9a-f]+`, etc.), peel one layer at a time.

## 8. The "Custom Cipher" Challenge (2024+)

When the cipher is custom and the only output is the ciphertext (no oracle):
1. **Look at the structure** — is it Feistel? Substitution-permutation? Sponge?
2. **Brute the key** — if the key is 32 bits, you can brute it
3. **Symbolic / SAT solve** — if the operations are simple, encode the inverse in z3
4. **Differential / linear cryptanalysis** — for AES-like ciphers with 4+ rounds, manual analysis; for fewer rounds, z3 is fast

## Common Pitfalls

- **Forgetting the curve order** — ECC math requires the order of the curve, not just `p`. Get it from the source or compute.
- **Using `E.order()` naively** — for non-prime-order curves, the discrete log is in the subgroup, not the full curve
- **PRNG state recovery needs the right number of outputs** — 624 for MT19937, 32 for LCG, etc.
- **z3 over-constraining** — `s.add(flag[i] == 'a')` for every unknown position; z3 returns `unsat` and you think the solution doesn't exist. Try a less-constrained approach.
- **Lattice with bad basis** — scaling matters; the textbook construction often needs column weighting to make the solution stand out
- **Sage installation** — `sage` is a 5GB download; for CTF, use `sage -python` (the bundled Python) so libraries are available

## Tooling

```bash
# Sage (essential for crypto)
sudo apt install sagemath
# or use the Docker image
docker run -it sagemath/sagemath

# pycryptodome
pip install pycryptodome

# gmpy2
pip install gmpy2

# z3-solver
pip install z3-solver

# randcrack (MT19937)
pip install randcrack

# pycryptodome, cryptography
pip install pycryptodome cryptography

# ecpy (for ECC)
pip install ecpy

# fpylll (for BKZ)
pip install fpylll
```

## One-Liner Cheat Sheet

```python
# ECC weak curve Pohlig-Hellman
sage -c "from sage.all import *; E = EllipticCurve(GF(p), [a,b]); print(E.order())"

# LCG recover
python3 -c "from pwn import *; print('LCG', (s2-s1)*pow(s1-s0, -1, m) % m)"

# MT19937 recover
pip install randcrack
python3 -c "import random, randcrack; rc = randcrack.RandCracker(); [rc.submit(random.getrandbits(32)) for _ in range(624)]; print(rc.predict_getrandbits(32))"

# z3 flag solver
python3 -c "from z3 import *; s = Solver(); x = BitVec('x', 8); s.add((x * 7) ^ 0x42 == 0x99); print(s.check()); print(s.model())"

# Sage LLL
sage -c "M = matrix(ZZ, [[1,2,3],[4,5,6],[7,8,10]]); print(M.LLL())"
```
