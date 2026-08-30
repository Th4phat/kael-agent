---
name: ctf-crypto-rsa
description: RSA attacks for CTF challenges — Wiener's, Coppersmith, common modulus, common factor, Fermat, Boneh-Durfee, partial key exposure, and the high-frequency `n, e, c` workflow
---

# CTF RSA Attacks

The most common CTF crypto challenge. 90% of RSA CTF challenges fall into one of ~15 named attacks. This skill enumerates them, in priority order, with detection signatures and reusable SageMath / Python recipes.

## 0. The CTF RSA Triage (First 60 Seconds)

```python
from Crypto.Util.number import long_to_bytes, bytes_to_long, isPrime, GCD
n, e, c = ...   # from the challenge
print(f"n bits: {n.bit_length()}")
print(f"e = {e}")
print(f"isPrime(n)? {isPrime(n)}")   # if True, n is not factorable directly
# If e is even, suspicious (e must be coprime to phi(n))
# If e is small (3, 5, 17), try Hastad / cube root
# If e is huge (close to n), try Wiener
```

**Single-table cheat sheet (in priority order):**

| Symptom | Attack | Tool |
|---|---|---|
| `e = 3`, message is small | Cube root attack | `gmpy2.iroot(c, 3)` |
| `e = 3`, same message encrypted with 3 different `e` | Hastad's broadcast attack | CRT + cube root |
| `e = 3`, `m^e < n` | m^3 doesn't wrap | Cube root |
| `e` is huge | Wiener's attack (small d) | `wiener.py` / `rsa-wiener` |
| `e*d ≈ n` (continued fraction) | Boneh-Durfee | Sage |
| `e1*e2 - 1` has only small factors | Boneh-Durfee | Sage |
| Two ciphertexts with same `n`, different `e` | Common modulus attack | `CommonModulus` |
| Two `n`s share a prime | Common factor / GCD | `GCD(n1, n2)` |
| `p` and `q` are close | Fermat factoring | `fermat.py` |
| `n = p^k * q` (low bits factor) | Pollard p-1 | `sympy.ntheory` |
| `p - 1` is smooth | Pollard p-1 | `sympy.pollard_pm1` |
| `q - 1` is smooth | Pollard p-1 | `sympy.pollard_pm1` |
| `n` is small enough to factor | ECM / SIQS / YAFU | `factordb.com` (first!), `sage.factor()` |
| `n` is on factordb | Use factordb | HTTP lookup |
| LSB / MSB of `p` known | Coppersmith (stereotyped message) | Sage |
| Half of the bits of `p` known | Coppersmith partial key exposure | Sage |
| `e` and `d` satisfy `e*d ≡ 1 (mod phi)` with leaked relation | Wiener / Boneh-Durfee | Sage |
| `n` is on the form `p*q*r` and `phi` is known | Compute `d` directly | `d = inverse(e, phi)` |
| LSB oracle (server tells you if `c * 2^e mod n` is even/odd) | LSB oracle attack | Iterative |
| Padding oracle (server tells you if decrypted padding is valid) | Padding oracle | Iterative |

## 1. Small Message / Small e — Cube Root

```python
import gmpy2
m, exact = gmpy2.iroot(c, e)   # integer cube root
if exact:
    flag = long_to_bytes(int(m))
```

**Hastad's broadcast attack (3 ciphertexts, same message, e=3):**
```python
# Server: c1 = m^3 mod n1, c2 = m^3 mod n2, c3 = m^3 mod n3
from sympy.ntheory.modular import crt
N = [n1, n2, n3]
C = [c1, c2, c3]
x, _ = crt(N, C)               # CRT: x = m^3 (mod n1*n2*n3)
# x = m^3 exactly, since m^3 < n1*n2*n3
m, _ = gmpy2.iroot(x, 3)
print(long_to_bytes(int(m)))
```

**e=3 with padding (Coppersmith's small root):**
```python
# m = prefix + unknown + suffix, and (m^e) < n
# Use Coppersmith in Sage (see below)
```

## 2. Wiener (small d)

```python
# Continued-fraction attack on e/n to find d when d < n^0.25
def wiener(e, n):
    cf = continued_fraction(e / n)
    convergents = cf.convergents()
    for k, d in convergents:
        if k == 0: continue
        phi = (e*d - 1) // k
        # phi(n) = n - p - q + 1; p + q = n - phi + 1
        s = n - phi + 1
        # p, q are roots of x^2 - s*x + n = 0
        discr = s*s - 4*n
        if discr > 0:
            from math import isqrt
            t = isqrt(discr)
            if t*t == discr:
                return d
    return None

# Modern Python implementation
# https://github.com/pablocelayes/rsa-wiener
```

## 3. Boneh-Durfee (d < n^0.292)

```python
# Sage script
def boneh_durfee(e, n, delta=0.292, m=4):
    # ... requires fpylll or flatter
    pass
# Use existing: https://github.com/mimoo/RSA-and-LLL-attacks
# Practical limit: e/n < 0.5 is favorable
```

## 4. Common Modulus Attack (same n, two e, two c)

```python
# c1 = m^e1 mod n, c2 = m^e2 mod n, gcd(e1, e2) = 1
from math import gcd
def common_modulus(c1, c2, e1, e2, n):
    g = gcd(e1, e2)
    if g != 1: return None
    # Find s, t such that s*e1 + t*e2 = 1
    from sympy import gcdex
    s, t, _ = gcdex(e1, e2)
    if s < 0:
        c1 = pow(c1, -1, n)
        s = -s
    if t < 0:
        c2 = pow(c2, -1, n)
        t = -t
    return (pow(c1, int(s), n) * pow(c2, int(t), n)) % n
m = common_modulus(c1, c2, e1, e2, n)
print(long_to_bytes(m))
```

## 5. Common Factor (GCD two n's)

```python
from math import gcd
# Given (n1, e1, c1) and (n2, e2, c2) — if they share a prime, gcd is the shared p
p = gcd(n1, n2)
if p != 1:
    q1 = n1 // p
    q2 = n2 // p
    phi1 = (p-1) * (q1-1)
    d1 = pow(e1, -1, phi1)
    print(long_to_bytes(pow(c1, d1, n1)))
```

## 6. Fermat (p and q are close)

```python
# p, q are within ~2^20 of sqrt(n)
import gmpy2
def fermat(n, max_iter=1000000):
    a = gmpy2.isqrt(n) + 1
    for _ in range(max_iter):
        b2 = a*a - n
        if b2 >= 0:
            b = gmpy2.isqrt(b2)
            if b*b == b2:
                return int(a-b), int(a+b)
        a += 1
    return None
```

## 7. Pollard p-1 (p-1 or q-1 is smooth)

```python
# If p-1 = 2 * 3 * 5 * 7 * 11 * ... (smooth, all small factors)
def pollard_pm1(n, B=2**20):
    a = 2
    for j in range(2, B):
        a = pow(a, j, n)
        d = gcd(a - 1, n)
        if 1 < d < n:
            return d
    return None
# Or: sympy.ntheory.factor_.pollard_pm1(n, B=2**20)
```

## 8. Williams p+1 (p+1 is smooth)

```python
# Similar to p-1 but uses Lucas sequences
# Use: sympy.ntheory.factor_.pollard_pm1(n, B=2**20) — it tries p-1 and p+1
```

## 9. Coppersmith (partial key / stereotyped message)

Sage has Coppersmith built in. The high-value cases:

### Case A: `m = prefix + unknown + suffix`, `e*|unknown| < n^(1/e)`
```python
# Sage
def small_roots_coppersmith(prefix, suffix, n, e, unknown_len, m_bits=None):
    P.<x> = PolynomialRing(Zmod(n))
    # m = prefix * 256^unk + x * 256^suffix_len + suffix
    M = prefix * 256^(unknown_len + len(suffix)) + x * 256^len(suffix) + suffix
    # M^e ≡ c (mod n)
    f = (M^e - c)
    roots = f.small_roots(X=2^(8*unknown_len) - 1, beta=1.0, epsilon=0.03)
    return roots

roots = small_roots_coppersmith(b'CTF{', b'}', n, e, 30)
# Returns the unknown bytes
```

### Case B: Half of `p` is known
```python
# If you know p mod 2^k or similar
# Sage Coppersmith with the known bits as the high bits of a partial variable
```

## 10. LSB Oracle (parity oracle)

When the server tells you the LSB of `m*2^e mod n` (i.e. `(m*2^e) mod n` is even/odd), recover `m` bit by bit:

```python
def lsb_oracle_attack(n, e, c, oracle, max_bits=2048):
    # oracle(c_prime) returns 0 if (c_prime^d mod n) is even, 1 if odd
    multipliers = []
    for bit in range(max_bits):
        c = (c * pow(2, e, n)) % n
        multipliers.append(2)
        if oracle(c) == 0:
            # m is in lower half
            pass
        else:
            # m is in upper half
            pass
        # bisect: maintain bounds [lo, hi] in rationals
    return m
# The full algorithm: maintain fractions (lo, hi) of the form a/b, halve each step
```

## 11. Padding Oracle (Bleichenbacher)

For RSAES-PKCS1-v1_5: server tells you if the decrypted padding is valid. Recover `m`:

```python
def bleichenbacher(n, e, c, oracle, max_steps=10000):
    # m = s^e * c mod n, where s is a chosen multiplier
    # Find s such that m*s mod n starts with 0x0002
    # ...
    # Standard implementation: ~1000 oracle calls
    pass
# Use existing: https://github.com/mimoo/RSA-and-LLL-attacks/blob/master/bleichenbacher.py
```

## 12. Leaked `d` or `dp`, `dq`

If `dp = d mod (p-1)` is leaked, and `e*dp - 1` has a small factor:
```python
# Use Coppersmith to find p
def recover_p_from_dp(e, dp, n, B=2**24):
    # p = gcd(e*dp - 1, n)  (when e*dp - 1 is divisible by p-1)
    for k in range(1, B):
        if (e*dp - 1) % k == 0:
            p_candidate = gcd((e*dp - 1) // k + 1, n)
            if 1 < p_candidate < n:
                return p_candidate
    return None
```

## 13. factordb.com (always try first!)

```python
# curl 'http://factordb.com/api?query=1234567890...'
# returns: {"status":"FF","factors":[...]}  # FF = fully factored
import requests
r = requests.get(f"http://factordb.com/api?query={n}").json()
if r.get('status') == 'FF':
    factors = r['factors']
    p, q = int(factors[0][0]), int(factors[1][0])
    phi = (p-1) * (q-1)
    d = pow(e, -1, phi)
    print(long_to_bytes(pow(c, d, n)))
```

**Always check factordb first.** Many CTF challenges reuse a known-weak `n`.

## 14. CTF-Specific Traps

- **n is a perfect power** — `i = iroot(n, k)[0]`; if i**k == n, factor further
- **n is the product of many small primes** — `factor(n)` (sympy or sage)
- **e = 1** — `c = m mod n` → already plaintext
- **e and phi(n) are not coprime** — `gcd(e, phi) > 1`; the message may have multiple roots or no root
- **CRT components leak** — `(dp, dq, qinv, p, q)` partial key; reconstruct `d`
- **n is on the wrong modulus** — read the challenge carefully; sometimes they give a different `n` for encryption and a different `n` for verification
- **`d` is leaked** — `d = e^(-1) mod phi(n)`; if `phi` is recoverable (e.g. from d, e), factor n
- **`phi(n)` is leaked** — `d = pow(e, -1, phi)`; decrypt

## Tooling

```bash
# Sage (most powerful)
sage script.sage
# or
sage -python script.py

# pycryptodome
pip install pycryptodome

# gmpy2
pip install gmpy2

# sympy (for pollard_pm1, factorint)
pip install sympy

# pwntools' number theory
python3 -c "from pwn import *; print(GCD(15, 25))"

# factordb (CLI)
pip install factordb-pycli
```

## CTF Solver Skeleton

```python
from Crypto.Util.number import long_to_bytes, bytes_to_long
from math import gcd, isqrt
import gmpy2

n, e, c = ...   # from challenge

# 1. factordb first
import requests
r = requests.get(f"http://factordb.com/api?query={n}").json()
if r.get('status') == 'FF':
    p, q = int(r['factors'][0][0]), int(r['factors'][1][0])
    phi = (p-1) * (q-1)
    d = pow(e, -1, phi)
    print(long_to_bytes(pow(c, d, n)))
    exit()

# 2. Small e?
if e == 3:
    m, _ = gmpy2.iroot(c, 3)
    if _:
        print(long_to_bytes(int(m)))
        exit()

# 3. Wiener
# (use the function above)

# 4. Common modulus, common factor, Fermat, Pollard p-1, Coppersmith, ...
# Try in order of likely success
```
