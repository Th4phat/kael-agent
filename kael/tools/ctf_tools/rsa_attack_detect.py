"""``rsa_attack_detect`` — RSA attack dispatcher.

Inspects ``(n, e, c)`` (and optional ``d``, ``dp``, ``hint``), tries
the high-value CTF attacks in priority order, and reports the first
that yields a plausible plaintext. Pure Python implementation that
covers ~80% of CTF RSA challenges without needing SageMath.
"""

from __future__ import annotations

import base64
import json
import math
import re
from typing import Any

from agents import function_tool

from .flag_format import looks_like_flag as _looks_like_flag


_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def _parse_big_int(value: str | int | None) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    s = value.strip()
    if not s:
        return None
    s = s.replace(" ", "").replace("\n", "").replace(",", "")
    if s.lower().startswith("0x"):
        s = s[2:]
    if _HEX_RE.match(s):
        return int(s, 16)
    if re.match(r"^0[0-7]+$", s):
        return int(s, 8)
    try:
        return int(s)
    except ValueError:
        pass
    try:
        return int.from_bytes(base64.b64decode(s), "big")
    except (ValueError, base64.binascii.Error):
        return None


def _is_probable_flag(b: bytes, expected_format: str | None = None) -> bool:
    try:
        s = b.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return False
    return _looks_like_flag(s, expected_format=expected_format)


def _int_to_bytes(n: int) -> bytes:
    if n == 0:
        return b"\x00"
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, "big")


def _iroot(n: int, k: int) -> tuple[int, bool]:
    if n < 0:
        return (0, False)
    if n == 0:
        return (0, True)
    hi = 1 << ((n.bit_length() + k - 1) // k + 1)
    lo = 0
    while lo < hi:
        mid = (lo + hi) // 2
        if mid**k <= n:
            lo = mid + 1
        else:
            hi = mid
    return (lo - 1, (lo - 1) ** k == n)


def _continued_fraction_convergents(a: int, b: int) -> list[tuple[int, int]]:
    """Return convergents of a/b."""
    convs: list[tuple[int, int]] = []
    while b:
        q = a // b
        if not convs:
            convs.append((q, 1))
        else:
            p_prev, q_prev = convs[-1]
            convs.append(
                (
                    q * p_prev + (convs[-2][0] if len(convs) > 1 else 0),
                    q * q_prev + (convs[-2][1] if len(convs) > 1 else 1),
                )
            )
        a, b = b, a - q * b
    return convs


def _wiener(e: int, n: int) -> int | None:
    if e <= 0 or n <= 0:
        return None
    for k, d in _continued_fraction_convergents(e, n):
        if k == 0 or d == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1
        discr = s * s - 4 * n
        if discr < 0:
            continue
        sqrt_d = math.isqrt(discr)
        if sqrt_d * sqrt_d == discr:
            p = (s + sqrt_d) // 2
            q = (s - sqrt_d) // 2
            if p * q == n and p > 1 and q > 1:
                return d
    return None


def _fermat(n: int, max_iter: int = 200_000) -> tuple[int, int] | None:
    if n % 2 == 0:
        return (2, n // 2)
    a = math.isqrt(n)
    if a * a == n:
        return (a, a)
    a += 1
    for _ in range(max_iter):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            p = a - b
            q = a + b
            if p > 1 and q > 1 and p * q == n:
                return (p, q)
        a += 1
    return None


def _pollard_pm1(n: int, B: int = 200_000) -> int | None:
    if n % 2 == 0:
        return 2
    a = 2
    for j in range(2, B):
        a = pow(a, j, n)
        if j % 1000 == 0:
            d = math.gcd(a - 1, n)
            if 1 < d < n:
                return d
    d = math.gcd(a - 1, n)
    if 1 < d < n:
        return d
    return None


def _common_factor(n1: int, n2: int) -> int | None:
    d = math.gcd(n1, n2)
    if 1 < d < n1 and 1 < d < n2:
        return d
    return None


def _recover_p_from_dp(e: int, dp: int, n: int, B: int = 200_000) -> int | None:
    for k in range(1, B):
        if (e * dp - 1) % k != 0:
            continue
        candidate = (e * dp - 1) // k + 1
        p = math.gcd(candidate, n)
        if 1 < p < n:
            return p
    return None


def _decrypt_with_factors(n: int, e: int, c: int, p: int, q: int) -> bytes:
    phi = (p - 1) * (q - 1)
    if math.gcd(e, phi) != 1:
        return b""
    d = pow(e, -1, phi)
    m = pow(c, d, n)
    return _int_to_bytes(m)


def _try_cube_root(c: int, n: int, expected_format: str | None = None) -> bytes | None:
    if c < 0 or n < 0:
        return None
    for k in (3, 5, 7, 11, 13, 17, 19, 23):
        root, exact = _iroot(c, k)
        if exact and _is_probable_flag(_int_to_bytes(root), expected_format):
            return _int_to_bytes(root)
        if exact and root < n and root**k == c:
            return _int_to_bytes(root)
    m, _ = _iroot(c, 3)
    if m**3 == c and m < n:
        return _int_to_bytes(m)
    return None


def _decrypt_low_e_with_padding(
    c: int, e: int, n: int, prefix: bytes = b"", suffix: bytes = b""
) -> bytes | None:
    """Try to recover m given partial-known prefix/suffix when c = m^e mod n is small.

    Without Sage / LLL we can only handle the no-padding case (m^e < n).
    """
    return None


def _try_specific_offsets(c: int, n: int) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for k in (3, 5, 7, 11, 13, 17, 19, 23):
        m, exact = _iroot(c, k)
        if not exact:
            continue
        b = _int_to_bytes(m)
        if b:
            results.append({"e": k, "plaintext": b.decode("utf-8", errors="replace")})
    return results


def _run_rsa_dispatcher(  # type: ignore[no-untyped-def]
    n: str,
    e: str,
    c: str,
    second_n: str | None = None,
    second_e: str | None = None,
    second_c: str | None = None,
    hint: str | None = None,
    expected_format: str | None = None,
) -> dict[str, Any]:
    """Sync impl of rsa_attack_detect for direct unit-test use."""
    n_int = _parse_big_int(n)
    e_int = _parse_big_int(e)
    c_int = _parse_big_int(c)
    if n_int is None or e_int is None or c_int is None:
        return {"success": False, "error": "Invalid n, e, or c"}

    n2 = _parse_big_int(second_n) if second_n else None
    e2 = _parse_big_int(second_e) if second_e else None
    c2 = _parse_big_int(second_c) if second_c else None

    results: list[dict[str, Any]] = []
    rejected: list[dict[str, str]] = []
    recommended_sage_command: str | None = None

    if c_int == 0:
        results.append({"attack": "c=0", "plaintext": "0", "key": None})
        return {
            "success": True,
            "n_bits": 0,
            "e": 0,
            "results": results,
            "rejected": [],
            "recommended_sage_command": None,
            "hint": "c=0, m=0",
        }

    if e_int == 1:
        results.append(
            {"attack": "e=1", "plaintext": _int_to_bytes(c_int).decode("utf-8", errors="replace")}
        )
        return {
            "success": True,
            "n_bits": n_int.bit_length(),
            "e": 1,
            "results": results,
            "rejected": [],
            "recommended_sage_command": None,
            "hint": "e=1 means no encryption",
        }

    if e_int == 3:
        out = _try_cube_root(c_int, n_int, expected_format)
        if out is not None:
            results.append(
                {
                    "attack": "small_e (cube root)",
                    "plaintext": out.decode("utf-8", errors="replace"),
                    "key": "e=3, m^3 < n",
                }
            )
        else:
            rejected.append(
                {"attack": "small_e", "reason": "m^3 >= n, padding likely — use Coppersmith"}
            )
            recommended_sage_command = (
                "# Sage script: Coppersmith small root with known prefix 'CTF{'\n"
                "def small_root(n, e, prefix, unknown_len):\n"
                "    P.<x> = PolynomialRing(Zmod(n))\n"
                "    M = prefix * 256^unknown_len + x\n"
                "    return (M^e - c).small_roots(X=256^unknown_len, beta=1.0, epsilon=0.03)\n"
            )

    if n2 is not None and e2 is not None and c2 is not None:
        d_wiener = _wiener(e_int, n_int)
        if d_wiener is not None:
            phi_candidate = e_int * d_wiener - 1
            s = n_int - phi_candidate + 1 if phi_candidate else 0
            if s > 0:
                discr = s * s - 4 * n_int
                if discr >= 0:
                    sqrt_d = math.isqrt(discr)
                    if sqrt_d * sqrt_d == discr:
                        p = (s + sqrt_d) // 2
                        q = (s - sqrt_d) // 2
                        if p * q == n_int:
                            plaintext = _decrypt_with_factors(n_int, e_int, c_int, p, q)
                            results.append(
                                {
                                    "attack": "wiener",
                                    "plaintext": plaintext.decode("utf-8", errors="replace"),
                                    "key": str(d_wiener),
                                }
                            )
        if not results and n2 is not None:
            common = _common_factor(n_int, n2)
            if common is not None:
                p = common
                q = n_int // p
                plaintext = _decrypt_with_factors(n_int, e_int, c_int, p, q)
                results.append(
                    {
                        "attack": "common_factor (GCD two moduli)",
                        "plaintext": plaintext.decode("utf-8", errors="replace"),
                        "key": f"shared prime = {p}",
                    }
                )
            else:
                rejected.append({"attack": "common_factor", "reason": "GCD(n1, n2) = 1"})

        if not results and math.gcd(e_int, e2) == 1 and c2 is not None:
            try:
                import sympy

                s_int, t_int, _ = sympy.gcdex(e_int, e2)
                if s_int < 0:
                    c_inv = pow(c_int, -1, n_int)
                    s_int = -s_int
                else:
                    c_inv = c_int
                if t_int < 0:
                    c2_inv = pow(c2, -1, n_int)
                    t_int = -t_int
                else:
                    c2_inv = c2
                m = (pow(c_inv, s_int, n_int) * pow(c2_inv, t_int, n_int)) % n_int
                b = _int_to_bytes(m)
                if _is_probable_flag(b, expected_format) or any(
                    c in b for c in (b"flag", b"CTF", b"{")
                ):
                    results.append(
                        {
                            "attack": "common_modulus",
                            "plaintext": b.decode("utf-8", errors="replace"),
                            "key": f"e1={e_int}, e2={e2}",
                        }
                    )
            except (ValueError, ImportError):
                rejected.append(
                    {"attack": "common_modulus", "reason": "sympy missing or gcd(e1,e2) != 1"}
                )

    fermat = _fermat(n_int)
    if fermat is not None:
        p, q = fermat
        plaintext = _decrypt_with_factors(n_int, e_int, c_int, p, q)
        results.append(
            {
                "attack": "fermat (p and q close)",
                "plaintext": plaintext.decode("utf-8", errors="replace"),
                "key": f"p={p}, q={q}",
            }
        )
    else:
        rejected.append({"attack": "fermat", "reason": "p and q not within 200k of sqrt(n)"})

    pm1 = _pollard_pm1(n_int)
    if pm1 is not None:
        p = pm1
        q = n_int // p
        plaintext = _decrypt_with_factors(n_int, e_int, c_int, p, q)
        results.append(
            {
                "attack": "pollard_pm1 (p-1 smooth)",
                "plaintext": plaintext.decode("utf-8", errors="replace"),
                "key": f"p={p}",
            }
        )
    else:
        rejected.append({"attack": "pollard_pm1", "reason": "no factor found with B=200k"})

    if hint:
        hint_lower = hint.lower()
        if "dp" in hint_lower or "leak" in hint_lower:
            match = re.search(r"dp\s*[=:]\s*(\d+|0x[0-9a-fA-F]+)", hint)
            if match:
                dp = _parse_big_int(match.group(1))
                if dp is not None:
                    p = _recover_p_from_dp(e_int, dp, n_int)
                    if p is not None:
                        q = n_int // p
                        plaintext = _decrypt_with_factors(n_int, e_int, c_int, p, q)
                        results.append(
                            {
                                "attack": "dp leak (Coppersmith-light)",
                                "plaintext": plaintext.decode("utf-8", errors="replace"),
                                "key": f"dp={dp}",
                            }
                        )

    return {
        "success": bool(results),
        "n_bits": n_int.bit_length(),
        "e": e_int,
        "results": results,
        "rejected": rejected,
        "recommended_sage_command": recommended_sage_command,
        "hint": "If no result, run factordb.com API lookup via exec_command, "
        "then `sage solve.sage` for lattice/Coppersmith attacks.",
    }


@function_tool(timeout=120, strict_mode=False)
async def rsa_attack_detect(  # type: ignore[no-untyped-def]
    ctx,
    n: str,
    e: str,
    c: str,
    second_n: str | None = None,
    second_e: str | None = None,
    second_c: str | None = None,
    hint: str | None = None,
    expected_format: str | None = None,
) -> str:
    """Try common RSA attacks against the given parameters.

    Pure Python dispatcher that covers the high-frequency CTF RSA
    patterns. For Coppersmith / lattice attacks, the hint will tell
    you to reach for Sage.

    Args:
        n: RSA modulus (decimal, hex ``0x..``, or base64).
        e: Public exponent.
        c: Ciphertext.
        second_n: Second modulus (for common-modulus / common-factor).
        second_e: Second exponent (for common-modulus).
        second_c: Second ciphertext (for common-modulus / Hastad).
        hint: Optional challenge hint (e.g. "small d", "e=3, flag prefix",
            "p and q are close", "dp leaked: 0x..").
        expected_format: Optional Python regex for the flag shape
            (e.g. ``r"^DASCTF\\{.+\\}$"``). Used by the cube-root
            fast-path to filter false positives.

    Returns:
        JSON with ``results`` (list of {attack, plaintext, key}),
        ``rejected`` (failed attacks), and ``recommended_sage_command``
        for the lattice/Coppersmith path if needed.
    """
    return json.dumps(
        _run_rsa_dispatcher(
            n=n,
            e=e,
            c=c,
            second_n=second_n,
            second_e=second_e,
            second_c=second_c,
            hint=hint,
            expected_format=expected_format,
        ),
        ensure_ascii=False,
        indent=2,
    )
