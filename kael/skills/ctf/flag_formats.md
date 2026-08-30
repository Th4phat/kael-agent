---
name: ctf-flag-formats
description: CTF flag format variety — prefixes by platform, exotic shapes (no-braces, URL, UUID, base64), how to extract the format from the challenge description, and how to pass it to kael tools
---

# CTF Flag Formats

A "flag" in CTF is whatever the challenge author decided it is. The default mental model (`flag{...}`) only covers ~40% of real CTFs. This skill enumerates the families, shows how to extract the expected format from the challenge text, and tells you how to feed that into the kael tools so they don't miss the real flag.

## 1. The Generic Family (the obvious case)

```regex
^flag\{.+\}$
^FLAG\{.+\}$
^ctf\{.+\}$
^CTF\{.+\}$
```

- Most public CTFs use one of these
- Length of the inside is usually 8-64 chars
- Lowercase alphanumerics + underscores + occasional `!@#`

## 2. Platform-Specific Prefixes

| Platform | Format | Example |
|---|---|---|
| picoCTF | `picoCTF{...}` | `picoCTF{s4m3_d1ff3r3nt_4ddr3ss}` |
| HackTheBox | `HTB{...}` | `HTB{f4k3_fl4g_f0r_t3st1ng}` |
| TryHackMe | `THM{...}` | `THM{p1v0t_p1v0t_p1v0t}` |
| picoCTF | `picoCTF{...}` | (above) |
| DASCTF | `DASCTF{...}` | `DASCTF{h3x_str34m}` |
| TUCTF | `TUCTF{...}` | `TUCTF{welcome_to_tuc}` |
| 0ops | `0ops{...}` | `0ops{r3v3rse_th1s}` |
| n1ctf | `n1ctf{...}` | `n1ctf{advanced_pwn}` |
| SUCTF | `SUCTF{...}` | `SUCTF{pwn_or_re}` |
| RCTF | `RCTF{...}` | `RCTF{reverse_2019}` |
| BJDCTF | `BJDCTF{...}` | `BJDCTF{simple_rsa}` |
| H&NCTF | `H&NCTF{...}` | `H&NCTF{leet_or_n00b}` |
| LitCTF | `LitCTF{...}` | `LitCTF{flag_here}` |
| NewStarCTF | `NewStarCTF{...}` | `NewStarCTF{week1_pwn}` |
| HFCTF | `HFCTF{...}` | `HFCTF{crypto_or_pwn}` |
| D3CTF | `D3CTF{...}` | `D3CTF{hard_flag}` |
| GYCTF | `GYCTF{...}` | `GYCTF{ezzz}` |
| GKCTF | `GKCTF{...}` | `GKCTF{reverse_2020}` |
| BaseCTF | `BaseCTF{...}` | `BaseCTF{newbie}` |
| CCTF | `CCTF{...}` | `CCTF{crypto_2018}` |
| VNCTF | `VNCTF{...}` | `VNCTF{misc_or_pwn}` |
| DuckyCTF | `DuckyCTF{...}` | `DuckyCTF{flag}` |
| dice | `dice{...}` | `dice{go_ducks}` |
| BuckeyeCTF | `buckeye{...}` | `buckeye{flag_here}` |
| pwn.college | `pwn.college{...}` | `pwn.college{shellcode}` |
| SEKAI | `SEKAI{...}` | `SEKAI{ctf_2023}` |
| idek | `idek{...}` | `idek{some_text}` |
| crew | `crew{...}` | `crew{pwn_2024}` |
| GreyCTF | `grey{...}` or `Grey{...}` | `grey{advanced}` |
| wargames | `wgmy{...}` | `wgmy{...}` |

The platform-specific list is curated from real CTFs 2017-2024. There are 30+ active CTF platforms; if you encounter a new one, add it to the table.

## 3. Exotic — No Braces

```regex
^flag_[A-Za-z0-9_\-]{8,}$
^FLAG_[A-Za-z0-9_\-]{8,}$
^FLAG: ?[A-Za-z0-9_\-]{8,}$
^flag is: ?[A-Za-z0-9_\-]{8,}$
^The flag is: ?[A-Za-z0-9_\-]{8,}$
```

Seen in:
- Beginner tutorials (some use `flag_xxxxxxxx`)
- OSINT challenges ("The flag is: paris_france_2024")
- Bash-themed challenges (FLAG: bash_is_fun)

## 4. Exotic — URL

```regex
^https?://[^\s]+/flag/[A-Za-z0-9_\-]+$
^https?://[^\s]+/[A-Za-z0-9_\-]{16,}$
```

Seen in:
- Web challenges where the flag is the response of an exfil URL
- OSINT challenges (the flag is a hidden URL on a target)
- Misc challenges where the flag is "submit this URL to the bot"

## 5. Exotic — UUID / Hex

```regex
^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$   # standard UUID
^[0-9a-f]{32}$                                                    # UUID without dashes
```

Seen in:
- Web challenges (the flag is generated server-side per team as a UUID)
- Web challenges that use cookies (the flag is a session ID, often UUID-shaped)
- Some modern pwn challenges (each connection gets a UUID token)

## 6. Exotic — Base64

```regex
^[A-Za-z0-9+/]{16,}={0,2}$
```

Some challenges don't add a prefix — the flag is just a 16+ char base64 string.

## 7. Exotic — Multi-Token (no clear delimiter)

```regex
^[a-z]+_[a-z]+_[a-z]+$      # snake_case word_word_word
^[A-Z][a-z]+[A-Z][a-z]+...$ # CamelCase
```

Seen in OSINT and trivia challenges.

## 8. "The Flag Is the Answer" Pattern

Some challenges have no flag at all — the flag is the answer to a question:

- "What city is this?" → `paris` (or `Paris, France`, or `paris_france`)
- "What's the username?" → `alice42`
- "What's the CVE?" → `CVE-2024-1234`
- "What's the latitude?" → `48.8584`
- "What's the bitcoin address?" → `1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa`

The flag is then submitted to the CTF platform as **the answer to a question** wrapped in the platform's standard format. Read the challenge text carefully — the description is the spec.

## 9. Reading the Format from the Challenge Description

The format is almost always stated explicitly. Look for patterns like:

```
"The flag format is: flag{...}"
"Submit the answer as DASCTF{your_answer}"
"Flag: H&NCTF{...}"
"Wrap your answer in picoCTF{} and submit"
"Answer is a 16-character hex string, e.g. 1a2b3c4d5e6f7890"
```

Extract the regex and pass it to kael tools:

```python
# Example: challenge says "Submit as flag{a1b2c3}"
expected_format = r"^flag\{[a-f0-9]{6}\}$"
```

## 10. How to Pass the Format to kael Tools

All the ctf tools in `kael/tools/ctf_tools/` accept an `expected_format` parameter:

```python
# cyberchef_decode
result = await cyberchef_decode(ctx, input=encoded_blob, expected_format=r"^DASCTF\{.+\}$")

# xor_bruteforce
result = await xor_bruteforce(ctx, data=ciphertext, expected_format=r"^n1ctf\{.+\}$")

# rsa_attack_detect
result = await rsa_attack_detect(
    ctx, n=n, e=e, c=c,
    expected_format=r"^picoCTF\{.+\}$"
)
```

When `expected_format` is set, the tool bypasses the built-in format library and uses only that regex. This is the **recommended** workflow when the challenge has a non-standard prefix.

## 11. The "Detect and Adapt" Workflow

When the challenge description is unclear or missing:

1. **Run the tool with no `expected_format`** — the built-in library catches the common cases
2. **If the tool returns a candidate that doesn't match any known prefix** — the candidate might be wrong, OR the prefix is exotic
3. **Re-run with a custom `expected_format`** matching the loose pattern you see (e.g. `r"^[A-Z]{2,10}\{.+\}$"` to match any prefixed flag)
4. **If the candidate is a UUID / URL / snake_case string** — it's likely the answer in non-brace form; submit it as-is or wrapped

## 12. Loose Detection (the "always-on" fallback)

If you have no idea what the flag looks like, use a **loose regex** that matches any plausible flag shape:

```python
# Loose: any alphanumeric prefix followed by a brace
loose_format = r"^[A-Za-z0-9_]+\{.+\}$"
# Even looser: any prefix of 2+ uppercase letters followed by braces
loose_format = r"^[A-Z][A-Z0-9_]*\{.+\}$"
# Brace-free: any long string with mixed case / numbers
loose_format = r"^[A-Za-z0-9_\-]{8,}$"
```

This catches 90% of cases. The 10% it misses are answered by reading the challenge text.

## 13. Where Flags Hide in Output

A "real" CTF finding is more than a candidate — it's the **flag string in the agent's output**. The flag can be:

- In a server response body (`flag{...}` somewhere in the HTML / JSON)
- In a file the agent read (`grep -r 'flag{' /workspace/`)
- In an environment variable (`env | grep -i flag`)
- In a database row (`SELECT flag FROM flags`)
- In a DNS TXT record (`dig TXT flag.target.com`)
- In a tarball inside a tarball inside a tarball

Always run a final pass with `strings`, `grep`, `tshark`, and `binwalk` to make sure the flag isn't hidden in a place the tool didn't think to look.

## 14. The "Submit to Platform" Step

Once you have the flag string, submit it to the CTF platform. Most platforms:

- Take a single string (no wrapper) — strip the prefix if the platform adds it
- Or take the full prefix-wrapped string
- Are case-sensitive
- Have a 30-second rate limit per submission

Always read the platform's submission rules before bulk-submitting candidates.

## Common Pitfalls

- **The flag has a different prefix than the platform's default** — the platform might use `picoCTF{}` but the challenge wraps it in a custom prefix
- **The flag is in a non-string form** — base64'd, gzipped, XOR'd, etc.
- **The flag is the answer to a question, not a fixed string** — re-read the description
- **Multiple "flag-like" strings in the output** — the platform's submission rules will accept only one; the right one is usually the one with the right prefix
- **The agent found a writeup and pasted the flag** — never copy a flag from a writeup; always re-derive it (CTF rules often require this; some platforms track past winners and refuse identical submissions)

## Quick Reference: Format → Regex

| Format | Regex |
|---|---|
| Generic | `r"^flag\{.+\}$"` |
| picoCTF | `r"^picoCTF\{.+\}$"` |
| HTB | `r"^HTB\{.+\}$"` |
| Loose (any prefix) | `r"^[A-Za-z0-9_]+\{.+\}$"` |
| UUID | `r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"` |
| URL | `r"^https?://.+$"` |
| Snake case | `r"^[a-z]+(_[a-z]+)+$"` |
| Brace-free | `r"^[A-Za-z0-9_\-]{8,}$"` |
