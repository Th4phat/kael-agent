"""CTF (Capture-The-Flag) tools for kael agents.

This package exposes a curated set of helper tools that wrap common CTF
challenge operations: encoding chain decoding, RSA attack dispatch, XOR
brute-forcing, pwntools template generation, binary protection checks,
and format-string offset discovery. Each tool is a sandbox-friendly
``@function_tool`` and is intended to be loaded by agents operating in
the dedicated ``ctf`` scan mode (see ``kael.agents.factory``).

These tools do NOT replace the sandbox's ``exec_command`` tool — the
agent still invokes any CLI (gdb, binwalk, vol, tshark, etc.) through
``exec_command``. The tools here exist to encapsulate the
domain-specific logic that would otherwise be 50+ lines of Python in
every agent run.
"""

from .binary_checksec import binary_checksec
from .cyberchef_decode import cyberchef_decode
from .format_string_offset import format_string_offset
from .pwn_template import pwn_template
from .rsa_attack_detect import rsa_attack_detect
from .xor_bruteforce import xor_bruteforce


ALL_CTF_TOOLS = [
    cyberchef_decode,
    xor_bruteforce,
    rsa_attack_detect,
    pwn_template,
    binary_checksec,
    format_string_offset,
]


__all__ = [
    "ALL_CTF_TOOLS",
    "binary_checksec",
    "cyberchef_decode",
    "format_string_offset",
    "pwn_template",
    "rsa_attack_detect",
    "xor_bruteforce",
]
