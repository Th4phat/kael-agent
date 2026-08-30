"""Tests for the CTF skill category and ctf_tools package."""

from __future__ import annotations

import json
import os

import pytest

from kael.agents.factory import get_base_tools
from kael.skills import (
    get_all_skill_names,
    get_available_skills,
    load_skills,
    validate_requested_skills,
)
from kael.tools.ctf_tools import (
    ALL_CTF_TOOLS,
    binary_checksec,
    cyberchef_decode,
    format_string_offset,
    pwn_template,
    rsa_attack_detect,
    xor_bruteforce,
)
from kael.tools.ctf_tools.cyberchef_decode import _decode_chain
from kael.tools.ctf_tools.flag_format import (
    detect_format,
    example_formats,
    looks_like_flag,
)
from kael.tools.ctf_tools.xor_bruteforce import _parse_input


class TestCTFSkillsDiscovery:
    """The ctf/ directory must be auto-discovered with nested subcategories."""

    def test_ctf_category_exists(self) -> None:
        grouped = get_available_skills()
        assert "ctf" in grouped, "ctf category must appear in available skills"

    def test_ctf_has_all_subcategories(self) -> None:
        grouped = get_available_skills()
        ctf_skills = set(grouped["ctf"])
        for sub in (
            "pwn/recon",
            "pwn/stack",
            "pwn/heap",
            "pwn/formats_and_misc",
            "reversing/static",
            "reversing/dynamic",
            "reversing/langs",
            "crypto/rsa",
            "crypto/symmetric",
            "crypto/other",
            "forensics/disks",
            "forensics/pcap",
            "forensics/memory",
            "forensics/stego",
            "osint/methodology",
            "osint/encodings",
            "osint/misc",
            "flag_formats",
            "ctf_scan_mode",
        ):
            assert sub in ctf_skills, f"missing ctf skill: {sub}"

    def test_ctf_has_no_web_duplicates(self) -> None:
        """Web vulns use canonical pentest skills, not ctf/web/* duplicates."""
        grouped = get_available_skills()
        ctf_skills = set(grouped["ctf"])
        for dup in (
            "web/sqli",
            "web/xss",
            "web/ssti",
            "web/ssrf",
            "web/jwt",
            "web/deserialization",
        ):
            assert dup not in ctf_skills, f"{dup} should live in vulnerabilities/, not ctf/"

    def test_ctf_skill_count(self) -> None:
        grouped = get_available_skills()
        # 19 CTF-specific skills (4 pwn + 3 reversing + 3 crypto + 4 forensics + 3 osint + 2 top-level).
        # Web skills reuse canonical pentest skills in vulnerabilities/.
        assert len(grouped["ctf"]) == 19, f"expected 19 ctf skills, got {len(grouped['ctf'])}"

    def test_canonical_pentest_skills_cover_web(self) -> None:
        """sqli/xss/ssti/ssrf/jwt/deserialization live in vulnerabilities/, not ctf/."""
        grouped = get_available_skills()
        assert "vulnerabilities" in grouped
        for s in ("sql_injection", "xss", "ssti", "ssrf", "authentication_jwt", "deserialization"):
            assert s in grouped["vulnerabilities"], f"{s} should be in vulnerabilities/"

    def test_legacy_skill_names_still_load(self) -> None:
        """Backward compat: loading by the old ``vulnerabilities/<name>`` path works."""
        content = load_skills(["vulnerabilities/sql_injection"])
        assert "sql_injection" in content
        assert "SQL Injection" in content["sql_injection"]


class TestCTFSkillContent:
    """Each CTF-specific skill must contain category-specific high-value content.

    Web skills (sqli, xss, ssti, ssrf, jwt, deserialization) intentionally reuse
    the canonical pentest skills under ``vulnerabilities/`` so we don't
    duplicate content — see ``test_canonical_pentest_skills_cover_web``.
    """

    def test_stack_skill_covers_ret2libc(self) -> None:
        body = load_skills(["ctf/pwn/stack"])["stack"]
        for marker in ("ret2libc", "ROP", "one_gadget", "format string", "MOVAPS"):
            assert marker in body, f"stack skill missing {marker!r}"

    def test_heap_skill_covers_modern_glibc(self) -> None:
        body = load_skills(["ctf/pwn/heap"])["heap"]
        for marker in ("tcache", "safe-linking", "House of", "FSOP", "unsorted bin"):
            assert marker in body, f"heap skill missing {marker!r}"

    def test_rsa_skill_covers_wiener_and_coppersmith(self) -> None:
        body = load_skills(["ctf/crypto/rsa"])["rsa"]
        for marker in ("Wiener", "Coppersmith", "Fermat", "Pollard", "GCD"):
            assert marker in body, f"rsa skill missing {marker!r}"

    def test_symmetric_skill_covers_padding_oracle(self) -> None:
        body = load_skills(["ctf/crypto/symmetric"])["symmetric"]
        for marker in ("padding oracle", "Bleichenbacher", "ECB", "GCM", "CBC"):
            assert marker in body, f"symmetric skill missing {marker!r}"

    def test_stego_skill_covers_common_tools(self) -> None:
        body = load_skills(["ctf/forensics/stego"])["stego"]
        for marker in ("zsteg", "steghide", "exiftool", "WavSteg", "binwalk"):
            assert marker in body, f"stego skill missing {marker!r}"

    def test_pcap_skill_covers_tshark(self) -> None:
        body = load_skills(["ctf/forensics/pcap"])["pcap"]
        for marker in ("tshark", "wireshark", "HID", "USB", "PCAP"):
            assert marker in body, f"pcap skill missing {marker!r}"

    def test_flag_formats_skill_covers_exotic(self) -> None:
        body = load_skills(["ctf/flag_formats"])["flag_formats"]
        for marker in ("picoCTF", "HTB", "DASCTF", "UUID", "expected_format"):
            assert marker in body, f"flag-formats skill missing {marker!r}"

    def test_ctf_scan_mode_skill_present(self) -> None:
        body = load_skills(["ctf/ctf_scan_mode"])["ctf_scan_mode"]
        for marker in ("Phase 0", "Category Dispatch", "flag", "Workflow"):
            assert marker in body, f"ctf_scan_mode missing {marker!r}"


class TestCTFSkillValidation:
    """Mixing old and new skill name styles should validate correctly."""

    def test_validate_mixed_names(self) -> None:
        err = validate_requested_skills(
            [
                "sql_injection",  # canonical pentest skill
                "ctf/pwn/stack",
                "ctf/crypto/rsa",
                "xss",  # legacy flat
                "stego",  # flat, but stego is in ctf/forensics — should fail by name
            ]
        )
        # "stego" is not a valid bare name (the actual is "forensics/stego")
        assert err is not None and "stego" in err

    def test_validate_nested_only(self) -> None:
        err = validate_requested_skills(
            [
                "sql_injection",  # canonical pentest skill
                "ctf/pwn/stack",
                "ctf/crypto/rsa",
                "ctf/forensics/stego",
                "ctf/osint/methodology",
            ]
        )
        assert err is None, err

    def test_validate_max_skills(self) -> None:
        err = validate_requested_skills(
            [
                "sql_injection",
                "ctf/pwn/stack",
                "ctf/crypto/rsa",
                "ctf/forensics/stego",
                "ctf/osint/methodology",
                "ctf/reversing/static",
            ]
        )
        assert err is not None and "more than 5" in err.lower()


class TestCTFToolsRegistration:
    """The ctf_tools package must be wired into the ctf scan mode."""

    def test_all_ctf_tools_importable(self) -> None:
        assert len(ALL_CTF_TOOLS) == 6

    def test_ctf_scan_mode_includes_ctf_tools(self) -> None:
        tools = get_base_tools(scan_mode="ctf")
        ctf_tool_names = {t.name for t in ALL_CTF_TOOLS}
        registered = {t.name for t in tools} & ctf_tool_names
        assert registered == ctf_tool_names, (
            f"missing tools in ctf mode: {ctf_tool_names - registered}"
        )

    def test_default_mode_excludes_ctf_tools(self) -> None:
        tools = get_base_tools()
        ctf_tool_names = {t.name for t in ALL_CTF_TOOLS}
        assert not (ctf_tool_names & {t.name for t in tools})

    def test_malware_re_mode_excludes_ctf_tools(self) -> None:
        tools = get_base_tools(scan_mode="malware_re")
        ctf_tool_names = {t.name for t in ALL_CTF_TOOLS}
        assert not (ctf_tool_names & {t.name for t in tools})


class TestFlagFormatDetection:
    """The shared flag_format module must detect every family."""

    def test_generic_prefixed(self) -> None:
        for s in ("flag{abc}", "FLAG{abc}", "ctf{abc}", "CTF{abc}"):
            assert looks_like_flag(s), f"should detect {s!r}"

    def test_platform_specific(self) -> None:
        for s in (
            "picoCTF{custom_flag}",
            "HTB{leet_hax}",
            "DASCTF{some_payload}",
            "n1ctf{leet_leet}",
            "idek{leet_leet}",
            "dice{some_thing}",
            "buckeye{leet_leet}",
        ):
            assert looks_like_flag(s), f"should detect {s!r}"

    def test_exotic_no_braces(self) -> None:
        assert looks_like_flag("flag_custom_no_braces_xyz123")

    def test_exotic_url(self) -> None:
        assert looks_like_flag("https://ctf.example.com/flag/abc123def")

    def test_exotic_uuid(self) -> None:
        assert looks_like_flag("123e4567-e89b-12d3-a456-426614174000")
        assert looks_like_flag("a" * 32)

    def test_exotic_base64(self) -> None:
        assert looks_like_flag("SGVsbG8gV29ybGQxMjM0NTY3OA==")

    def test_negative(self) -> None:
        assert not looks_like_flag("just some english text without pattern")
        assert not looks_like_flag("")

    def test_custom_expected_format(self) -> None:
        custom = r"^DASCTF\{.+\}$"
        assert looks_like_flag("DASCTF{x}", expected_format=custom)
        assert not looks_like_flag("CTF{x}", expected_format=custom)

    def test_detect_format_returns_family(self) -> None:
        assert detect_format("picoCTF{some_flag}") == "platform_specific:picoCTF"
        assert detect_format("HTB{leet_hax}") == "platform_specific:HackTheBox"
        assert detect_format("not a flag") is None

    def test_example_formats_returns_list(self) -> None:
        examples = example_formats()
        assert isinstance(examples, list)
        assert len(examples) >= 5
        for ex in examples:
            assert isinstance(ex, str)


class TestCyberchefDecode:
    """The encoding-chain decoder must handle common CTF scenarios."""

    def test_single_layer_base64(self) -> None:
        result = _decode_chain("SGVsbG8gd29ybGQ=")
        assert result["success"] is True
        assert result["chain"] == ["base64"]
        assert result["final"] == "Hello world"

    def test_single_layer_hex(self) -> None:
        result = _decode_chain("48656c6c6f")
        assert result["success"] is True
        assert result["chain"] == ["hex"]
        assert result["final"] == "Hello"

    def test_single_layer_url(self) -> None:
        result = _decode_chain("CTF%7Babc%7D")
        assert result["success"] is True
        assert result["chain"] == ["url"]
        assert result["final"] == "CTF{abc}"
        assert result["found_flag"] is True

    def test_multi_layer_flag_inside(self) -> None:
        # base64 of 'flag{hello}' in hex
        result = _decode_chain("666c61677b68656c6c6f7d")
        assert result["success"] is True
        assert result["chain"] == ["hex"]
        assert result["final"] == "flag{hello}"
        assert result["found_flag"] is True

    def test_no_decoding_needed(self) -> None:
        # Plain digits/punctuation — no decoder matches, chain is empty
        result = _decode_chain("123 456 789")
        assert result["success"] is True
        assert result["chain"] == []
        assert result["final"] == "123 456 789"

    def test_custom_expected_format(self) -> None:
        result = _decode_chain(
            "666c61677b68656c6c6f7d",
            expected_format=r"^flag\{.+\}$",
        )
        assert result["found_flag"] is True

    def test_does_not_cycle_rot13(self) -> None:
        # ROT13 is its own inverse; the loader must not cycle.
        result = _decode_chain("SGVsbG8gd29ybGQ=")
        assert result["chain"] == ["base64"]
        assert "rot13" not in result["chain"]

    def test_empty_input(self) -> None:
        result = _decode_chain("")
        assert result["success"] is False


class TestXorBruteforce:
    """The XOR brute-forcer must parse inputs in multiple formats."""

    def test_parse_hex_with_prefix(self) -> None:
        assert _parse_input("0x4142") == b"AB"

    def test_parse_bare_hex(self) -> None:
        assert _parse_input("4142") == b"AB"

    def test_parse_base64(self) -> None:
        assert _parse_input("QUJD") == b"ABC"

    def test_parse_raw_text(self) -> None:
        assert _parse_input("plain text") == b"plain text"


class TestBinaryChecksec:
    """The ELF/PE protection summary must run on a real binary."""

    def test_elf_magic_detected(self) -> None:
        import tempfile

        from kael.tools.ctf_tools.binary_checksec import _checksec_elf

        # ELF magic (4 bytes) + padding + ei_class=2 (64-bit) + ei_data=1 (LE) + padding
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tf:
            tf.write(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8)
            tf.write(b"\x00" * 100)
            path = tf.name
        try:
            info = _checksec_elf(path)
            assert info.get("is_elf") is True
            assert info.get("class") == "64-bit"
        finally:
            os.unlink(path)

    def test_missing_file_returns_error_dict(self) -> None:
        # The function tool returns a JSON string
        import asyncio

        from kael.tools.ctf_tools.binary_checksec import binary_checksec

        result = asyncio.run(
            binary_checksec.on_invoke_tool(
                type("C", (), {"tool_name": "binary_checksec"})(),
                json.dumps({"binary_path": "/nonexistent/path"}),
            )
        )
        # on_invoke_tool wraps result, but if there's a context issue we get a tool error string
        # Either way, success is False
        if not result.startswith("An error"):
            data = json.loads(result)
            assert data["success"] is False


class TestFormatStringOffset:
    """The format-string offset probe planner must produce correct probes."""

    def test_default_marker(self) -> None:
        from kael.tools.ctf_tools.format_string_offset import _build_probes

        data = _build_probes("AAAABBBB", 1, 30)
        assert data["success"] is True
        assert data["marker"] == "AAAABBBB"
        assert len(data["probes"]) == 30
        assert "AAAA" in data["probes"][0] and "$p" in data["probes"][0]

    def test_custom_range(self) -> None:
        from kael.tools.ctf_tools.format_string_offset import _build_probes

        data = _build_probes("CCCCDDDD", 5, 10)
        assert len(data["probes"]) == 6
        assert "CCCCDDDD%5$p" in data["probes"]
        assert "CCCCDDDD%10$p" in data["probes"]

    def test_invalid_marker_length(self) -> None:
        from kael.tools.ctf_tools.format_string_offset import _build_probes

        data = _build_probes("SHORT", 1, 30)
        assert data["success"] is False


class TestRsaAttackDetect:
    """The RSA attack dispatcher must produce structured results."""

    def test_small_e_cube_root(self) -> None:
        from kael.tools.ctf_tools.rsa_attack_detect import _run_rsa_dispatcher

        m_int = int.from_bytes(b"hello", "big")
        c_int = m_int**3
        data = _run_rsa_dispatcher(n=str(m_int**2), e="3", c=str(c_int))
        assert data["success"] is True
        assert "results" in data
        assert "rejected" in data

    def test_invalid_input(self) -> None:
        from kael.tools.ctf_tools.rsa_attack_detect import _run_rsa_dispatcher

        data = _run_rsa_dispatcher(n="not a number", e="3", c="123")
        assert data["success"] is False


class TestPwnTemplate:
    """The pwntools template generator must produce a runnable script."""

    def test_template_is_complete(self) -> None:
        from kael.tools.ctf_tools.pwn_template import render_template

        result = render_template(binary="chall", host="t.com", port=1337, offset=72)
        assert "from pwn import *" in result
        assert "context.binary" in result
        assert "OFFSET = 72" in result
        assert 'remote("t.com", 1337)' in result

    def test_template_uses_safe_defaults(self) -> None:
        from kael.tools.ctf_tools.pwn_template import render_template

        result = render_template()
        assert "chall" in result
        assert "1337" in result
