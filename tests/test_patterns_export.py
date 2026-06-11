"""Unit tests for friTap pattern export (no Ghidra required).

Covers the builder, arch mapping, merge/dedup, file-writing guard, the
export-patterns reconstruction path, and the parser fix that captures
ssl_log_secret / SSL_read / SSL_write byte patterns from the real Ghidra output.
"""

import json

from boring_secret_hunter.analyzer import (
    _parse_function_matches,
    result_from_parsed_output,
)
from boring_secret_hunter.patterns_export import (
    build_fritap_patterns,
    has_patterns,
    merge_patterns,
    to_fritap_arch,
    write_patterns_file,
)
from boring_secret_hunter.result import AnalysisResult, FunctionMatch


# --- arch mapping -----------------------------------------------------------

def test_to_fritap_arch_maps_ghidra_strings():
    assert to_fritap_arch("AARCH64:LE:64:v8A") == "arm64"
    assert to_fritap_arch("ARM:LE:32:v8") == "arm"
    assert to_fritap_arch("x86:LE:64:default") == "x64"
    assert to_fritap_arch("x86:LE:32:default") == "x86"


def test_to_fritap_arch_idempotent_and_unknown():
    assert to_fritap_arch("arm64") == "arm64"  # already a friTap token
    assert to_fritap_arch("MIPS:BE:32:default") is None
    assert to_fritap_arch(None) is None


# --- merge / dedup ----------------------------------------------------------

def test_merge_patterns_appends_and_dedups_lists():
    base = {"libssl.so": {"arm64": {"ssl_log_secret": ["AA BB"]}}}
    merge_patterns(base, {"libssl.so": {"arm64": {"ssl_log_secret": ["AA BB", "CC DD"]}}})
    assert base["libssl.so"]["arm64"]["ssl_log_secret"] == ["AA BB", "CC DD"]


# --- builder ----------------------------------------------------------------

def _ssl_result():
    return AnalysisResult(
        binary_name="libssl.so",
        binary_path="/x/libssl.so",
        architecture="AARCH64:LE:64:v8A",
        binary_type="elf",
        tls_library_type="BoringSSL",
        functions=[
            FunctionMatch(label="ssl_log_secret", byte_pattern="3F 23 03 D5",
                          function_type="ssl_log_secret"),
            FunctionMatch(label="SSL_read", byte_pattern="2D E9 F0 41",
                          function_type="SSL_read"),
            FunctionMatch(label="SSL_write", byte_pattern="AA BB CC DD",
                          function_type="SSL_write"),
        ],
        success=True,
        raw_output="FULL GHIDRA LOG",
    )


def test_build_keys_ssl_by_binary_name_and_maps_func_keys():
    p = build_fritap_patterns([_ssl_result()])
    assert p["libssl.so"]["arm64"]["ssl_log_secret"] == ["3F 23 03 D5"]
    assert p["libssl.so"]["arm64"]["SSL_Read"] == ["2D E9 F0 41"]
    assert p["libssl.so"]["arm64"]["SSL_Write"] == ["AA BB CC DD"]


def test_build_merges_quiche_under_google_quiche():
    r = AnalysisResult(
        binary_name="libmonochrome.so",
        quiche_patterns={"google_quiche": {"arm64": {"QuicSpdyStream_WriteOrBufferBody": ["3F 23"]}}},
        success=True,
    )
    p = build_fritap_patterns([r])
    assert p["google_quiche"]["arm64"]["QuicSpdyStream_WriteOrBufferBody"] == ["3F 23"]


def test_meta_excludes_raw_output_by_default():
    p = build_fritap_patterns([_ssl_result()], include_raw_output=False)
    assert "FULL GHIDRA LOG" not in json.dumps(p)
    assert p["_meta"]["generator"] == "BoringSecretHunter"
    assert p["_meta"]["binaries"][0]["binary_name"] == "libssl.so"


def test_meta_includes_raw_output_when_requested():
    p = build_fritap_patterns([_ssl_result()], include_raw_output=True)
    assert p["_meta"]["binaries"][0]["raw_output"] == "FULL GHIDRA LOG"


def test_unmappable_arch_without_quiche_skips_ssl():
    r = AnalysisResult(
        binary_name="weird.so",
        architecture="MIPS:BE:32:default",
        functions=[FunctionMatch(label="ssl_log_secret", byte_pattern="AA",
                                 function_type="ssl_log_secret")],
        success=True,
    )
    p = build_fritap_patterns([r])
    assert "weird.so" not in p  # no usable arch and no QUIC fallback -> skipped


def test_missing_arch_falls_back_to_quiche_arch():
    # Header detection failed (empty arch) but the QUICHE finder reported arm64;
    # the SSL functions should inherit that arch rather than be dropped.
    r = AnalysisResult(
        binary_name="lib.so",
        architecture="",
        functions=[FunctionMatch(label="ssl_log_secret", byte_pattern="AA BB",
                                 function_type="ssl_log_secret")],
        quiche_patterns={"google_quiche": {"arm64": {"X": ["00"]}}},
        success=True,
    )
    p = build_fritap_patterns([r])
    assert p["lib.so"]["arm64"]["ssl_log_secret"] == ["AA BB"]
    assert p["google_quiche"]["arm64"]["X"] == ["00"]


# --- file write guard -------------------------------------------------------

def test_has_patterns_ignores_meta_only():
    assert has_patterns({"_meta": {}}) is False
    assert has_patterns({"_meta": {}, "libssl.so": {}}) is True


def test_write_skips_when_no_patterns(tmp_path):
    out = tmp_path / "patterns.json"
    written = write_patterns_file({"_meta": {"x": 1}}, out)
    assert written is False
    assert not out.exists()


def test_write_creates_parent_dirs(tmp_path):
    out = tmp_path / "results" / "patterns.json"
    written = write_patterns_file(build_fritap_patterns([_ssl_result()]), out)
    assert written is True
    assert out.exists()
    json.loads(out.read_text())  # valid JSON


# --- parser fix: real Ghidra output strings ---------------------------------

REAL_OUTPUT = """
BoringSecretHunter v1.4.0
[+] ssl_log_secret identified via SymbolTableLookup!
[*] Function label: ssl_log_secret (ssl_log_secret)
[*] Function offset (Ghidra): 0010A0 (0x0010A0)
[*] Function offset (IDA with base 0x0): 10A0 (0x10A0)
[*] Byte pattern for frida (friTap): 55 48 89 E5 41 57 41 56
[*] Byte pattern for frida (friTap) truncated version: 55 48 89 E5
""".strip()


def test_parser_captures_byte_pattern_from_real_output():
    fns = _parse_function_matches(REAL_OUTPUT)
    assert len(fns) == 1
    fn = fns[0]
    # The truncated line must NOT overwrite the full pattern.
    assert fn.byte_pattern == "55 48 89 E5 41 57 41 56"
    assert fn.function_type == "ssl_log_secret"
    assert fn.ghidra_offset.startswith("0010A0")


def test_parser_strips_duplicate_label_parenthetical():
    # Ghidra prints "label (function repr)"; the redundant parenthetical must be
    # stripped so patterns.json gets a clean label, not "FUN_x (FUN_x)".
    out = "[*] Function label: FUN_05ba9b1c (FUN_05ba9b1c)\n" \
          "[*] Byte pattern for frida (friTap): 3F 23 03 D5"
    fns = _parse_function_matches(out)
    assert len(fns) == 1
    assert fns[0].label == "FUN_05ba9b1c"


def test_parser_keeps_label_without_parenthetical():
    out = "[*] Function label: ssl_log_secret\n" \
          "[*] Byte pattern for frida (friTap): 3F 23 03 D5"
    fns = _parse_function_matches(out)
    assert fns[0].label == "ssl_log_secret"


def test_result_from_parsed_output_roundtrip(tmp_path):
    # Use a real file so architecture detection has something to read.
    binp = tmp_path / "lib.bin"
    # Minimal ELF header: magic + 64-bit LE + EM_AARCH64 (0xB7) at offset 18.
    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4] = 2  # 64-bit
    header[5] = 1  # little-endian
    header[18] = 0xB7  # EM_AARCH64
    binp.write_bytes(bytes(header))
    res = result_from_parsed_output(binp, REAL_OUTPUT)
    assert res.architecture == "AARCH64:LE:64:v8A"
    p = build_fritap_patterns([res])
    assert p["lib.bin"]["arm64"]["ssl_log_secret"] == ["55 48 89 E5 41 57 41 56"]
