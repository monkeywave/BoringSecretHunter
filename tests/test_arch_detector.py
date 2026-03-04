"""Tests for arch_detector module."""

import struct
from pathlib import Path

import pytest

from boring_secret_hunter.arch_detector import (
    DEFAULT_PROCESSOR,
    detect_architecture,
    detect_from_siblings,
)


def _make_elf(tmp_path, name, e_machine, ei_data=1):
    """Create a minimal ELF binary with given e_machine value."""
    f = tmp_path / name
    data = bytearray(20)
    data[0:4] = b"\x7fELF"
    data[5] = ei_data  # 1=LE, 2=BE
    endian = "<" if ei_data == 1 else ">"
    struct.pack_into(f"{endian}H", data, 18, e_machine)
    f.write_bytes(bytes(data) + b"\x00" * 100)
    return f


class TestDetectArchitecture:
    @pytest.mark.parametrize(
        "e_machine,expected",
        [
            (0xB7, "AARCH64:LE:64:v8A"),
            (0x3E, "x86:LE:64:default"),
            (0x28, "ARM:LE:32:v8"),
            (0x03, "x86:LE:32:default"),
        ],
    )
    def test_elf_arch(self, tmp_path, e_machine, expected):
        f = _make_elf(tmp_path, "test.so", e_machine)
        assert detect_architecture(f) == expected

    def test_elf_unknown_machine(self, tmp_path):
        f = _make_elf(tmp_path, "test.so", 0xFF)
        assert detect_architecture(f) is None

    def test_raw_data_returns_none(self, tmp_path):
        f = tmp_path / "dump.bin"
        f.write_bytes(b"\x00\x01\x02\x03" * 100)
        assert detect_architecture(f) is None

    def test_real_elf_binary(self):
        """Test with the real test binary if available."""
        test_bin = Path(__file__).parent.parent / "test" / "libcronet.132.0.6779.0.so"
        if test_bin.exists():
            arch = detect_architecture(test_bin)
            assert arch is not None


class TestDetectFromSiblings:
    def test_finds_arch_from_sibling(self, tmp_path):
        _make_elf(tmp_path, "sibling.so", 0xB7)
        raw = tmp_path / "dump.bin"
        raw.write_bytes(b"\x00" * 100)
        assert detect_from_siblings(tmp_path) == "AARCH64:LE:64:v8A"

    def test_override_takes_precedence(self, tmp_path):
        _make_elf(tmp_path, "sibling.so", 0xB7)
        assert (
            detect_from_siblings(tmp_path, "x86:LE:64:default") == "x86:LE:64:default"
        )

    def test_defaults_when_no_siblings(self, tmp_path):
        assert detect_from_siblings(tmp_path) == DEFAULT_PROCESSOR
