"""Tests for binary_classifier module."""

from pathlib import Path

import pytest

from boring_secret_hunter.binary_classifier import (
    BinaryType,
    classify_binary,
    is_archive_extension,
)


class TestClassifyBinary:
    def test_elf_binary(self, tmp_path):
        f = tmp_path / "test.so"
        f.write_bytes(b"\x7fELF" + b"\x00" * 100)
        assert classify_binary(f) == BinaryType.ELF

    @pytest.mark.parametrize(
        "magic",
        [
            b"\xcf\xfa\xed\xfe",  # 64-bit LE
            b"\xce\xfa\xed\xfe",  # 32-bit LE
            b"\xca\xfe\xba\xbe",  # fat/universal
        ],
    )
    def test_macho_variants(self, tmp_path, magic):
        f = tmp_path / "test.dylib"
        f.write_bytes(magic + b"\x00" * 100)
        assert classify_binary(f) == BinaryType.MACHO

    def test_pe32(self, tmp_path):
        f = tmp_path / "test.exe"
        f.write_bytes(b"MZ" + b"\x00" * 100)
        assert classify_binary(f) == BinaryType.PE32

    def test_raw_data(self, tmp_path):
        f = tmp_path / "dump.bin"
        f.write_bytes(b"\x00\x01\x02\x03" + b"\xff" * 100)
        assert classify_binary(f) == BinaryType.RAW_DATA

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty"
        f.write_bytes(b"")
        assert classify_binary(f) == BinaryType.UNKNOWN

    def test_tiny_file(self, tmp_path):
        f = tmp_path / "tiny"
        f.write_bytes(b"\x00")
        assert classify_binary(f) == BinaryType.UNKNOWN

    def test_nonexistent(self, tmp_path):
        f = tmp_path / "nope"
        assert classify_binary(f) == BinaryType.UNKNOWN

    def test_real_elf_binary(self):
        """Test with the real test binary if available."""
        test_bin = Path(__file__).parent.parent / "test" / "libcronet.132.0.6779.0.so"
        if test_bin.exists():
            assert classify_binary(test_bin) == BinaryType.ELF


class TestIsArchiveExtension:
    def test_apk(self, tmp_path):
        assert is_archive_extension(tmp_path / "app.apk") is True

    def test_ipa(self, tmp_path):
        assert is_archive_extension(tmp_path / "app.ipa") is True

    def test_zip(self, tmp_path):
        assert is_archive_extension(tmp_path / "lib.zip") is True

    def test_jar(self, tmp_path):
        assert is_archive_extension(tmp_path / "lib.jar") is True

    def test_so(self, tmp_path):
        assert is_archive_extension(tmp_path / "lib.so") is False
