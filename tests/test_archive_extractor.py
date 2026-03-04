"""Tests for archive_extractor module."""

import zipfile

import pytest

from boring_secret_hunter.archive_extractor import extract_binaries, is_archive


class TestIsArchive:
    def test_apk(self, tmp_path):
        assert is_archive(tmp_path / "app.apk") is True

    def test_ipa(self, tmp_path):
        assert is_archive(tmp_path / "app.ipa") is True

    def test_zip(self, tmp_path):
        assert is_archive(tmp_path / "lib.zip") is True

    def test_so(self, tmp_path):
        assert is_archive(tmp_path / "lib.so") is False

    def test_no_ext(self, tmp_path):
        assert is_archive(tmp_path / "binary") is False


class TestExtractBinaries:
    @pytest.fixture
    def extracted(self):
        """Run extraction and ensure temp dir cleanup."""
        tmp_dirs = []

        def _extract(archive_path):
            result, tmp_dir = extract_binaries(archive_path)
            tmp_dirs.append(tmp_dir)
            return result

        yield _extract

        import shutil

        for d in tmp_dirs:
            shutil.rmtree(d, ignore_errors=True)

    def _make_apk(self, tmp_path, name="test.apk"):
        """Create a test APK with an ELF .so inside."""
        apk_path = tmp_path / name
        elf_content = b"\x7fELF" + b"\x00" * 2000
        with zipfile.ZipFile(apk_path, "w") as zf:
            zf.writestr("lib/arm64-v8a/libtest.so", elf_content)
            zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 100)
        return apk_path

    def _make_zip_with_macho(self, tmp_path, name="test.zip"):
        """Create a test ZIP with a Mach-O binary inside."""
        zip_path = tmp_path / name
        macho_content = b"\xcf\xfa\xed\xfe" + b"\x00" * 2000
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("Payload/App.app/App", macho_content)
        return zip_path

    def test_extract_apk(self, tmp_path, extracted):
        apk = self._make_apk(tmp_path)
        result = extracted(apk)
        assert len(result) == 1
        assert result[0].name.endswith(".so")

    def test_extract_ipa(self, tmp_path, extracted):
        ipa = self._make_zip_with_macho(tmp_path, "test.ipa")
        result = extracted(ipa)
        assert len(result) == 1

    def test_bad_archive(self, tmp_path, extracted):
        bad = tmp_path / "bad.zip"
        bad.write_bytes(b"not a zip file")
        result = extracted(bad)
        assert len(result) == 0

    def test_empty_archive(self, tmp_path, extracted):
        empty = tmp_path / "empty.apk"
        with zipfile.ZipFile(empty, "w"):
            pass
        result = extracted(empty)
        assert len(result) == 0
