"""Extract binaries from APK/IPA/ZIP archives."""

import logging
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import List, Tuple

from boring_secret_hunter.binary_classifier import BinaryType, classify_binary

log = logging.getLogger(__name__)

# Archive types recognized by extension
_ARCHIVE_EXTENSIONS = {".apk", ".ipa", ".zip"}


def is_archive(path: Path) -> bool:
    """Check if a file is a supported archive type."""
    return path.suffix.lower() in _ARCHIVE_EXTENSIONS


def extract_binaries(archive_path: Path) -> Tuple[List[Path], Path]:
    """Extract binaries from an archive.

    For APK: extracts only .so files that are ELF binaries.
    For IPA: extracts all Mach-O binaries.
    For ZIP: extracts all ELF and Mach-O binaries.

    Returns:
        Tuple of (list of extracted binary paths, temp directory to clean up)
    """
    suffix = archive_path.suffix.lower()
    tmp_dir = Path(tempfile.mkdtemp(prefix="bsh_extract_"))

    log.info("Extracting archive: %s", archive_path.name)

    try:
        with zipfile.ZipFile(archive_path, "r") as zf:
            zf.extractall(tmp_dir)
    except (zipfile.BadZipFile, Exception) as e:
        log.warning("Failed to extract %s: %s", archive_path.name, e)
        shutil.rmtree(tmp_dir, ignore_errors=True)
        return [], tmp_dir

    extracted = []
    for candidate in tmp_dir.rglob("*"):
        if not candidate.is_file() or candidate.stat().st_size < 1024:
            continue

        bin_type = classify_binary(candidate)
        should_extract = False

        if suffix == ".apk":
            if candidate.suffix == ".so" and bin_type == BinaryType.ELF:
                should_extract = True
        elif suffix == ".ipa":
            if bin_type == BinaryType.MACHO:
                should_extract = True
        else:
            if bin_type in (BinaryType.ELF, BinaryType.MACHO):
                should_extract = True

        if should_extract:
            relative = candidate.relative_to(tmp_dir)
            sanitized = str(relative).replace("/", "__").replace("\\", "__")
            dest_name = f"{archive_path.name}__{sanitized}"
            dest_path = tmp_dir / dest_name
            if candidate != dest_path:
                shutil.copy2(candidate, dest_path)
            extracted.append(dest_path)
            log.info("    Found: %s", relative)

    return extracted, tmp_dir
