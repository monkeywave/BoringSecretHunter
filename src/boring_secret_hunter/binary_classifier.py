"""Classify binary files by magic bytes."""

import enum
from pathlib import Path


class BinaryType(enum.Enum):
    ELF = "elf"
    MACHO = "macho"
    PE32 = "pe32"
    RAW_DATA = "data"
    UNKNOWN = "unknown"


# Magic byte signatures
_ELF_MAGIC = b"\x7fELF"
_MACHO_MAGIC_64_LE = b"\xcf\xfa\xed\xfe"  # 64-bit little-endian
_MACHO_MAGIC_32_LE = b"\xce\xfa\xed\xfe"  # 32-bit little-endian
_MACHO_MAGIC_64_BE = b"\xfe\xed\xfa\xcf"  # 64-bit big-endian
_MACHO_MAGIC_32_BE = b"\xfe\xed\xfa\xce"  # 32-bit big-endian
_MACHO_FAT_BE = b"\xca\xfe\xba\xbe"  # Universal/fat binary
_MACHO_FAT_LE = b"\xbe\xba\xfe\xca"  # Universal/fat binary (LE)
_PE_MAGIC = b"MZ"


def classify_binary(path: Path) -> BinaryType:
    """Classify a binary file by reading its magic bytes.

    Returns BinaryType enum indicating the file type.
    """
    try:
        with open(path, "rb") as f:
            header = f.read(4)
    except (OSError, IOError):
        return BinaryType.UNKNOWN

    if len(header) < 2:
        return BinaryType.UNKNOWN

    if header[:4] == _ELF_MAGIC:
        return BinaryType.ELF

    if header[:4] in (
        _MACHO_MAGIC_64_LE,
        _MACHO_MAGIC_32_LE,
        _MACHO_MAGIC_64_BE,
        _MACHO_MAGIC_32_BE,
        _MACHO_FAT_BE,
        _MACHO_FAT_LE,
    ):
        return BinaryType.MACHO

    if header[:2] == _PE_MAGIC:
        return BinaryType.PE32

    return BinaryType.RAW_DATA


def is_supported_binary(path: Path) -> bool:
    """Check if a file is a supported binary type (not UNKNOWN)."""
    return classify_binary(path) != BinaryType.UNKNOWN


def is_archive_extension(path: Path) -> bool:
    """Check if a file has an archive extension (to skip during classification)."""
    return path.suffix.lower() in {".apk", ".ipa", ".zip", ".jar"}
