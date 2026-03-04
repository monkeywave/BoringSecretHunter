"""Detect CPU architecture from binary headers."""

import struct
from pathlib import Path
from typing import Optional

from boring_secret_hunter.binary_classifier import (
    BinaryType,
    classify_binary,
    _MACHO_MAGIC_64_LE,
    _MACHO_MAGIC_32_LE,
    _MACHO_MAGIC_64_BE,
    _MACHO_MAGIC_32_BE,
    _MACHO_FAT_BE,
    _MACHO_FAT_LE,
)


# ELF e_machine values (at offset 18, 2 bytes)
_ELF_MACHINES = {
    0x03: "x86:LE:32:default",  # EM_386
    0x3E: "x86:LE:64:default",  # EM_X86_64
    0x28: "ARM:LE:32:v8",  # EM_ARM
    0xB7: "AARCH64:LE:64:v8A",  # EM_AARCH64
    0x08: "MIPS:BE:32:default",  # EM_MIPS
    0xF3: "RISCV:LE:64:default",  # EM_RISCV
}

# Mach-O cputype values (at offset 4, 4 bytes)
_MACHO_CPUTYPES_LE = {
    0x0C: "ARM:LE:32:v8",  # CPU_TYPE_ARM
    0x0100000C: "AARCH64:LE:64:v8A",  # CPU_TYPE_ARM64
    0x07: "x86:LE:32:default",  # CPU_TYPE_X86
    0x01000007: "x86:LE:64:default",  # CPU_TYPE_X86_64
}

DEFAULT_PROCESSOR = "AARCH64:LE:64:v8A"


def detect_architecture(path: Path) -> Optional[str]:
    """Detect Ghidra processor string from binary headers.

    Returns a Ghidra-compatible processor string like 'AARCH64:LE:64:v8A'
    or None if detection fails.
    """
    bin_type = classify_binary(path)

    if bin_type == BinaryType.ELF:
        return _detect_elf_arch(path)
    elif bin_type == BinaryType.MACHO:
        return _detect_macho_arch(path)
    return None


def _detect_elf_arch(path: Path) -> Optional[str]:
    """Read ELF e_machine field at offset 18."""
    try:
        with open(path, "rb") as f:
            f.seek(5)
            ei_data = struct.unpack("B", f.read(1))[0]
            endian = "<" if ei_data == 1 else ">"
            f.seek(18)
            e_machine = struct.unpack(f"{endian}H", f.read(2))[0]
        return _ELF_MACHINES.get(e_machine)
    except (OSError, struct.error):
        return None


def _detect_macho_arch(path: Path) -> Optional[str]:
    """Read Mach-O cputype field at offset 4."""
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
            # Determine endianness from magic
            if magic in (_MACHO_MAGIC_64_LE, _MACHO_MAGIC_32_LE):
                endian = "<"
            elif magic in (_MACHO_MAGIC_64_BE, _MACHO_MAGIC_32_BE):
                endian = ">"
            elif magic == _MACHO_FAT_BE:
                # Fat binary - read first arch
                endian = ">"
                f.seek(8)  # skip to first arch cputype
            elif magic == _MACHO_FAT_LE:
                endian = "<"
                f.seek(8)
            else:
                return None
            cputype = struct.unpack(f"{endian}I", f.read(4))[0]
        return _MACHO_CPUTYPES_LE.get(cputype)
    except (OSError, struct.error):
        return None


def detect_from_siblings(
    directory: Path, processor_override: Optional[str] = None
) -> str:
    """Detect processor from sibling binaries in the same directory.

    Used for raw data dumps where the binary itself has no headers.

    Args:
        directory: Directory to scan for sibling binaries
        processor_override: If set, use this value directly (from CLI --processor flag)

    Returns:
        Ghidra processor string, defaults to AARCH64:LE:64:v8A
    """
    if processor_override:
        return processor_override

    for sibling in directory.iterdir():
        if not sibling.is_file():
            continue
        arch = detect_architecture(sibling)
        if arch:
            return arch

    return DEFAULT_PROCESSOR
