"""Main analysis orchestrator — ports ghidra_analysis.sh."""

import logging
from concurrent.futures import ThreadPoolExecutor

import shutil
from pathlib import Path
from typing import Callable, Dict, List, Optional

from boring_secret_hunter.archive_extractor import extract_binaries, is_archive
from boring_secret_hunter.arch_detector import detect_architecture, detect_from_siblings
from boring_secret_hunter.binary_classifier import (
    BinaryType,
    classify_binary,
    is_archive_extension,
)
from boring_secret_hunter.ghidra_runner import GhidraError, parse_output, run_analysis
from boring_secret_hunter.result import AnalysisResult, BatchResult, FunctionMatch

log = logging.getLogger(__name__)

# Threshold for "large dump" mode (in bytes)
LARGE_DUMP_THRESHOLD = 100 * 1024 * 1024  # 100 MB


def discover_binaries(path: Path) -> List[Path]:
    """Discover all supported binaries at the given path.

    If path is a file, returns [path] if it's a supported binary or archive.
    If path is a directory, returns all supported binaries in the directory.
    """
    if path.is_file():
        return [path]

    if not path.is_dir():
        log.error("Path does not exist: %s", path)
        return []

    binaries = []
    for item in sorted(path.iterdir()):
        if not item.is_file():
            continue
        if is_archive_extension(item):
            continue
        bin_type = classify_binary(item)
        if bin_type != BinaryType.UNKNOWN:
            binaries.append(item)
    return binaries


def _parse_function_matches(parsed_output: str) -> List[FunctionMatch]:
    """Parse function match info from the BoringSecretHunter output."""
    functions = []
    current = FunctionMatch()

    for line in parsed_output.splitlines():
        line = line.strip()
        if not line:
            continue

        # Look for function label patterns
        if "Function Label:" in line or "function label:" in line.lower():
            if current.label:
                functions.append(current)
                current = FunctionMatch()
            current.label = line.split(":", 1)[1].strip()
        elif "Ghidra Offset:" in line or "ghidra offset:" in line.lower():
            current.ghidra_offset = line.split(":", 1)[1].strip()
        elif "IDA Offset:" in line or "ida offset:" in line.lower():
            current.ida_offset = line.split(":", 1)[1].strip()
        elif "Byte Pattern:" in line or "byte pattern:" in line.lower():
            current.byte_pattern = line.split(":", 1)[1].strip()

    if current.label:
        functions.append(current)

    return functions


def _detect_tls_library(parsed_output: str) -> str:
    """Detect TLS library type from output."""
    lower = parsed_output.lower()
    if "boringssl" in lower:
        return "BoringSSL"
    elif "rustls" in lower:
        return "RustLS"
    elif "openssl" in lower:
        return "OpenSSL"
    return "unknown"


def analyze_binary(
    binary_path: Path,
    ghidra_dir: str,
    debug: bool = False,
    large_dump_mode: Optional[str] = None,
    processor_override: Optional[str] = None,
) -> AnalysisResult:
    """Analyze a single binary.

    Args:
        binary_path: Path to the binary
        ghidra_dir: Path to Ghidra installation
        debug: Enable debug output
        large_dump_mode: Mode for large dumps ('normal', 'fast', 'skip')
        processor_override: Override processor detection with this value
    """
    result = AnalysisResult(
        binary_name=binary_path.name,
        binary_path=str(binary_path),
    )

    bin_type = classify_binary(binary_path)
    result.binary_type = bin_type.value

    # Detect architecture
    arch = detect_architecture(binary_path)
    if arch:
        result.architecture = arch

    # Build extra args for raw data files
    extra_args = []
    if bin_type == BinaryType.RAW_DATA:
        proc = processor_override or detect_from_siblings(
            binary_path.parent, processor_override
        )
        result.architecture = proc
        extra_args = ["-processor", proc, "-loader", "BinaryLoader"]
        log.info("    Raw data file detected, using processor: %s", proc)

        # Check size for large dump handling
        file_size = binary_path.stat().st_size
        if file_size > LARGE_DUMP_THRESHOLD:
            size_mb = file_size // (1024 * 1024)
            mode = large_dump_mode or "normal"
            if mode == "skip":
                log.info(
                    "    Skipping %s (%d MB) per user choice.",
                    binary_path.name,
                    size_mb,
                )
                result.error = f"Skipped (large dump: {size_mb} MB)"
                return result

    try:
        raw_output = run_analysis(
            binary_path=binary_path,
            ghidra_dir=ghidra_dir,
            extra_args=extra_args if extra_args else None,
            debug=debug,
            large_dump_mode=large_dump_mode,
        )
        result.raw_output = raw_output

        parsed = parse_output(raw_output)
        if parsed.strip():
            result.success = True
            result.functions = _parse_function_matches(parsed)
            result.tls_library_type = _detect_tls_library(parsed)
        else:
            log.warning(
                "    No results found in Ghidra output for %s", binary_path.name
            )
            if debug:
                log.debug("Raw output:\n%s", raw_output)

        if debug:
            log.debug("Raw Ghidra output:\n%s", raw_output)

    except GhidraError as e:
        result.error = str(e)
        log.error("    Analysis failed: %s", e)

    return result


def analyze(
    path: Path,
    ghidra_dir: str,
    debug: bool = False,
    large_dump_mode: Optional[str] = None,
    processor_override: Optional[str] = None,
    on_result: Optional[Callable[[AnalysisResult, str], None]] = None,
) -> BatchResult:
    """Analyze one or more binaries.

    Handles archives (APK/IPA/ZIP), single files, and directories.

    Args:
        path: Path to binary, archive, or directory
        ghidra_dir: Path to Ghidra installation
        debug: Enable debug output
        large_dump_mode: Mode for large dumps
        processor_override: Override processor for raw dumps
    """
    batch = BatchResult()
    temp_dirs = []

    try:
        # Handle archives
        if path.is_file() and is_archive(path):
            extracted, tmp_dir = extract_binaries(path)
            temp_dirs.append(tmp_dir)
            binaries = extracted
        else:
            binaries = discover_binaries(path)

        batch.total = len(binaries)

        if not binaries:
            log.warning(
                "No supported binaries found. Supported types: ELF, Mach-O, PE32, raw data files."
            )
            return batch

        if len(binaries) == 1:
            log.info("Found 1 binary to analyze:")
        else:
            log.info("Found %d binaries to analyze:", len(binaries))
        for i, b in enumerate(binaries, 1):
            log.info("    %d. %s", i, b.name)

        for i, binary in enumerate(binaries, 1):
            log.info("[%d/%d] Analyzing %s...", i, batch.total, binary.name)

            result = analyze_binary(
                binary_path=binary,
                ghidra_dir=ghidra_dir,
                debug=debug,
                large_dump_mode=large_dump_mode,
                processor_override=processor_override,
            )
            batch.results.append(result)

            if result.success:
                batch.successful += 1
                parsed = parse_output(result.raw_output)
                if parsed.strip():
                    log.debug("Parsed output for %s:\n%s", binary.name, parsed)
                    if on_result is not None:
                        on_result(result, parsed)

    finally:
        for tmp_dir in temp_dirs:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    return batch


def analyze_parallel(
    binaries: List[Path],
    ghidra_dir: str,
    max_workers: int = 4,
    debug: bool = False,
    large_dump_mode: Optional[str] = None,
    processor_override: Optional[str] = None,
) -> Dict[Path, AnalysisResult]:
    """Analyze multiple binaries in parallel using threads.

    Args:
        binaries: List of binary paths to analyze
        ghidra_dir: Path to Ghidra installation
        max_workers: Maximum number of concurrent analyses
        debug: Enable debug output
        large_dump_mode: Mode for large dumps ('normal', 'fast', 'skip')
        processor_override: Override processor for raw dumps

    Returns:
        Dictionary mapping each binary path to its AnalysisResult.
    """
    results: Dict[Path, AnalysisResult] = {}

    def _run(binary_path: Path) -> tuple:
        result = analyze_binary(
            binary_path=binary_path,
            ghidra_dir=ghidra_dir,
            debug=debug,
            large_dump_mode=large_dump_mode,
            processor_override=processor_override,
        )
        return binary_path, result

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for path, result in executor.map(_run, binaries):
            results[path] = result

    return results
