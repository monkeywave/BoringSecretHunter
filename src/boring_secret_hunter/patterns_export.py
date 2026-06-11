"""Build and write fritap-consumable pattern JSON files.

This is the single source of truth for turning BoringSecretHunter analysis
results into the JSON layout that friTap consumes via ``--patterns``. Both the
PyPi CLI (``bsh analyze``) and the Docker entrypoint (``ghidra_analysis.sh`` ->
``bsh export-patterns``) call into here so the two paths always emit identical
files.

friTap's ``PatternLoader.validate()`` accepts a flat three-level structure::

    {
      "_meta": { ...ignored by friTap (key starts with '_')... },
      "libssl.so": {
        "arm64": { "ssl_log_secret": ["3F 23 03 D5 ..."], "SSL_Read": [...] }
      },
      "google_quiche": {
        "arm64": { "QuicSpdyStream_WriteOrBufferBody": [...] }
      }
    }

There is NO ``modules`` wrapper and NO platform level. Architecture tokens are
``x64`` / ``arm64`` / ``arm`` / ``x86``. Pattern strings are space-separated hex
pairs with optional ``?`` / ``??`` wildcards. Top-level keys starting with ``_``
are silently skipped by friTap, so ``_meta`` is a safe place for human-facing
debug data.
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional

from boring_secret_hunter import __version__
from boring_secret_hunter.result import AnalysisResult

log = logging.getLogger(__name__)

# Ghidra processor strings (as produced by arch_detector.detect_architecture)
# mapped to the architecture tokens friTap expects.
GHIDRA_ARCH_TO_FRITAP = {
    "AARCH64:LE:64:v8A": "arm64",
    "ARM:LE:32:v8": "arm",
    "x86:LE:64:default": "x64",
    "x86:LE:32:default": "x86",
}

# friTap architecture tokens (used to recognise an already-mapped value).
_FRITAP_ARCHES = {"arm64", "arm", "x64", "x86"}

# Map BoringSecretHunter FunctionMatch.function_type values to the function-key
# names friTap looks up. Capitalisation matches friTap's default_patterns.json
# (_docs.categories) and the legacy pattern hooking consumer. The "_ex" variants
# are forward-compatible: current friTap ignores unknown function keys.
SSL_FUNC_KEY = {
    "ssl_log_secret": "ssl_log_secret",
    "SSL_read": "SSL_Read",
    "SSL_write": "SSL_Write",
    "SSL_read_ex": "SSL_Read_Ex",
    "SSL_write_ex": "SSL_Write_Ex",
}

# Top-level key that holds Google QUICHE patterns (a friTap pseudo-library, not
# a real .so name). FunctionMatch entries with this type live in
# AnalysisResult.quiche_patterns already, so they are handled separately.
_QUICHE_TYPE = "quiche"
_QUICHE_KEY = "google_quiche"


def to_fritap_arch(ghidra_arch: Optional[str]) -> Optional[str]:
    """Map a Ghidra processor string to a friTap architecture token.

    Returns the token (``arm64`` / ``arm`` / ``x64`` / ``x86``) or ``None`` if
    the value cannot be mapped. Already-mapped tokens are returned as-is so the
    function is idempotent.
    """
    if not ghidra_arch:
        return None
    if ghidra_arch in _FRITAP_ARCHES:
        return ghidra_arch
    return GHIDRA_ARCH_TO_FRITAP.get(ghidra_arch)


def merge_patterns(base: dict, overlay: dict) -> dict:
    """Recursively merge ``overlay`` into ``base`` in place and return it.

    Dicts merge recursively. Leaf pattern lists are appended with de-duplication
    (preserving order) so repeated functions and multiple binaries accumulate
    their pattern variants instead of overwriting one another.
    """
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            merge_patterns(base[key], value)
        elif isinstance(value, list) and isinstance(base.get(key), list):
            for item in value:
                if item not in base[key]:
                    base[key].append(item)
        else:
            base[key] = value
    return base


def _quiche_arch(result: AnalysisResult) -> Optional[str]:
    """Return the friTap arch token carried by a result's QUICHE patterns.

    QUICHE patterns are stored as ``{"google_quiche": {<arch>: {...}}}`` where
    <arch> is already a friTap token emitted by the Ghidra finder. Used as a
    fallback arch for SSL functions when header-based detection failed.
    """
    quiche = result.quiche_patterns.get(_QUICHE_KEY, {})
    for arch in quiche:
        if arch in _FRITAP_ARCHES:
            return arch
    return None


def _result_meta(result: AnalysisResult, include_raw_output: bool) -> dict:
    """Build the per-binary ``_meta`` entry for a single result."""
    meta = {
        "binary_name": result.binary_name,
        "binary_path": result.binary_path,
        "architecture": result.architecture,
        "binary_type": result.binary_type,
        "tls_library_type": result.tls_library_type,
        "success": result.success,
        "functions": [
            {
                "label": fn.label,
                "function_type": fn.function_type,
                "ghidra_offset": fn.ghidra_offset,
                "ida_offset": fn.ida_offset,
                "strategy_name": fn.strategy_name,
            }
            for fn in result.functions
        ],
    }
    if result.error:
        meta["error"] = result.error
    if include_raw_output:
        meta["raw_output"] = result.raw_output
    return meta


def build_fritap_patterns(
    results: List[AnalysisResult], include_raw_output: bool = False
) -> dict:
    """Assemble the friTap pattern dict from analysis results.

    SSL/keylog patterns are keyed by the analysed binary's filename (friTap
    matches ``patternData[moduleName]`` first). QUICHE patterns are merged under
    the ``google_quiche`` pseudo-library. A ``_meta`` block carries human-facing
    debug data that friTap ignores.
    """
    patterns: Dict[str, dict] = {}
    binaries_meta = []

    for result in results:
        binaries_meta.append(_result_meta(result, include_raw_output))

        # QUICHE patterns are already in friTap flat form -> merge as-is.
        if result.quiche_patterns:
            merge_patterns(patterns, result.quiche_patterns)

        # SSL / keylog functions need an architecture token and a library key.
        ssl_functions = [
            fn
            for fn in result.functions
            if fn.function_type != _QUICHE_TYPE and fn.byte_pattern
        ]
        if not ssl_functions:
            continue

        arch = to_fritap_arch(result.architecture) or _quiche_arch(result)
        if not arch:
            log.warning(
                "Could not map architecture %r for %s; skipping its SSL patterns.",
                result.architecture,
                result.binary_name,
            )
            continue

        lib_key = result.binary_name or "unknown"
        for fn in ssl_functions:
            func_key = SSL_FUNC_KEY.get(fn.function_type, fn.function_type)
            entry = {lib_key: {arch: {func_key: [fn.byte_pattern]}}}
            merge_patterns(patterns, entry)

    patterns["_meta"] = {
        "generator": "BoringSecretHunter",
        "version": __version__,
        "format": "friTap pattern format v1",
        "note": "Keys starting with '_' are ignored by friTap. Consume with: "
        "fritap --patterns <this file>",
        "binaries": binaries_meta,
    }
    return patterns


def has_patterns(patterns: dict) -> bool:
    """Return True if the dict contains at least one real (non-``_``) library."""
    return any(not key.startswith("_") for key in patterns)


def write_patterns_file(patterns: dict, out_path: Path) -> bool:
    """Write the pattern dict to ``out_path`` as indented JSON.

    Creates parent directories as needed. Skips writing entirely when there are
    no real patterns (only ``_meta``), so an empty/misleading file is never
    produced. Returns True if a file was written.
    """
    # Resolve to an absolute path so the logged location is unambiguous on the
    # host (e.g. /Users/.../results/patterns.json, not a bare "results/...").
    out_path = Path(out_path).resolve()
    if not has_patterns(patterns):
        log.info("No patterns found; not writing %s", out_path)
        return False

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(patterns, indent=2))
    log.info("Patterns written to %s", out_path)
    return True
