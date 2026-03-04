"""BoringSecretHunter - Extract ssl_log_secret() offsets from BoringSSL/RustLS binaries."""

from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("BoringSecretHunter")
except PackageNotFoundError:
    __version__ = "0.0.0-dev"

from boring_secret_hunter.analyzer import (
    analyze,
    analyze_binary,
    analyze_parallel,
    discover_binaries,
)
from boring_secret_hunter.binary_classifier import BinaryType, classify_binary
from boring_secret_hunter.config import find_ghidra, find_java
from boring_secret_hunter.ghidra_runner import GhidraError
from boring_secret_hunter.result import AnalysisResult, BatchResult, FunctionMatch

__all__ = [
    "__version__",
    # Analysis
    "analyze",
    "analyze_binary",
    "analyze_parallel",
    "discover_binaries",
    # Data models
    "AnalysisResult",
    "BatchResult",
    "FunctionMatch",
    # Config helpers
    "find_ghidra",
    "find_java",
    # Classification
    "BinaryType",
    "classify_binary",
    # Errors
    "GhidraError",
]
