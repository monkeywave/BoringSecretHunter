"""Logging setup and dependency checking utilities."""

import logging
import sys
from typing import Tuple

from boring_secret_hunter.config import (
    find_ghidra,
    get_analyze_headless,
    find_java,
    get_java_version,
)


log = logging.getLogger(__name__)

# ANSI color codes
_COLORS = {
    "green": "\033[92m",
    "yellow": "\033[93m",
    "red": "\033[91m",
    "cyan": "\033[96m",
    "bold": "\033[1m",
    "reset": "\033[0m",
}


def supports_color() -> bool:
    """Check if the terminal supports color output."""
    if not hasattr(sys.stdout, "isatty"):
        return False
    return sys.stdout.isatty()


def color(text: str, color_name: str) -> str:
    """Apply ANSI color to text if terminal supports it."""
    if not supports_color():
        return text
    return f"{_COLORS.get(color_name, '')}{text}{_COLORS['reset']}"


def setup_logging(debug: bool = False) -> None:
    """Configure logging for the application."""
    level = logging.DEBUG if debug else logging.INFO
    fmt = (
        "[%(levelname).1s] %(message)s"
        if not debug
        else "[%(levelname)s] %(name)s: %(message)s"
    )
    logging.basicConfig(level=level, format=fmt, stream=sys.stderr)


def check_dependencies(ghidra_path: str = None) -> Tuple[bool, str]:
    """Check that all required dependencies are available.

    Returns:
        Tuple of (all_ok, status_message)
    """
    lines = []
    all_ok = True

    # Check Java
    java_path = find_java()
    if java_path:
        version = get_java_version(java_path) or "unknown version"
        lines.append(f"  {color('[OK]', 'green')} Java: {java_path} ({version})")
    else:
        lines.append(f"  {color('[MISSING]', 'red')} Java: not found (need JDK 17+)")
        all_ok = False

    # Check Ghidra
    ghidra_dir = find_ghidra(ghidra_path)
    if ghidra_dir:
        analyze = get_analyze_headless(ghidra_dir)
        if analyze:
            lines.append(f"  {color('[OK]', 'green')} Ghidra: {ghidra_dir}")
            lines.append(f"         analyzeHeadless: {analyze}")
        else:
            lines.append(
                f"  {color('[ERROR]', 'red')} Ghidra dir found but analyzeHeadless missing: {ghidra_dir}"
            )
            all_ok = False
    else:
        lines.append(f"  {color('[MISSING]', 'red')} Ghidra: not found")
        lines.append("         Set GHIDRA_INSTALL_DIR or use: bsh setup-ghidra")
        all_ok = False

    status = "\n".join(lines)
    return all_ok, status
