"""Ghidra and Java path discovery and configuration."""

import os
import platform
import shutil
import configparser
from pathlib import Path
from typing import Optional
import glob as glob_mod


CONFIG_DIR = Path.home() / ".boring-secret-hunter"
CONFIG_FILE = CONFIG_DIR / "config"

# Common Ghidra install locations per platform
_GHIDRA_SEARCH_PATHS = {
    "Darwin": [
        "/opt/ghidra*/",
        "/usr/local/share/ghidra*/",
        Path.home() / "ghidra*/",
        "/Applications/ghidra*/",
        Path.home() / "Applications/ghidra*/",
    ],
    "Linux": [
        "/opt/ghidra*/",
        "/usr/local/share/ghidra*/",
        "/usr/share/ghidra*/",
        Path.home() / "ghidra*/",
    ],
    "Windows": [
        Path("C:/") / "ghidra*/",
        Path("C:/Program Files") / "ghidra*/",
        Path.home() / "ghidra*/",
    ],
}


def _read_config_file() -> Optional[str]:
    """Read Ghidra install dir from config file."""
    if not CONFIG_FILE.exists():
        return None
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    path = config.get("ghidra", "install_dir", fallback=None)
    if path and Path(path).is_dir():
        return path
    return None


def _scan_common_paths() -> Optional[str]:
    """Auto-scan common install locations for Ghidra."""
    system = platform.system()
    search_paths = _GHIDRA_SEARCH_PATHS.get(system, _GHIDRA_SEARCH_PATHS["Linux"])
    candidates = []
    for pattern in search_paths:
        matches = sorted(glob_mod.glob(str(pattern)), reverse=True)
        for match in matches:
            analyze_headless = _find_analyze_headless(match)
            if analyze_headless:
                candidates.append(match)
    return candidates[0] if candidates else None


def _find_analyze_headless(ghidra_dir: str) -> Optional[str]:
    """Find the analyzeHeadless script within a Ghidra installation."""
    ghidra_path = Path(ghidra_dir)
    for name in ["analyzeHeadless", "analyzeHeadless.bat"]:
        candidate = ghidra_path / "support" / name
        if candidate.is_file():
            return str(candidate)
    return None


def find_ghidra(cli_path: Optional[str] = None) -> Optional[str]:
    """Find Ghidra installation directory.

    Search order:
    1. Explicit CLI argument
    2. GHIDRA_INSTALL_DIR environment variable
    3. Config file (~/.boring-secret-hunter/config)
    4. Auto-scan common paths
    """
    # 1. CLI argument
    if cli_path and Path(cli_path).is_dir():
        return cli_path

    # 2. Environment variable
    env_path = os.environ.get("GHIDRA_INSTALL_DIR")
    if env_path and Path(env_path).is_dir():
        return env_path

    # 3. Config file
    config_path = _read_config_file()
    if config_path:
        return config_path

    # 4. Auto-scan
    return _scan_common_paths()


def get_analyze_headless(ghidra_dir: str) -> Optional[str]:
    """Get path to analyzeHeadless script."""
    return _find_analyze_headless(ghidra_dir)


def find_java() -> Optional[str]:
    """Find Java installation. Returns path to java binary or None."""
    # Check JAVA_HOME first
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        java_bin = Path(java_home) / "bin" / "java"
        if java_bin.is_file():
            return str(java_bin)

    # Fall back to PATH
    java_path = shutil.which("java")
    return java_path


def get_java_version(java_path: str) -> Optional[str]:
    """Get Java version string."""
    import subprocess

    try:
        result = subprocess.run(
            [java_path, "-version"], capture_output=True, text=True, timeout=10
        )
        output = result.stderr or result.stdout
        for line in output.splitlines():
            if "version" in line.lower():
                return line.strip()
    except (subprocess.SubprocessError, OSError):
        pass
    return None


def save_config(ghidra_dir: str) -> None:
    """Save Ghidra installation path to config file."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    config = configparser.ConfigParser()
    config["ghidra"] = {"install_dir": ghidra_dir}
    with open(CONFIG_FILE, "w") as f:
        config.write(f)


def get_ghidra_scripts_dir() -> Path:
    """Get path to bundled Ghidra scripts (package data)."""
    return Path(__file__).parent / "ghidra_scripts"
