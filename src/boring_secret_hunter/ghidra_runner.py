"""Wrap Ghidra analyzeHeadless subprocess invocation."""

import logging
import os
import subprocess
import tempfile
import shutil
from pathlib import Path
from typing import List, Optional

from boring_secret_hunter.config import get_analyze_headless, get_ghidra_scripts_dir

log = logging.getLogger(__name__)

_SCRIPT_MARKER = "BoringSecretHunter"
_SCRIPT_END_MARKER = "Thx for using BoringSecretHunter"


class GhidraError(Exception):
    """Raised when Ghidra analysis fails."""


def run_analysis(
    binary_path: Path,
    ghidra_dir: str,
    extra_args: Optional[List[str]] = None,
    debug: bool = False,
    large_dump_mode: Optional[str] = None,
    timeout: int = 3600,
) -> str:
    """Run Ghidra headless analysis on a binary.

    Args:
        binary_path: Path to the binary to analyze
        ghidra_dir: Path to Ghidra installation directory
        extra_args: Additional args (e.g. -processor, -loader)
        debug: Enable debug output
        large_dump_mode: Mode for large dumps ('normal', 'fast', 'skip')
        timeout: Subprocess timeout in seconds

    Returns:
        Raw stdout+stderr output from Ghidra

    Raises:
        GhidraError: If Ghidra invocation fails
    """
    analyze_headless = get_analyze_headless(ghidra_dir)
    if not analyze_headless:
        raise GhidraError(f"analyzeHeadless not found in {ghidra_dir}")

    scripts_dir = get_ghidra_scripts_dir()
    prescript = scripts_dir / "MinimalAnalysisOption.java"
    postscript = scripts_dir / "BoringSecretHunter.java"
    log4j_config = scripts_dir / "custom_log4j.xml"

    if not prescript.exists() or not postscript.exists():
        raise GhidraError(f"Ghidra scripts not found in {scripts_dir}")

    # Create a unique temporary project directory and derive name from it
    project_dir = tempfile.mkdtemp(prefix="bsh_ghidra_")
    project_name = Path(project_dir).name

    # Ensure analyzeHeadless and its helper scripts (e.g. launch.sh) are executable
    analyze_path = Path(analyze_headless)
    support_dir = analyze_path.parent
    for script in [analyze_path] + list(support_dir.glob("*.sh")):
        if not os.access(script, os.X_OK):
            os.chmod(script, script.stat().st_mode | 0o755)

    # Run directly to honor the #!/usr/bin/env bash shebang
    cmd = [
        analyze_headless,
        project_dir,
        project_name,
        "-import",
        str(binary_path),
        "-scriptPath",
        str(scripts_dir),
        "-prescript",
        str(prescript),
        "-postScript",
        str(postscript),
    ]

    # Add script arguments (passed as postScript args)
    script_args = []
    if debug:
        script_args.append("DEBUG_RUN=true")
    if large_dump_mode and large_dump_mode in ("normal", "fast"):
        script_args.append(f"LARGE_DUMP_MODE={large_dump_mode}")

    if script_args:
        cmd.extend(script_args)

    # Add extra args (e.g. -processor AARCH64:LE:64:v8A -loader BinaryLoader)
    if extra_args:
        cmd.extend(extra_args)

    # Set up environment with log4j config to suppress noisy output
    env = os.environ.copy()
    if log4j_config.exists():
        log4j_uri = log4j_config.as_uri()
        existing = env.get("JAVA_TOOL_OPTIONS", "")
        log4j_opt = f"-Dlog4j.configurationFile={log4j_uri}"
        if log4j_opt not in existing:
            env["JAVA_TOOL_OPTIONS"] = f"{existing} {log4j_opt}".strip()

    log.debug("Running: %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
        output = result.stdout

        if result.returncode != 0:
            log.warning("analyzeHeadless exited with code %d", result.returncode)
        if debug and result.stderr:
            log.debug("Ghidra stderr:\n%s", result.stderr)

        return output
    except subprocess.TimeoutExpired:
        raise GhidraError(f"Ghidra analysis timed out after {timeout}s")
    except OSError as e:
        raise GhidraError(f"Failed to run analyzeHeadless: {e}")
    finally:
        # Clean up project directory
        shutil.rmtree(project_dir, ignore_errors=True)


def parse_output(raw_output: str) -> str:
    """Extract BoringSecretHunter-relevant lines from Ghidra output.

    Filters output between the BoringSecretHunter script markers,
    matching the sed pattern from ghidra_analysis.sh:
        sed -n '/BoringSecretHunter/,/Thx for using BoringSecretHunter/p'
    """
    lines = raw_output.splitlines()
    filtered = []
    capturing = False

    for line in lines:
        if _SCRIPT_MARKER in line and not capturing:
            capturing = True
        if capturing:
            # Strip Ghidra log prefixes like "INFO  BoringSecretHunter.java> "
            clean = line
            tag = f"{_SCRIPT_MARKER}.java>"
            if tag in clean:
                idx = clean.index(tag)
                clean = clean[idx + len(tag) :].strip()
            elif "INFO  " in clean:
                clean = clean.split("INFO  ", 1)[-1].strip()
            filtered.append(clean)
            if _SCRIPT_END_MARKER in line:
                break

    return "\n".join(filtered)
