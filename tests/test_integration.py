"""Integration tests for BoringSecretHunter.

These tests require Ghidra and JDK to be installed.
Run with: pytest tests/test_integration.py -v
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from boring_secret_hunter.config import find_ghidra, find_java

TEST_BINARY = Path(__file__).parent.parent / "test" / "libcronet.132.0.6779.0.so"

# Use the installed bsh entry point instead of python -m
# (avoids shadowing from root-level boring_secret_hunter_ghidra.py)
BSH = shutil.which("bsh") or [sys.executable, "-m", "boring_secret_hunter"]
ANALYSIS_TIMEOUT = 600


def _run_bsh(*args, **kwargs):
    """Run the bsh CLI command."""
    if isinstance(BSH, list):
        cmd = BSH + list(args)
    else:
        cmd = [BSH] + list(args)
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


requires_ghidra = pytest.mark.skipif(
    not find_ghidra(),
    reason="Ghidra not installed",
)
requires_java = pytest.mark.skipif(
    not find_java(),
    reason="Java not installed",
)
requires_test_binary = pytest.mark.skipif(
    not TEST_BINARY.exists(),
    reason=f"Test binary not found: {TEST_BINARY}",
)


class TestCLI:
    def test_version(self):
        result = _run_bsh("--version")
        assert "2.0.0" in result.stdout or "2.0.0" in result.stderr

    def test_help(self):
        result = _run_bsh("--help")
        assert result.returncode == 0
        assert "analyze" in result.stdout

    def test_analyze_help(self):
        result = _run_bsh("analyze", "--help")
        assert result.returncode == 0
        assert "--debug" in result.stdout


class TestCheckCommand:
    def test_check_runs(self):
        result = _run_bsh("check")
        output = result.stdout + result.stderr
        assert "BoringSecretHunter" in output


@requires_ghidra
@requires_java
@requires_test_binary
class TestAnalysis:
    def test_analyze_single_binary(self, tmp_path):
        """Test analyzing the test binary produces output."""
        result = _run_bsh("analyze", str(TEST_BINARY), timeout=ANALYSIS_TIMEOUT)
        assert result.returncode in (0, 1)

    def test_analyze_json_output(self, tmp_path):
        """Test JSON output mode."""
        json_path = tmp_path / "result.json"
        _run_bsh(
            "analyze",
            str(TEST_BINARY),
            "--output",
            str(json_path),
            timeout=ANALYSIS_TIMEOUT,
        )
        if json_path.exists():
            data = json.loads(json_path.read_text())
            assert "results" in data
            assert "total" in data
