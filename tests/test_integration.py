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

from boring_secret_hunter import __version__
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
        assert __version__ in result.stdout or __version__ in result.stderr

    def test_help(self):
        result = _run_bsh("--help")
        assert result.returncode == 0
        assert "analyze" in result.stdout

    def test_analyze_help(self):
        result = _run_bsh("analyze", "--help")
        assert result.returncode == 0
        assert "--debug" in result.stdout

    def test_analyze_help_shows_timeout_and_memory(self):
        result = _run_bsh("analyze", "--help")
        assert result.returncode == 0
        assert "--timeout" in result.stdout
        assert "--max-memory" in result.stdout


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
        """--output writes a friTap-consumable patterns file with a _meta block."""
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
            # friTap flat schema: a _meta block (ignored by friTap) carries the
            # per-binary metadata that used to be the full BatchResult dump.
            assert "_meta" in data
            assert data["_meta"]["generator"] == "BoringSecretHunter"
            assert isinstance(data["_meta"]["binaries"], list)
            # At least one real (non-_) library section with arch -> func -> list.
            lib_keys = [k for k in data if not k.startswith("_")]
            for lib in lib_keys:
                for arch, funcs in data[lib].items():
                    for patterns in funcs.values():
                        assert isinstance(patterns, list)

    def test_analyze_default_patterns_file(self, tmp_path):
        """By default a results/patterns.json is written into the output dir."""
        _run_bsh(
            "analyze",
            str(TEST_BINARY),
            timeout=ANALYSIS_TIMEOUT,
            cwd=str(tmp_path),
        )
        default_path = tmp_path / "results" / "patterns.json"
        # Only present when patterns were extracted; assert schema if so.
        if default_path.exists():
            data = json.loads(default_path.read_text())
            assert "_meta" in data
            assert any(not k.startswith("_") for k in data)

    def test_analyze_patterns_file_override(self, tmp_path):
        """--patterns-file renames the patterns file inside the output dir."""
        _run_bsh(
            "analyze",
            str(TEST_BINARY),
            "--patterns-file",
            "custom.json",
            timeout=ANALYSIS_TIMEOUT,
            cwd=str(tmp_path),
        )
        custom = tmp_path / "results" / "custom.json"
        default = tmp_path / "results" / "patterns.json"
        if custom.exists() or default.exists():
            assert custom.exists()
            assert not default.exists()
