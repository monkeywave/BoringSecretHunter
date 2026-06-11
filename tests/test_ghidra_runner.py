"""Unit tests for run_analysis timeout + heap plumbing (no Ghidra required).

These mock out the analyzeHeadless invocation and assert that the configurable
timeout and --max-memory heap controls reach the subprocess / JVM correctly.
"""

from pathlib import Path
from unittest import mock

from boring_secret_hunter import ghidra_runner


def _fake_ghidra(tmp_path, monkeypatch):
    """Stub get_analyze_headless / get_ghidra_scripts_dir for a fake install."""
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    (scripts / "MinimalAnalysisOption.java").write_text("")
    (scripts / "BoringSecretHunter.java").write_text("")

    support = tmp_path / "support"
    support.mkdir()
    headless = support / "analyzeHeadless"
    headless.write_text("#!/bin/sh\n")
    headless.chmod(0o755)

    monkeypatch.setattr(ghidra_runner, "get_analyze_headless", lambda d: str(headless))
    monkeypatch.setattr(ghidra_runner, "get_ghidra_scripts_dir", lambda: scripts)


def _capture_run(monkeypatch):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["timeout"] = kwargs.get("timeout")
        captured["env"] = kwargs.get("env")
        return mock.Mock(stdout="ok", returncode=0, stderr="")

    monkeypatch.setattr(ghidra_runner.subprocess, "run", fake_run)
    return captured


def test_default_timeout_is_none(tmp_path, monkeypatch):
    _fake_ghidra(tmp_path, monkeypatch)
    captured = _capture_run(monkeypatch)

    out = ghidra_runner.run_analysis(Path("/bin/ls"), "/ghidra")

    assert out == "ok"
    assert captured["timeout"] is None  # no timeout by default (matches Docker)


def test_explicit_timeout_passes_through(tmp_path, monkeypatch):
    _fake_ghidra(tmp_path, monkeypatch)
    captured = _capture_run(monkeypatch)

    ghidra_runner.run_analysis(Path("/bin/ls"), "/ghidra", timeout=900)

    assert captured["timeout"] == 900


def test_max_memory_injects_xmx_into_java_options(tmp_path, monkeypatch):
    _fake_ghidra(tmp_path, monkeypatch)
    captured = _capture_run(monkeypatch)

    ghidra_runner.run_analysis(Path("/bin/ls"), "/ghidra", max_memory="5G")

    assert "-Xmx5G" in captured["env"]["_JAVA_OPTIONS"]


def test_no_max_memory_leaves_java_options_unset(tmp_path, monkeypatch):
    _fake_ghidra(tmp_path, monkeypatch)
    captured = _capture_run(monkeypatch)
    monkeypatch.delenv("_JAVA_OPTIONS", raising=False)

    ghidra_runner.run_analysis(Path("/bin/ls"), "/ghidra")

    assert "_JAVA_OPTIONS" not in captured["env"]
