"""Tests for the public library API surface, thread safety, and no-stdout guarantee."""

import io
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch, MagicMock


import boring_secret_hunter


class TestPublicAPI:
    """All __all__ symbols are importable and have the expected types."""

    def test_all_symbols_importable(self):
        for name in boring_secret_hunter.__all__:
            obj = getattr(boring_secret_hunter, name)
            assert obj is not None, f"{name} resolved to None"

    def test_analyze_is_callable(self):
        assert callable(boring_secret_hunter.analyze)

    def test_analyze_binary_is_callable(self):
        assert callable(boring_secret_hunter.analyze_binary)

    def test_analyze_parallel_is_callable(self):
        assert callable(boring_secret_hunter.analyze_parallel)

    def test_discover_binaries_is_callable(self):
        assert callable(boring_secret_hunter.discover_binaries)

    def test_find_ghidra_is_callable(self):
        assert callable(boring_secret_hunter.find_ghidra)

    def test_find_java_is_callable(self):
        assert callable(boring_secret_hunter.find_java)

    def test_classify_binary_is_callable(self):
        assert callable(boring_secret_hunter.classify_binary)

    def test_analysis_result_is_dataclass(self):
        r = boring_secret_hunter.AnalysisResult()
        assert hasattr(r, "binary_name")
        assert hasattr(r, "success")

    def test_batch_result_is_dataclass(self):
        r = boring_secret_hunter.BatchResult()
        assert hasattr(r, "total")
        assert hasattr(r, "results")

    def test_function_match_is_dataclass(self):
        r = boring_secret_hunter.FunctionMatch()
        assert hasattr(r, "label")
        assert hasattr(r, "ghidra_offset")

    def test_binary_type_is_enum(self):
        assert hasattr(boring_secret_hunter.BinaryType, "ELF")
        assert hasattr(boring_secret_hunter.BinaryType, "MACHO")

    def test_ghidra_error_is_exception(self):
        assert issubclass(boring_secret_hunter.GhidraError, Exception)


class TestAnalyzeNoStdout:
    """analyze() must not write to stdout; output goes through the callback."""

    def test_no_stdout_on_success(self, tmp_path):
        """When analyze() finds a successful result, stdout stays clean."""
        binary = tmp_path / "test.so"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)

        callback_calls = []

        def _capture(result, parsed):
            callback_calls.append((result, parsed))

        fake_raw = (
            "INFO  BoringSecretHunter.java> BoringSecretHunter start\n"
            "INFO  BoringSecretHunter.java> Function Label: ssl_log_secret\n"
            "INFO  BoringSecretHunter.java> Thx for using BoringSecretHunter\n"
        )

        with patch("boring_secret_hunter.analyzer.run_analysis", return_value=fake_raw):
            captured = io.StringIO()
            old_stdout = sys.stdout
            sys.stdout = captured
            try:
                result = boring_secret_hunter.analyze(
                    path=binary,
                    ghidra_dir="/fake/ghidra",
                    on_result=_capture,
                )
            finally:
                sys.stdout = old_stdout

        assert captured.getvalue() == "", "analyze() must not print to stdout"
        assert len(callback_calls) == 1, "callback should have been called once"
        assert result.successful == 1

    def test_no_callback_no_crash(self, tmp_path):
        """analyze() works fine without a callback (on_result=None)."""
        binary = tmp_path / "test.so"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)

        fake_raw = (
            "INFO  BoringSecretHunter.java> BoringSecretHunter start\n"
            "INFO  BoringSecretHunter.java> Function Label: ssl_log_secret\n"
            "INFO  BoringSecretHunter.java> Thx for using BoringSecretHunter\n"
        )

        with patch("boring_secret_hunter.analyzer.run_analysis", return_value=fake_raw):
            result = boring_secret_hunter.analyze(
                path=binary,
                ghidra_dir="/fake/ghidra",
            )

        assert result.successful == 1


class TestGhidraRunnerProjectName:
    """Concurrent run_analysis calls must get distinct project directories."""

    def test_unique_project_dirs(self):
        """mkdtemp guarantees uniqueness even when called concurrently."""
        from boring_secret_hunter.ghidra_runner import run_analysis

        captured_dirs = []

        original_mkdtemp = tempfile.mkdtemp

        def _spy_mkdtemp(**kwargs):
            d = original_mkdtemp(**kwargs)
            captured_dirs.append(d)
            return d

        with (
            patch(
                "boring_secret_hunter.ghidra_runner.tempfile.mkdtemp",
                side_effect=_spy_mkdtemp,
            ),
            patch(
                "boring_secret_hunter.ghidra_runner.get_analyze_headless",
                return_value="/fake/bin",
            ),
            patch(
                "boring_secret_hunter.ghidra_runner.get_ghidra_scripts_dir"
            ) as mock_scripts,
        ):
            scripts_dir = MagicMock()
            prescript = MagicMock()
            prescript.exists.return_value = True
            postscript = MagicMock()
            postscript.exists.return_value = True
            scripts_dir.__truediv__ = (
                lambda self, name: prescript if "Minimal" in str(name) else postscript
            )
            log4j = MagicMock()
            log4j.exists.return_value = False

            # Make / operator return the right mocks
            def _truediv(name):
                if "Minimal" in str(name):
                    return prescript
                if "Boring" in str(name):
                    return postscript
                return log4j

            scripts_dir.__truediv__ = _truediv
            mock_scripts.return_value = scripts_dir

            with patch("subprocess.run", side_effect=OSError("not a real ghidra")):

                def _call(i):
                    try:
                        run_analysis(Path(f"/fake/binary_{i}"), "/fake/ghidra")
                    except Exception:
                        pass

                with ThreadPoolExecutor(max_workers=8) as pool:
                    list(pool.map(_call, range(20)))

        # All captured directories must be unique
        assert len(captured_dirs) == len(set(captured_dirs)), (
            f"Duplicate project dirs: {captured_dirs}"
        )


class TestThreadSafety:
    """classify_binary and discover_binaries are safe under concurrent calls."""

    def test_classify_binary_concurrent(self, tmp_path):
        files = []
        for i in range(20):
            f = tmp_path / f"bin_{i}.so"
            f.write_bytes(b"\x7fELF" + bytes([i]) * 100)
            files.append(f)

        with ThreadPoolExecutor(max_workers=20) as pool:
            results = list(pool.map(boring_secret_hunter.classify_binary, files))

        assert all(r == boring_secret_hunter.BinaryType.ELF for r in results)

    def test_discover_binaries_concurrent(self, tmp_path):
        dirs = []
        for i in range(10):
            d = tmp_path / f"dir_{i}"
            d.mkdir()
            f = d / "lib.so"
            f.write_bytes(b"\x7fELF" + b"\x00" * 100)
            dirs.append(d)

        with ThreadPoolExecutor(max_workers=10) as pool:
            results = list(pool.map(boring_secret_hunter.discover_binaries, dirs))

        for binaries in results:
            assert len(binaries) == 1
            assert binaries[0].name == "lib.so"
