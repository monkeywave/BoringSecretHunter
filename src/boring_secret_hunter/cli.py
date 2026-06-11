"""CLI entry point for BoringSecretHunter (bsh command)."""

import argparse
import logging
import os
import sys
from pathlib import Path

from boring_secret_hunter import __version__

log = logging.getLogger(__name__)

# Default name for the friTap-consumable pattern file. Overridable via the
# --patterns-file CLI flag or the PATTERNS_FILE environment variable (the env
# var is how the Docker entrypoint receives the override, since its own flags
# are consumed by the container entrypoint).
DEFAULT_PATTERNS_FILENAME = "patterns.json"
DEFAULT_OUTPUT_DIR = "results"


def _resolve_patterns_filename(args) -> str:
    """Resolve the patterns filename: --patterns-file > $PATTERNS_FILE > default."""
    return (
        getattr(args, "patterns_file", None)
        or os.environ.get("PATTERNS_FILE")
        or DEFAULT_PATTERNS_FILENAME
    )


def cmd_analyze(args):
    """Run analysis on binary/archive/directory."""
    from boring_secret_hunter.analyzer import analyze
    from boring_secret_hunter.config import find_ghidra
    from boring_secret_hunter.utils import setup_logging

    setup_logging(debug=args.debug)

    # Resolve Ghidra
    ghidra_dir = find_ghidra(args.ghidra_path)
    if not ghidra_dir:
        print(
            "Error: Ghidra installation not found.\n"
            "  Set GHIDRA_INSTALL_DIR environment variable, or\n"
            "  Use --ghidra-path /path/to/ghidra, or\n"
            "  Run: bsh setup-ghidra",
            file=sys.stderr,
        )
        sys.exit(1)

    target = Path(args.target)
    if not target.exists():
        print(f"Error: Path not found: {target}", file=sys.stderr)
        sys.exit(1)

    if args.no_symbols and args.strategy == "SymbolTableLookup":
        print(
            "Error: --no-symbols and --strategy SymbolTableLookup are mutually exclusive.",
            file=sys.stderr,
        )
        sys.exit(1)

    # --no-symbols and --strategy only make sense with SSL_read/SSL_write scanning
    find_ssl_rw = args.find_ssl_rw
    if not find_ssl_rw and (args.no_symbols or args.strategy):
        find_ssl_rw = True
        print(
            "Info: --find-ssl-rw implied by "
            + ("--no-symbols" if args.no_symbols else f"--strategy {args.strategy}")
            + ".",
            file=sys.stderr,
        )

    def _print_result(result, parsed):
        print(parsed)
        print()

    # 0 (or unset) means "no timeout"; an empty --max-memory keeps the host default.
    timeout = args.timeout or None
    max_memory = args.max_memory or None

    result = analyze(
        path=target,
        ghidra_dir=ghidra_dir,
        debug=args.debug,
        large_dump_mode=args.large_dump_mode,
        processor_override=args.processor,
        no_symbols=args.no_symbols,
        strategy=args.strategy,
        find_ssl_rw=find_ssl_rw,
        find_quiche=args.find_quiche,
        timeout=timeout,
        max_memory=max_memory,
        on_result=_print_result,
    )

    # friTap-consumable patterns.json. Always written by default when there are
    # results: to the explicit --output path if given, otherwise to
    # <output-dir>/<patterns-file> (default ./results/patterns.json). --output
    # (or --debug) additionally embeds the full raw Ghidra output in _meta.
    from boring_secret_hunter.patterns_export import (
        build_fritap_patterns,
        write_patterns_file,
    )

    patterns = build_fritap_patterns(
        result.results, include_raw_output=bool(args.output or args.debug)
    )
    if args.output:
        patterns_path = Path(args.output)
    else:
        patterns_path = Path(args.output_dir) / _resolve_patterns_filename(args)
    if not write_patterns_file(patterns, patterns_path):
        log.info("No patterns extracted — %s was not created.", patterns_path.resolve())

    # Summary
    if result.total == 0:
        print("No binaries found to analyze.", file=sys.stderr)
        sys.exit(1)

    print(
        f"\nAnalysis complete: {result.successful}/{result.total} binaries produced results.",
        file=sys.stderr,
    )

    if result.successful == 0:
        sys.exit(1)


def cmd_export_patterns(args):
    """Build a friTap patterns file from pre-parsed BoringSecretHunter output.

    Used by the Docker entrypoint, which runs Ghidra itself and only has the
    filtered (parsed) text per binary. The manifest is a TSV file with one
    `binary_path<TAB>parsed_text_path` line per analysed binary.
    """
    from boring_secret_hunter.analyzer import result_from_parsed_output
    from boring_secret_hunter.patterns_export import (
        build_fritap_patterns,
        write_patterns_file,
    )
    from boring_secret_hunter.utils import setup_logging

    setup_logging(debug=args.debug)

    manifest_path = Path(args.manifest)
    if not manifest_path.is_file():
        print(f"Error: manifest not found: {manifest_path}", file=sys.stderr)
        sys.exit(1)

    results = []
    for line in manifest_path.read_text().splitlines():
        if not line.strip():
            continue
        binary_path, _, parsed_path = line.partition("\t")
        if not parsed_path:
            log.warning("Skipping malformed manifest line: %r", line)
            continue
        parsed_text = ""
        parsed_file = Path(parsed_path)
        if parsed_file.is_file():
            parsed_text = parsed_file.read_text()
        results.append(
            result_from_parsed_output(Path(binary_path), parsed_text)
        )

    patterns = build_fritap_patterns(results, include_raw_output=args.debug)
    if not write_patterns_file(patterns, Path(args.output)):
        log.info("No patterns extracted — %s was not created.", args.output)


def cmd_check(args):
    """Check that all dependencies are available."""
    from boring_secret_hunter.utils import check_dependencies, setup_logging

    setup_logging(debug=False)

    print(f"BoringSecretHunter v{__version__}")
    print("Checking dependencies...\n")

    all_ok, status = check_dependencies(getattr(args, "ghidra_path", None))
    print(status)

    if all_ok:
        print("\nAll dependencies found. Ready to analyze.")
    else:
        print(
            "\nSome dependencies are missing. See above for details.", file=sys.stderr
        )
        sys.exit(1)


def cmd_setup_ghidra(args):
    """Download and install Ghidra."""
    from boring_secret_hunter.config import find_java, find_ghidra, save_config
    from boring_secret_hunter.utils import setup_logging

    setup_logging(debug=False)

    # Check Java first
    java_path = find_java()
    if not java_path:
        print(
            "Error: Java (JDK 17+) is required but not found.\n"
            "  Install from: https://adoptium.net/",
            file=sys.stderr,
        )
        sys.exit(1)

    # Check if Ghidra already exists
    existing = find_ghidra()
    if existing:
        print(f"Ghidra already found at: {existing}")
        save = input("Save this path to config? [Y/n] ").strip().lower()
        if save != "n":
            save_config(existing)
            print("Saved to ~/.boring-secret-hunter/config")
        return

    print("Ghidra not found. Download options:\n")
    print(
        "  1. Download from: https://github.com/NationalSecurityAgency/ghidra/releases"
    )
    print("  2. Extract the archive to a directory (e.g. /opt/ghidra_12.0.3_PUBLIC)")
    print("  3. Then either:")
    print("     a) Set GHIDRA_INSTALL_DIR=/path/to/ghidra")
    print("     b) Run: bsh setup-ghidra  (to save the path)")
    print()

    ghidra_path = (
        input("Enter Ghidra installation path (or press Enter to skip): ")
        .strip()
        .strip("\"'")
    )
    if ghidra_path and Path(ghidra_path).is_dir():
        save_config(ghidra_path)
        print(f"Saved Ghidra path: {ghidra_path}")
    elif ghidra_path:
        print(f"Error: Directory not found: {ghidra_path}", file=sys.stderr)
        sys.exit(1)


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="bsh",
        description="BoringSecretHunter — Extract ssl_log_secret() offsets from BoringSSL/RustLS binaries",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # analyze subcommand
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze binary, archive (APK/IPA/ZIP), or directory",
        description=(
            "Analyze a binary, archive (APK/IPA/ZIP), or directory for "
            "ssl_log_secret() offsets. Pass --find-ssl-rw to additionally "
            "locate SSL_read / SSL_write (currently under development)."
        ),
    )
    analyze_parser.add_argument(
        "target",
        help="Path to binary, archive, or directory containing binaries",
    )
    analyze_parser.add_argument(
        "--debug",
        "-d",
        action="store_true",
        help="Enable verbose debug output",
    )
    analyze_parser.add_argument(
        "--ghidra-path",
        help="Path to Ghidra installation directory",
    )
    analyze_parser.add_argument(
        "--large-dump-mode",
        choices=["normal", "fast", "skip"],
        default=None,
        help="Mode for handling large (>100MB) raw data dumps",
    )
    analyze_parser.add_argument(
        "--processor",
        help="Override Ghidra processor (e.g. AARCH64:LE:64:v8A)",
    )
    analyze_parser.add_argument(
        "--timeout",
        type=int,
        default=None,
        metavar="SECONDS",
        help=(
            "Maximum seconds to wait for Ghidra per binary. Default: no timeout "
            "(0 also means unlimited). Set a positive value to abort runaway "
            "analyses of very large binaries."
        ),
    )
    analyze_parser.add_argument(
        "--max-memory",
        default="5G",
        metavar="SIZE",
        help=(
            "Ghidra JVM max heap, e.g. 5G or 4096m (default: 5G, matching the "
            "Docker image). Larger binaries analyze faster with more heap; pass "
            "an empty value to keep the host Ghidra default. On hosts with less "
            "than 5 GB free RAM the JVM may fail to start — lower it (e.g. "
            "--max-memory 2G)."
        ),
    )
    analyze_parser.add_argument(
        "--output",
        "-o",
        help=(
            "Explicit path for the friTap patterns JSON file (overrides "
            "--output-dir/--patterns-file). Also embeds the full raw Ghidra "
            "output under the file's _meta block for debugging."
        ),
    )
    analyze_parser.add_argument(
        "--output-dir",
        default=DEFAULT_OUTPUT_DIR,
        help=(
            "Directory for the patterns file when --output is not given "
            f"(default: ./{DEFAULT_OUTPUT_DIR})"
        ),
    )
    analyze_parser.add_argument(
        "--patterns-file",
        default=None,
        help=(
            "Filename for the friTap patterns JSON inside --output-dir "
            f"(default: {DEFAULT_PATTERNS_FILENAME}; also settable via the "
            "PATTERNS_FILE environment variable)"
        ),
    )
    analyze_parser.add_argument(
        "--no-symbols",
        action="store_true",
        help=(
            "[Under development] Skip symbol-based identification for "
            "SSL_read/SSL_write (test pattern matching on non-stripped "
            "binaries; implies --find-ssl-rw)"
        ),
    )
    analyze_parser.add_argument(
        "--strategy",
        choices=[
            "SymbolTableLookup",
            "ErrorStringFingerprinting",
            "NumericErrorCodeFingerprinting",
            "CallGraphTracing",
            "AdjacentFunctionScanning",
            "ConstantFingerprinting",
            "FunctionSignatureAnalysis",
            "ErrorCodeTableScan",
        ],
        help=(
            "[Under development] Use only the specified strategy for "
            "SSL_read/SSL_write identification (implies --find-ssl-rw)"
        ),
    )
    analyze_parser.add_argument(
        "--find-ssl-rw",
        action="store_true",
        default=False,
        help=(
            "[Under development] Also identify SSL_read / SSL_write functions "
            "(off by default; experimental, may produce false positives)"
        ),
    )
    analyze_parser.add_argument(
        "--find-quiche",
        action="store_true",
        default=False,
        help=(
            "[Under development] Also identify Google QUICHE (Chrome/Cronet HTTP/3) functions: "
            "QuicSpdyStream::WriteOrBufferBody, OnHeadersDecoded, WriteHeaders, "
            "OnDataFramePayload; QuicStreamSequencer::OnStreamFrame, Readv; "
            "net::QuicChromiumClientStream::WriteHeaders; "
            "QuicSpdySession::WriteHeadersOnHeadersStream"
        ),
    )
    analyze_parser.set_defaults(func=cmd_analyze)

    # export-patterns subcommand (used by the Docker entrypoint)
    export_parser = subparsers.add_parser(
        "export-patterns",
        help="Build a friTap patterns JSON from pre-parsed output (internal/Docker)",
        description=(
            "Build a friTap-consumable patterns JSON from already-parsed "
            "BoringSecretHunter output listed in a manifest. Primarily used by "
            "the Docker entrypoint."
        ),
    )
    export_parser.add_argument(
        "--manifest",
        required=True,
        help="TSV file: one 'binary_path<TAB>parsed_text_path' line per binary",
    )
    export_parser.add_argument(
        "--output",
        required=True,
        help="Path to write the friTap patterns JSON file",
    )
    export_parser.add_argument(
        "--debug",
        "-d",
        action="store_true",
        help="Embed raw output in _meta and enable verbose logging",
    )
    export_parser.set_defaults(func=cmd_export_patterns)

    # check subcommand
    check_parser = subparsers.add_parser(
        "check",
        help="Verify Ghidra and JDK are available",
    )
    check_parser.add_argument(
        "--ghidra-path",
        help="Path to Ghidra installation directory",
    )
    check_parser.set_defaults(func=cmd_check)

    # setup-ghidra subcommand
    setup_parser = subparsers.add_parser(
        "setup-ghidra",
        help="Set up Ghidra installation path",
    )
    setup_parser.set_defaults(func=cmd_setup_ghidra)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    args.func(args)
