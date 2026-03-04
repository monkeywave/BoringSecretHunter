"""CLI entry point for BoringSecretHunter (bsh command)."""

import argparse
import logging
import sys
from pathlib import Path

from boring_secret_hunter import __version__

log = logging.getLogger(__name__)


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

    def _print_result(result, parsed):
        print(parsed)
        print()

    result = analyze(
        path=target,
        ghidra_dir=ghidra_dir,
        debug=args.debug,
        large_dump_mode=args.large_dump_mode,
        processor_override=args.processor,
        on_result=_print_result,
    )

    # JSON output
    if args.output:
        output_path = Path(args.output)
        output_path.write_text(result.to_json())
        log.info("Results written to %s", output_path)

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
        "--output",
        "-o",
        help="Write results to JSON file",
    )
    analyze_parser.set_defaults(func=cmd_analyze)

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
