#!/usr/bin/env python3
"""
findBoringSSLLibsOnAndroid.py

Scan loaded .so modules in a target Android process for occurrences of:
 - "EXPORTER_SECRET" (primary)
 - "CLIENT_RANDOM"   (fallback)

Usage examples:
  # interactive scan and dump for package
  python3 findBoringSSLLibsOnAndroid.py --package com.example.app

  # non-interactive, dump all matches to ./dumps/
  python3 findBoringSSLLibsOnAndroid.py --package com.example.app --output ./dumps --non-interactive

  # skip scan and dump a specific library by name (must be loaded in process)
  python3 findBoringSSLLibsOnAndroid.py --package com.example.app --library libcronet.132.0.6779.0.so

Dependencies:
  pip install frida-tools colorlog
  adb in PATH is optional (preferred for exact on-disk file pull)
"""
from __future__ import annotations
import argparse
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from typing import Dict, List, Optional, Tuple

# Optional color logging
try:
    import colorlog

    COLORLOG_AVAILABLE = True
except Exception:
    COLORLOG_AVAILABLE = False

# Frida
try:
    import frida
except Exception as e:
    print("ERROR: frida Python package not found or not importable.")
    print("Install frida-tools (which includes frida) via:")
    print("  pip install frida-tools")
    print("Full import error:", repr(e))
    sys.exit(1)


# ---------------------------
# Logging setup
# ---------------------------
def setup_logging(verbose: bool) -> logging.Logger:
    level = logging.DEBUG if verbose else logging.INFO
    logger = logging.getLogger("findBoringSSLLibsOnAndroid")
    logger.setLevel(level)
    if COLORLOG_AVAILABLE:
        handler = colorlog.StreamHandler()
        handler.setFormatter(
            colorlog.ColoredFormatter(
                "%(log_color)s%(levelname)s:%(reset)s %(message)s",
                log_colors={
                    "DEBUG": "cyan",
                    "INFO": "green",
                    "WARNING": "yellow",
                    "ERROR": "red",
                    "CRITICAL": "red",
                },
            )
        )
    else:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    logger.handlers = []
    logger.addHandler(handler)
    return logger


logger = setup_logging(False)  # updated later with args


# ---------------------------
# JS payload (Frida)
# ---------------------------
# Note: this JS tries Memory.readByteArray if available, otherwise falls back to per-byte reads.
JS_PAYLOAD = r"""
'use strict';

rpc.exports = {
  enumerateModules: function() {
    var mods = Process.enumerateModules();
    var out = [];
    for (var i = 0; i < mods.length; i++) {
      var m = mods[i];
      out.push({ name: m.name, path: m.path || "", base: m.base.toString(), size: m.size });
    }
    return out;
  },

  scanModuleForPatterns: function(moduleName, patterns) {
    var m = Process.findModuleByName(moduleName);
    if (!m) {
      throw new Error("Module not found: " + moduleName);
    }
    var found = [];
    for (var i = 0; i < patterns.length; i++) {
      var pat = patterns[i];
      try {
        var res = Memory.scanSync(m.base, m.size, pat);
        if (res && res.length > 0) {
          found.push({ pattern: pat, occurrences: res.length });
        }
      } catch (e) {
        // skip pattern or region read errors
      }
    }
    return found;
  },

  // Robust chunked dump: try readByteArray if available; fallback to reading bytes.
  dumpModuleChunks: function(moduleName, chunkSize) {
    var m = Process.findModuleByName(moduleName);
    if (!m) throw new Error("Module not found: " + moduleName);
    var total = m.size;
    var base = m.base;
    var offset = 0;
    var seq = 0;

    // helper: check functions exist
    var haveReadByteArray = (typeof Memory.readByteArray === 'function');

    while (offset < total) {
      var size = chunkSize;
      if (offset + size > total) size = total - offset;
      try {
        if (haveReadByteArray) {
          // attempt a fast block read
          var buf = Memory.readByteArray(ptr(base).add(offset), size);
          send({ type: 'chunk', module: moduleName, seq: seq, offset: offset, final: (offset + size) >= total }, buf);
        } else {
          // readByteArray not available: do a per-byte read into a Uint8Array
          var arr = new Uint8Array(size);
          for (var i = 0; i < size; i++) {
            arr[i] = Memory.readU8(ptr(base).add(offset + i));
          }
          send({ type: 'chunk', module: moduleName, seq: seq, offset: offset, final: (offset + size) >= total }, arr.buffer);
        }
      } catch (e1) {
        // If block read failed but readByteArray exists, try a byte-wise fallback
        try {
          var arr2 = new Uint8Array(size);
          for (var i2 = 0; i2 < size; i2++) {
            arr2[i2] = Memory.readU8(ptr(base).add(offset + i2));
          }
          send({ type: 'chunk', module: moduleName, seq: seq, offset: offset, final: (offset + size) >= total }, arr2.buffer);
        } catch (e2) {
          send({ type: 'error', module: moduleName, message: 'Memory.read failed at offset ' + offset + ': ' + e2.toString() });
          throw e2;
        }
      }
      offset += size;
      seq += 1;
    }
    return true;
  }
};
"""


# ---------------------------
# Utilities / adb helpers
# ---------------------------
def run_cmd(args: List[str], timeout: int = 60) -> Tuple[int, str]:
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except Exception as e:
        return 1, f"command failed: {e}"


def check_adb() -> bool:
    return shutil.which("adb") is not None


def adb_pull(remote: str, local: str, timeout: int = 180) -> Tuple[bool, str]:
    try:
        os.makedirs(os.path.dirname(local) or ".", exist_ok=True)
        proc = subprocess.run(["adb", "pull", remote, local], capture_output=True, text=True, timeout=timeout)
        out = (proc.stdout or "") + (proc.stderr or "")
        return (proc.returncode == 0, out)
    except Exception as e:
        return False, f"adb pull failed: {e}"


def adb_shell(cmd: str) -> Tuple[int, str]:
    return run_cmd(["adb", "shell", cmd], timeout=60)


def pull_apks_for_package(pkg: str, tmp_dir: str, logger: logging.Logger) -> List[str]:
    """
    Use `adb shell pm path <pkg>` to list APKs, pull them to tmp_dir, and return list of local APK paths.
    """
    ret, out = adb_shell(f"pm path {pkg}")
    if ret != 0:
        logger.warning("Failed to list package apk paths via 'pm path'. Output: %s", out.strip())
        return []

    apk_paths = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("package:"):
            remote_path = line.split("package:", 1)[1]
            local_apk = os.path.join(tmp_dir, os.path.basename(remote_path))
            ok, pull_out = adb_pull(remote_path, local_apk)
            if ok:
                logger.info("Pulled APK: %s -> %s", remote_path, local_apk)
                apk_paths.append(local_apk)
            else:
                logger.warning("Failed to pull %s: %s", remote_path, pull_out.strip())
    return apk_paths


def extract_so_from_apk(apk_path: str, target_names: List[str], out_dir: str, logger: logging.Logger) -> List[str]:
    """
    Extract matching so files from an APK into out_dir.
    Returns list of extracted local paths.
    """
    extracted = []
    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            for entry in z.namelist():
                if not entry.startswith("lib/"):
                    continue
                base = os.path.basename(entry)
                if base in target_names:
                    local_out = os.path.join(out_dir, base)
                    os.makedirs(os.path.dirname(local_out) or ".", exist_ok=True)
                    logger.info("Extracting %s from %s -> %s", entry, apk_path, local_out)
                    with open(local_out, "wb") as f:
                        f.write(z.read(entry))
                    extracted.append(local_out)
    except zipfile.BadZipFile:
        logger.warning("APK %s is not a valid zip file", apk_path)
    except Exception as e:
        logger.warning("Failed extracting from %s: %s", apk_path, e)
    return extracted


def pull_and_extract_inner_so(module_path: str, tmp_apk_dir: str, out_dir: str, logger: logging.Logger) -> Optional[str]:
    """
    If module_path contains '!', treat it as 'remote_apk_path!inner_path'.
    Pull remote_apk_path via adb into tmp_apk_dir (cached per APK file name).
    Extract inner_path (strip leading slash) from APK and copy to out_dir.
    Returns path to extracted .so file on success, None on failure.
    """
    if "!" not in module_path:
        return None

    remote_apk_path, inner_path = module_path.split("!", 1)
    remote_apk_path = remote_apk_path.strip()
    inner_path = inner_path.strip()
    if inner_path.startswith("/"):
        inner_path_zip = inner_path[1:]
    else:
        inner_path_zip = inner_path

    logger.info("Detected APK!inner syntax. Remote APK: %s  inner path: %s", remote_apk_path, inner_path_zip)

    os.makedirs(tmp_apk_dir, exist_ok=True)
    apk_basename = os.path.basename(remote_apk_path)
    local_apk_path = os.path.join(tmp_apk_dir, apk_basename)

    if not os.path.exists(local_apk_path):
        logger.info("Pulling APK via adb: %s -> %s", remote_apk_path, local_apk_path)
        ok, out = adb_pull(remote_apk_path, local_apk_path)
        if not ok:
            logger.warning("Failed to pull APK %s via adb: %s", remote_apk_path, out.strip())
            return None
        logger.info("Successfully pulled APK: %s", local_apk_path)
    else:
        logger.info("Using cached APK: %s", local_apk_path)

    try:
        with zipfile.ZipFile(local_apk_path, "r") as z:
            matched_entries = [e for e in z.namelist() if e == inner_path_zip]
            if not matched_entries:
                inner_basename = os.path.basename(inner_path_zip)
                candidates = [e for e in z.namelist() if e.endswith("/" + inner_basename)]
                if candidates:
                    logger.info("Exact inner path not in APK; found candidate entries that end with /%s: %s", inner_basename, ", ".join(candidates[:5]))
                    matched_entries = candidates
                else:
                    logger.warning("APK extraction did not find %s in %s", inner_path_zip, local_apk_path)
                    return None

            entry = matched_entries[0]
            out_so_path = os.path.join(out_dir, os.path.basename(entry))
            os.makedirs(os.path.dirname(out_so_path) or ".", exist_ok=True)
            logger.info("Extracting %s from %s -> %s", entry, local_apk_path, out_so_path)
            with z.open(entry, "r") as src, open(out_so_path, "wb") as dst:
                shutil.copyfileobj(src, dst)
            logger.info("Extracted library to %s", out_so_path)
            return out_so_path
    except zipfile.BadZipFile:
        logger.warning("Pulled APK %s is not a zip file or is corrupted", local_apk_path)
        return None
    except FileNotFoundError:
        logger.warning("Pulled APK %s does not exist on disk (pull may have failed earlier)", local_apk_path)
        return None
    except Exception as e:
        logger.warning("Unexpected error while extracting %s from %s: %s", inner_path_zip, local_apk_path, e)
        return None


# ---------------------------
# Pattern building
# ---------------------------
def ascii_to_hex_pattern(s: str) -> str:
    return " ".join(f"{ord(c):02x}" for c in s)


def ascii_utf16le_pattern(s: str) -> str:
    return " ".join(f"{ord(c):02x} 00" for c in s)


def reversed_hex_pattern(s: str) -> str:
    bs = [f"{ord(c):02x}" for c in s]
    bs.reverse()
    return " ".join(bs)


def gapped_pattern(s: str, gap: int) -> str:
    parts = []
    for c in s:
        parts.append(f"{ord(c):02x}")
        for _ in range(gap):
            parts.append("00")
    return " ".join(parts)


def build_patterns(target: str, prefix_len: int = 8) -> List[str]:
    patterns = []
    t = target
    patterns.append(ascii_to_hex_pattern(t))
    t_lower = t.lower()
    if t_lower != t:
        patterns.append(ascii_to_hex_pattern(t_lower))
    t_upper = t.upper()
    if t_upper != t and t_upper != t_lower:
        patterns.append(ascii_to_hex_pattern(t_upper))
    patterns.append(ascii_utf16le_pattern(t))
    if prefix_len and prefix_len < len(t):
        prefix = t[:prefix_len]
        patterns.append(ascii_to_hex_pattern(prefix))
        patterns.append(ascii_utf16le_pattern(prefix))
    patterns.append(reversed_hex_pattern(t))
    for g in (1, 3, 7):
        patterns.append(gapped_pattern(t, g))
    return patterns


# ---------------------------
# CLI and main flow
# ---------------------------
def parse_args():
    p = argparse.ArgumentParser(description="Find and dump .so modules from Android process (improved).")
    p.add_argument("--device", "-d", help="Frida device spec (e.g. 192.168.1.2:27042). If omitted, USB is used.")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--package", "-p", help="Package name to attach to (e.g. org.thoughtcrime.securesms).")
    g.add_argument("--pid", help="PID to attach to.")
    p.add_argument("--library", "-l", help="Skip scanning and dump this specific library name (must be loaded).")
    p.add_argument("--output", "-o", default="./dumps", help="Output directory (default ./dumps).")
    p.add_argument("--non-interactive", action="store_true", help="Do not prompt; dump all matches automatically.")
    p.add_argument("--no-adb", action="store_true", help="Do not attempt adb pull; force memory dumps.")
    p.add_argument("--verbose", action="store_true", help="Verbose logging.")
    p.add_argument("--chunk-size", type=int, default=64 * 1024, help="Chunk size for memory dumps (bytes).")
    p.add_argument("--partial-prefix", type=int, default=8, help="When full-string search fails, search for prefix length (default 8).")
    return p.parse_args()


def human_size(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024.0 or unit == "GiB":
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} B"


def main():
    args = parse_args()
    global logger
    logger = setup_logging(args.verbose)

    logger.info("Starting findBoringSSLLibsOnAndroid.py")
    if args.no_adb:
        logger.info("ADB usage disabled by --no-adb")
    adb_available = check_adb() and not args.no_adb
    if adb_available:
        logger.info("ADB available: using adb pull where appropriate")
    else:
        logger.info("ADB not available or disabled: will use Frida memory dumps")

    # Connect to device
    try:
        if args.device:
            manager = frida.get_device_manager()
            try:
                manager.add_remote_device(args.device)
            except Exception:
                pass
            device = frida.get_device(args.device)
        else:
            device = frida.get_usb_device(timeout=5)
    except frida.TimedOutError:
        logger.error("Timed out waiting for a Frida device. Is frida-server on the device running?")
        sys.exit(1)
    except Exception as e:
        logger.error("Could not obtain Frida device: %s", e)
        sys.exit(1)

    target_ident = args.package if args.package else args.pid
    try:
        if args.pid:
            session = device.attach(int(args.pid))
        else:
            session = device.attach(args.package)
    except Exception as e:
        logger.error("Failed to attach to process '%s': %s", target_ident, e)
        try:
            procs = device.enumerate_processes()
            logger.info("Sample running processes:")
            for p in procs[:40]:
                logger.info("  %s (pid=%s)", p["name"], p["pid"])
        except Exception:
            pass
        sys.exit(1)

    logger.info("Attached to process %s", target_ident)

    # Create and load script
    try:
        script = session.create_script(JS_PAYLOAD)
    except Exception as e:
        logger.error("Failed to create frida script: %s", e)
        sys.exit(1)

    # message handler for chunked dumps
    dump_state: Dict[str, Dict] = {}

    def on_message(msg, data):
        typ = msg.get("type")
        payload = msg.get("payload") or {}
        if typ == "send":
            if payload.get("type") == "chunk":
                mod = payload.get("module")
                offset = payload.get("offset", 0)
                final = payload.get("final", False)
                if mod not in dump_state:
                    logger.warning("Received chunk for unknown module %s", mod)
                    return
                entry = dump_state[mod]
                fobj = entry["file"]
                try:
                    fobj.seek(offset)
                    fobj.write(data or b"")
                    entry["received"] += len(data or b"")
                except Exception as e:
                    logger.error("Failed to write chunk for %s: %s", mod, e)
                if final:
                    fobj.close()
                    logger.info("Completed memory dump for %s -> %s (bytes=%d)", mod, entry["path"], entry["received"])
                    del dump_state[mod]
            elif payload.get("type") == "error":
                mod = payload.get("module")
                msgtext = payload.get("message")
                logger.error("Frida-side error while dumping %s: %s", mod, msgtext)
            else:
                logger.debug("Message from frida script: %s", payload)
        elif typ == "error":
            logger.error("Frida script error: %s", msg.get("description"))
        else:
            logger.debug("Unhandled message type: %s - payload: %s", typ, payload)

    script.on("message", on_message)
    script.load()

    exports_obj = getattr(script, "exports_sync", None) or getattr(script, "exports", None)

    try:
        modules = exports_obj.enumerate_modules()
    except Exception as e:
        logger.error("Failed to enumerate modules via frida RPC: %s", e)
        sys.exit(1)

    logger.info("Found %d loaded modules", len(modules))

    # Find targets (either user-specified or scan)
    targets: List[Dict] = []
    if args.library:
        for m in modules:
            if m.get("name") == args.library:
                targets.append({**m, "matched_by": "user-specified"})
                break
        if not targets:
            logger.error("Requested library %s is not loaded in the process.", args.library)
            logger.info("Sample modules (first 40):")
            for m in modules[:40]:
                logger.info("  %s (path: %s)", m.get("name"), m.get("path"))
            sys.exit(1)
    else:
        primary = "EXPORTER_SECRET"
        fallback = "CLIENT_RANDOM"
        patterns = build_patterns(primary, args.partial_prefix)
        fallback_patterns = build_patterns(fallback, args.partial_prefix)
        logger.info("Built %d primary patterns and %d fallback patterns", len(patterns), len(fallback_patterns))

        for m in modules:
            name = m.get("name")
            try:
                found = exports_obj.scan_module_for_patterns(name, patterns)
                if found:
                    logger.info("Module %s matched primary patterns (count %d)", name, len(found))
                    targets.append({**m, "matched_by": "primary"})
                    continue
                found2 = exports_obj.scan_module_for_patterns(name, fallback_patterns)
                if found2:
                    logger.info("Module %s matched fallback patterns (count %d)", name, len(found2))
                    targets.append({**m, "matched_by": "fallback"})
            except Exception:
                logger.debug("Skipping module %s due to scan error", name)

    if not targets:
        logger.warning("No modules matched primary or fallback patterns.")
        logger.info("Consider running the script with --verbose and verifying the process/package.")
        sys.exit(0)

    # selection
    chosen: List[Dict] = []
    if args.non_interactive or len(targets) == 1:
        chosen = targets
    else:
        logger.info("Candidate modules:")
        for idx, t in enumerate(targets, start=1):
            size = human_size(int(t.get("size", 0) or 0))
            logger.info(" [%d] %s   path: %s   size: %s   matched_by: %s", idx, t.get("name"), t.get("path"), size, t.get("matched_by"))
        sel = input("Enter comma-separated indices to dump (or press Enter to dump all): ").strip()
        if not sel:
            chosen = targets
        else:
            try:
                for part in sel.split(","):
                    i = int(part.strip())
                    if 1 <= i <= len(targets):
                        chosen.append(targets[i - 1])
            except Exception:
                logger.warning("Invalid selection; defaulting to all targets.")
                chosen = targets

    os.makedirs(args.output, exist_ok=True)

    tmp_apk_dir = None
    pulled_apks: List[str] = []

    # Dump each chosen module
    for t in chosen:
        name = t.get("name")
        path = t.get("path") or ""
        size = int(t.get("size") or 0)
        logger.info("Preparing to dump %s (size %s) path: %s", name, human_size(size), path or "<no-path>")

        extracted_ok = False
        local_so_path = os.path.join(args.output, name)

        # If the path contains an APK!inner entry, try the direct APK inner extraction first
        if adb_available and path and "!" in path:
            if not tmp_apk_dir:
                tmp_apk_dir = tempfile.mkdtemp(prefix="frida_apk_")
                logger.debug("Created temp apk dir %s", tmp_apk_dir)
            extracted = pull_and_extract_inner_so(path, tmp_apk_dir, args.output, logger)
            if extracted:
                logger.info("Extracted %s from APK inner path -> %s", name, extracted)
                extracted_ok = True
            else:
                logger.warning("APK inner extraction failed for path: %s", path)

        # If no '!' path or previous extraction failed, try direct adb pull when path is a normal file path
        if not extracted_ok and adb_available and path and "!" not in path:
            logger.info("Attempting adb pull of %s", path)
            ok, out = adb_pull(path, local_so_path)
            if ok:
                logger.info("adb pull succeeded: %s", local_so_path)
                extracted_ok = True
            else:
                logger.warning("adb pull failed: %s", out.strip())

        # If still not extracted and the path looks like .apk or we haven't tried package-level APK pulling, try pm path list
        if not extracted_ok and adb_available:
            # Ensure tmp dir created
            if not tmp_apk_dir:
                tmp_apk_dir = tempfile.mkdtemp(prefix="frida_apk_")
                logger.debug("Created temp apk dir %s", tmp_apk_dir)
            # Try to pull all APKs for the package and extract .so files from them
            if args.package:
                a_paths = pull_apks_for_package(args.package, tmp_apk_dir, logger)
                pulled_apks.extend(a_paths)
                if a_paths:
                    wanted = [name]
                    for apk in a_paths:
                        founds = extract_so_from_apk(apk, wanted, args.output, logger)
                        if founds:
                            logger.info("Extracted %d .so files from APK %s", len(founds), apk)
                            extracted_ok = True
                            break
                else:
                    logger.warning("Failed to list package apk paths via 'pm path'. Output was empty or command failed.")
            else:
                logger.debug("No package provided; cannot list APKs via pm path.")

        # If still not extracted, fallback to Frida memory dump
        if not extracted_ok:
            outfile = local_so_path + ".memdump.so"
            try:
                f = open(outfile, "wb")
            except Exception as e:
                logger.error("Cannot open output file %s: %s", outfile, e)
                continue
            dump_state[name] = {"file": f, "path": outfile, "received": 0}
            logger.info("Starting memory dump for %s (chunk_size=%d bytes)", name, args.chunk_size)
            try:
                if getattr(script, "exports_sync", None):
                    script.exports_sync.dump_module_chunks(name, args.chunk_size)
                else:
                    # Note: calling script.exports.<fn> may be synchronous or asynchronous depending on frida version; the exports_sync check above avoids the deprecation warning.
                    script.exports.dump_module_chunks(name, args.chunk_size)
                wait_start = time.time()
                while name in dump_state:
                    time.sleep(0.1)
                    if time.time() - wait_start > 300:
                        logger.error("Timeout waiting for memory dump for %s", name)
                        try:
                            entry = dump_state.pop(name, None)
                            if entry and entry.get("file"):
                                entry["file"].close()
                        except Exception:
                            pass
                        break
            except Exception as e:
                logger.error("Frida memory dump failed for %s: %s", name, e)
                try:
                    entry = dump_state.pop(name, None)
                    if entry and entry.get("file"):
                        entry["file"].close()
                except Exception:
                    pass
                try:
                    if os.path.exists(outfile) and os.path.getsize(outfile) == 0:
                        os.remove(outfile)
                except Exception:
                    pass
                continue

    # cleanup
    if tmp_apk_dir:
        try:
            logger.debug("Cleaning up temporary APK directory %s", tmp_apk_dir)
            shutil.rmtree(tmp_apk_dir)
        except Exception:
            logger.debug("Failed to remove temp dir %s", tmp_apk_dir)

    logger.info("All requested dump operations completed. Look in: %s", os.path.abspath(args.output))


if __name__ == "__main__":
    main()
