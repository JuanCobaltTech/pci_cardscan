#!/usr/bin/env python3
"""
pci_cardscan.py — PCI DSS Card Data Scanner for Ubuntu/Debian
Detects PANs (Primary Account Numbers) in plaintext files.
Validates with Luhn algorithm and classifies by card network.
Outputs JSON results for report generation.

Usage:
  python3 pci_cardscan.py /path/to/scan
  python3 pci_cardscan.py /path/to/scan --output results.json
  python3 pci_cardscan.py /path/to/scan --exclude /proc /sys /dev
"""

import os
import re
import sys
import json
import argparse
import hashlib
import platform
import socket
from datetime import datetime, timezone
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
#  Constants
# ─────────────────────────────────────────────────────────────────────────────

VERSION = "1.0.0"

# File extensions that are always binary — skip without even reading
BINARY_EXTENSIONS = {
    ".gz", ".bz2", ".xz", ".zip", ".tar", ".rar", ".7z", ".zst",
    ".whl", ".egg", ".jar", ".war", ".ear",
    ".deb", ".rpm", ".apk", ".snap",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".elf",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp", ".ico",
    ".mp3", ".mp4", ".wav", ".ogg", ".flac", ".avi", ".mkv", ".mov",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".sqlite", ".db", ".dbf",
    ".pyc", ".pyo", ".class",
    ".o", ".a", ".lib",
    ".iso", ".img", ".vmdk", ".qcow2",
    ".key", ".p12", ".pfx", ".der", ".crt", ".cer",
}

# Directories to always skip
DEFAULT_EXCLUDES = {
    "/proc", "/sys", "/dev", "/run", "/snap",
    "/boot", "/lib/firmware", "/usr/lib/firmware",
}

# PAN regex patterns — grouped by card network (digits only, with optional separators)
PAN_PATTERNS = {
    "Visa":             re.compile(r'\b4[0-9]{3}[ \-]?[0-9]{4}[ \-]?[0-9]{4}[ \-]?[0-9]{4}\b'),
    "Mastercard":       re.compile(r'\b(?:5[1-5][0-9]{2}|2(?:2[2-9][1-9]|[3-6][0-9]{2}|7[01][0-9]|720))[0-9]{2}[ \-]?[0-9]{4}[ \-]?[0-9]{4}[ \-]?[0-9]{4}\b'),
    "Amex":             re.compile(r'\b3[47][0-9]{2}[ \-]?[0-9]{6}[ \-]?[0-9]{5}\b'),
    "Discover":         re.compile(r'\b6(?:011|5[0-9]{2})[ \-]?[0-9]{4}[ \-]?[0-9]{4}[ \-]?[0-9]{4}\b'),
    "Diners Club":      re.compile(r'\b3(?:0[0-5]|[68][0-9])[ \-]?[0-9]{4}[ \-]?[0-9]{6}\b'),
    "JCB":              re.compile(r'\b(?:2131|1800|35[0-9]{3})[ \-]?[0-9]{4}[ \-]?[0-9]{4}[ \-]?[0-9]{3}\b'),
}

# Single combined pattern for fast pre-screening lines
PRESCREEN = re.compile(r'\b[3-6][0-9]{3}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}')

# ─────────────────────────────────────────────────────────────────────────────
#  Luhn Validation
# ─────────────────────────────────────────────────────────────────────────────

def luhn_check(number: str) -> bool:
    """Return True if the digit string passes the Luhn check."""
    digits = [int(d) for d in number]
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    total = sum(odd_digits)
    for d in even_digits:
        doubled = d * 2
        total += doubled if doubled < 10 else doubled - 9
    return total % 10 == 0


def clean_digits(raw: str) -> str:
    """Strip spaces and dashes from a matched PAN string."""
    return re.sub(r'[\s\-]', '', raw)


def mask_pan(digits: str) -> str:
    """Mask PAN per PCI DSS: show first 6 and last 4 only."""
    if len(digits) < 10:
        return "*" * len(digits)
    return digits[:6] + "*" * (len(digits) - 10) + digits[-4:]

# ─────────────────────────────────────────────────────────────────────────────
#  Binary Detection
# ─────────────────────────────────────────────────────────────────────────────

def is_binary(filepath: str, sample: int = 8192) -> bool:
    """Return True if the file appears to be binary."""
    ext = Path(filepath).suffix.lower()
    if ext in BINARY_EXTENSIONS:
        return True
    try:
        with open(filepath, 'rb') as f:
            chunk = f.read(sample)
        if not chunk:
            return False
        if b'\x00' in chunk:          # Null bytes → binary
            return True
        # High ratio of non-printable, non-whitespace bytes → binary
        non_text = sum(
            1 for b in chunk
            if b > 127 or (b < 32 and b not in (9, 10, 13))
        )
        return (non_text / len(chunk)) > 0.15
    except (OSError, PermissionError):
        return True

# ─────────────────────────────────────────────────────────────────────────────
#  File Scanner
# ─────────────────────────────────────────────────────────────────────────────

def scan_file(filepath: str, max_file_mb: int = 50) -> list:
    """
    Scan a single file for PAN candidates.
    Returns list of finding dicts.
    """
    findings = []
    try:
        size_mb = os.path.getsize(filepath) / (1024 * 1024)
        if size_mb > max_file_mb:
            return []                    # Skip very large files
        if is_binary(filepath):
            return []

        with open(filepath, 'r', encoding='utf-8', errors='replace') as fh:
            for lineno, line in enumerate(fh, start=1):
                if not PRESCREEN.search(line):
                    continue            # Fast skip for lines with no candidate
                for card_type, pattern in PAN_PATTERNS.items():
                    for match in pattern.finditer(line):
                        raw = match.group(0)
                        digits = clean_digits(raw)
                        if not luhn_check(digits):
                            continue
                        context = line.strip()[:120]
                        # Mask PAN in context for safe logging
                        masked = mask_pan(digits)
                        safe_ctx = re.sub(re.escape(raw), masked, context)
                        findings.append({
                            "file":       filepath,
                            "line":       lineno,
                            "card_type":  card_type,
                            "pan_masked": masked,
                            "pan_length": len(digits),
                            "context":    safe_ctx,
                        })
    except (PermissionError, OSError):
        pass
    return findings

# ─────────────────────────────────────────────────────────────────────────────
#  Directory Walker
# ─────────────────────────────────────────────────────────────────────────────

def walk_and_scan(root: str, excludes: set, verbose: bool = True) -> dict:
    """Walk directory tree and scan every eligible file."""
    all_findings = []
    stats = {
        "files_scanned": 0,
        "files_skipped_binary": 0,
        "files_skipped_permission": 0,
        "files_skipped_size": 0,
        "dirs_excluded": 0,
    }

    # Resolve excludes to absolute paths
    abs_excludes = {os.path.realpath(e) for e in excludes}

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        real_dir = os.path.realpath(dirpath)

        # Check if current dir matches an exclusion
        if any(real_dir == ex or real_dir.startswith(ex + os.sep)
               for ex in abs_excludes):
            dirnames.clear()
            stats["dirs_excluded"] += 1
            continue

        # Prune subdirs that are excluded
        pruned = []
        for d in list(dirnames):
            subpath = os.path.realpath(os.path.join(dirpath, d))
            if any(subpath == ex or subpath.startswith(ex + os.sep)
                   for ex in abs_excludes):
                stats["dirs_excluded"] += 1
            else:
                pruned.append(d)
        dirnames[:] = pruned

        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            try:
                if os.path.islink(fpath):
                    continue
                size_mb = os.path.getsize(fpath) / (1024 * 1024)
                if size_mb > 50:
                    stats["files_skipped_size"] += 1
                    continue
                if is_binary(fpath):
                    stats["files_skipped_binary"] += 1
                    continue
                results = scan_file(fpath)
                stats["files_scanned"] += 1
                if results:
                    all_findings.extend(results)
                    if verbose:
                        for r in results:
                            print(f"  [FOUND] {r['card_type']:12s} {r['pan_masked']}  "
                                  f"{r['file']}:{r['line']}")
                elif verbose and stats["files_scanned"] % 500 == 0:
                    print(f"  ... {stats['files_scanned']} files scanned, "
                          f"{len(all_findings)} findings so far", flush=True)
            except PermissionError:
                stats["files_skipped_permission"] += 1
            except OSError:
                stats["files_skipped_binary"] += 1

    return {"findings": all_findings, "stats": stats}

# ─────────────────────────────────────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="PCI DSS Card Data Scanner for Ubuntu/Debian",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("target", help="Root directory to scan")
    parser.add_argument("--output", default="pci_scan_results.json",
                        help="JSON output file (default: pci_scan_results.json)")
    parser.add_argument("--exclude", nargs="*", default=[],
                        help="Additional directories to exclude")
    parser.add_argument("--quiet", action="store_true",
                        help="Suppress per-finding console output")
    args = parser.parse_args()

    target = os.path.abspath(args.target)
    if not os.path.isdir(target):
        print(f"[ERROR] Target is not a directory: {target}", file=sys.stderr)
        sys.exit(1)

    excludes = DEFAULT_EXCLUDES | set(args.exclude)

    scan_start = datetime.now(timezone.utc)
    print(f"\n{'='*70}")
    print(f"  PCI DSS Card Data Scanner v{VERSION}")
    print(f"  Host     : {socket.gethostname()}")
    print(f"  OS       : {platform.platform()}")
    print(f"  Scanning : {target}")
    print(f"  Started  : {scan_start.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"{'='*70}\n")

    result = walk_and_scan(target, excludes, verbose=not args.quiet)

    scan_end = datetime.now(timezone.utc)
    duration_s = (scan_end - scan_start).total_seconds()

    findings   = result["findings"]
    stats      = result["stats"]
    files_with = len({f["file"] for f in findings})

    # Build card type summary
    by_type = {}
    for f in findings:
        by_type[f["card_type"]] = by_type.get(f["card_type"], 0) + 1

    output = {
        "meta": {
            "scanner_version": VERSION,
            "hostname": socket.gethostname(),
            "os": platform.platform(),
            "scan_root": target,
            "scan_start": scan_start.isoformat(),
            "scan_end": scan_end.isoformat(),
            "duration_seconds": round(duration_s, 1),
            "excluded_paths": sorted(excludes),
        },
        "summary": {
            "files_scanned": stats["files_scanned"],
            "files_skipped_binary": stats["files_skipped_binary"],
            "files_skipped_permission": stats["files_skipped_permission"],
            "files_skipped_large": stats["files_skipped_size"],
            "dirs_excluded": stats["dirs_excluded"],
            "total_findings": len(findings),
            "files_with_pan": files_with,
            "findings_by_card_type": by_type,
        },
        "findings": findings,
    }

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    # Console summary
    print(f"\n{'='*70}")
    print(f"  SCAN COMPLETE")
    print(f"  Duration        : {duration_s:.1f}s")
    print(f"  Files scanned   : {stats['files_scanned']:,}")
    print(f"  Binary skipped  : {stats['files_skipped_binary']:,}")
    print(f"  Permission err  : {stats['files_skipped_permission']:,}")
    print(f"  ─────────────────────────────────")
    print(f"  PANs found      : {len(findings)}")
    print(f"  Affected files  : {files_with}")
    if by_type:
        for ctype, cnt in sorted(by_type.items(), key=lambda x: -x[1]):
            print(f"    {ctype:<14}: {cnt}")
    print(f"  Results saved   : {args.output}")
    print(f"{'='*70}\n")

    return 0 if len(findings) == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
