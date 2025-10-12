#!/usr/bin/env python3
"""Recursive directory scanner for secret detection testing and fine-tuning.

Scans all files in a directory tree and reports which files contain potential
secrets, along with line numbers and detection types. Does NOT emit the actual
secret values to avoid accidental exposure.
"""

import argparse
import json
import os
import sys
from collections import defaultdict
from pathlib import Path
from pathlib import Path as PathLib

# Add plugin directory to path
_plugin_path = PathLib(__file__).parent.parent / "plugins" / "secrets_scanner" / "hooks"
sys.path.insert(0, str(_plugin_path))

from secrets_scanner_hook import (
    PATTERNS,
    scan_file,
    scan_text,
    should_scan_file,
    MAX_SCAN_BYTES,
)


# Default paths to exclude from scanning
DEFAULT_EXCLUDES = {
    ".git",
    ".svn",
    ".hg",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    ".pytest_cache",
    ".mypy_cache",
    ".tox",
    "dist",
    "build",
    ".egg-info",
}


class Colors:
    """ANSI color codes for terminal output."""
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def should_exclude(path: Path, excludes: set) -> bool:
    """Check if path should be excluded from scanning."""
    parts = path.parts
    return any(exc in parts for exc in excludes)


def scan_directory(
    root_dir: str,
    excludes: set = None,
    max_files: int = None,
    verbose: bool = False,
) -> dict:
    """Scan all files in directory tree and collect findings.

    Returns:
        dict with structure:
        {
            'files_scanned': int,
            'files_skipped': int,
            'files_with_findings': int,
            'total_findings': int,
            'findings': [
                {
                    'file': str,
                    'line': int,
                    'type': str,
                    # NOTE: 'match' field intentionally omitted to avoid exposing secrets
                }
            ],
            'errors': [{'file': str, 'error': str}]
        }
    """
    if excludes is None:
        excludes = DEFAULT_EXCLUDES

    root_path = Path(root_dir).resolve()
    if not root_path.exists():
        raise FileNotFoundError(f"Directory does not exist: {root_dir}")
    if not root_path.is_dir():
        raise NotADirectoryError(f"Not a directory: {root_dir}")

    results = {
        "files_scanned": 0,
        "files_skipped": 0,
        "files_with_findings": 0,
        "total_findings": 0,
        "findings": [],
        "errors": [],
    }

    files_processed = 0

    for item in root_path.rglob("*"):
        if not item.is_file():
            continue

        if should_exclude(item.relative_to(root_path), excludes):
            results["files_skipped"] += 1
            if verbose:
                print(f"  {Colors.CYAN}SKIP{Colors.RESET} {item.relative_to(root_path)}", file=sys.stderr)
            continue

        if max_files and files_processed >= max_files:
            break

        try:
            # Check if we should scan this file
            if not should_scan_file(str(item)):
                results["files_skipped"] += 1
                if verbose:
                    print(f"  {Colors.CYAN}SKIP{Colors.RESET} {item.relative_to(root_path)} (binary)", file=sys.stderr)
                continue

            # Check file size
            if item.stat().st_size > MAX_SCAN_BYTES:
                results["files_skipped"] += 1
                if verbose:
                    print(f"  {Colors.CYAN}SKIP{Colors.RESET} {item.relative_to(root_path)} (too large)", file=sys.stderr)
                continue

            # Scan the file
            findings = scan_file(str(item))
            results["files_scanned"] += 1
            files_processed += 1

            if findings:
                results["files_with_findings"] += 1
                results["total_findings"] += len(findings)

                # Remove the 'match' field to avoid exposing secrets
                for finding in findings:
                    finding.pop("match", None)
                    results["findings"].append(finding)

                if verbose:
                    print(f"  {Colors.RED}FOUND{Colors.RESET} {item.relative_to(root_path)} ({len(findings)} findings)", file=sys.stderr)
            else:
                if verbose:
                    print(f"  {Colors.GREEN}CLEAN{Colors.RESET} {item.relative_to(root_path)}", file=sys.stderr)

        except Exception as e:
            results["errors"].append({"file": str(item.relative_to(root_path)), "error": str(e)})
            if verbose:
                print(f"  {Colors.YELLOW}ERROR{Colors.RESET} {item.relative_to(root_path)}: {e}", file=sys.stderr)

    return results


def format_findings_report(results: dict, use_color: bool = True) -> str:
    """Format scan results as a human-readable report."""
    if not use_color:
        c_reset = c_bold = c_red = c_green = c_yellow = c_blue = ""
    else:
        c_reset = Colors.RESET
        c_bold = Colors.BOLD
        c_red = Colors.RED
        c_green = Colors.GREEN
        c_yellow = Colors.YELLOW
        c_blue = Colors.BLUE

    lines = []
    lines.append(f"\n{c_bold}=== Secret Scanner Directory Report ==={c_reset}\n")

    # Summary statistics
    lines.append(f"{c_bold}Summary:{c_reset}")
    lines.append(f"  Files scanned:      {results['files_scanned']}")
    lines.append(f"  Files skipped:      {results['files_skipped']}")
    lines.append(f"  Files with secrets: {c_red if results['files_with_findings'] else c_green}{results['files_with_findings']}{c_reset}")
    lines.append(f"  Total findings:     {c_red if results['total_findings'] else c_green}{results['total_findings']}{c_reset}")
    lines.append("")

    # Group findings by file
    if results["findings"]:
        findings_by_file = defaultdict(list)
        for finding in results["findings"]:
            findings_by_file[finding["file"]].append(finding)

        lines.append(f"{c_bold}Files with Findings:{c_reset}\n")

        for file_path in sorted(findings_by_file.keys()):
            file_findings = findings_by_file[file_path]
            lines.append(f"{c_red}●{c_reset} {c_bold}{file_path}{c_reset}")

            # Group by type
            by_type = defaultdict(list)
            for f in file_findings:
                by_type[f["type"]].append(f["line"])

            for secret_type in sorted(by_type.keys()):
                line_nums = sorted(by_type[secret_type])
                line_str = ", ".join(str(ln) for ln in line_nums[:10])
                if len(line_nums) > 10:
                    line_str += f" ... (+{len(line_nums) - 10} more)"
                lines.append(f"  {c_yellow}{secret_type}{c_reset}: lines {line_str}")
            lines.append("")

    # Errors
    if results["errors"]:
        lines.append(f"{c_bold}Errors:{c_reset}\n")
        for err in results["errors"]:
            lines.append(f"{c_yellow}⚠{c_reset} {err['file']}: {err['error']}")
        lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Recursively scan directory for secrets (for testing/fine-tuning)"
    )
    parser.add_argument(
        "directory",
        help="Directory to scan recursively"
    )
    parser.add_argument(
        "--exclude",
        action="append",
        help="Additional directory/file names to exclude (can be specified multiple times)"
    )
    parser.add_argument(
        "--max-files",
        type=int,
        help="Maximum number of files to scan (useful for testing on large dirs)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show progress for each file scanned"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON instead of formatted report"
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output"
    )

    args = parser.parse_args()

    # Build excludes set
    excludes = DEFAULT_EXCLUDES.copy()
    if args.exclude:
        excludes.update(args.exclude)

    try:
        if args.verbose:
            print(f"Scanning directory: {args.directory}", file=sys.stderr)
            print(f"Excluding: {', '.join(sorted(excludes))}\n", file=sys.stderr)

        results = scan_directory(
            args.directory,
            excludes=excludes,
            max_files=args.max_files,
            verbose=args.verbose,
        )

        if args.json:
            print(json.dumps(results, indent=2))
        else:
            print(format_findings_report(results, use_color=not args.no_color))

        # Exit with error code if secrets were found
        sys.exit(1 if results["files_with_findings"] > 0 else 0)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
