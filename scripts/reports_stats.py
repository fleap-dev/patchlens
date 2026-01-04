#!/usr/bin/env -S uv --quiet run --script
# /// script
# requires-python = ">=3.13"
# dependencies = []
# ///
"""
Report Statistics Script

Analyzes soundness reports and displays statistics about their verdicts.

Usage:
    ./reports_stats.py              # Show statistics for all reports
    ./reports_stats.py list-ok      # List reports with OK verdict
    ./reports_stats.py list-unsound # List reports with UNSOUND verdict
    ./reports_stats.py list-todo    # List reports not yet filled

Filters:
    --linux   Include only Linux reports
    --php     Include only PHP reports
    --ffmpeg  Include only FFmpeg reports
"""

import argparse
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path
import sys
from typing import cast


class Verdict(Enum):
    OK = auto()
    UNSOUND = auto()
    TODO = auto()


@dataclass
class Report:
    path: Path
    verdict: Verdict
    product: str  # linux, php, ffmpeg, etc.


def get_verdict_from_report(report_path: Path) -> Verdict:
    """Extract the verdict from a report file."""
    content = report_path.read_text()
    lines = content.splitlines()

    # Find the line "## Veredict (OK,UNSOUND)" and get the next non-empty line
    for i, line in enumerate(lines):
        if line.strip() == "## Veredict (OK,UNSOUND)":
            # Look for the verdict in subsequent lines
            for j in range(i + 1, len(lines)):
                verdict_line = lines[j].strip()
                if verdict_line == "OK":
                    return Verdict.OK
                elif verdict_line == "UNSOUND":
                    return Verdict.UNSOUND
                elif verdict_line == "":
                    continue
                else:
                    # Some other content, treat as TODO
                    return Verdict.TODO
            # Reached end of file without finding verdict
            return Verdict.TODO

    # Section not found
    return Verdict.TODO


def collect_reports(
    soundness_dir: Path, products: list[str] | None = None
) -> list[Report]:
    """Collect all reports from the soundness directory."""
    reports: list[Report] = []

    if not soundness_dir.exists():
        return reports

    # Get all product directories or filter by specified products
    if products:
        product_dirs = [
            soundness_dir / p for p in products if (soundness_dir / p).exists()
        ]
    else:
        product_dirs = [d for d in soundness_dir.iterdir() if d.is_dir()]

    for product_dir in product_dirs:
        product_name = product_dir.name
        for report_file in product_dir.glob("report-*.md"):
            verdict = get_verdict_from_report(report_file)
            reports.append(
                Report(path=report_file, verdict=verdict, product=product_name)
            )

    return reports


def print_stats(reports: list[Report]) -> None:
    """Print statistics about the reports."""
    total = len(reports)
    if total == 0:
        print("No reports found.")
        return

    ok_count = sum(1 for r in reports if r.verdict == Verdict.OK)
    unsound_count = sum(1 for r in reports if r.verdict == Verdict.UNSOUND)
    todo_count = sum(1 for r in reports if r.verdict == Verdict.TODO)

    ok_pct = (ok_count / total) * 100
    unsound_pct = (unsound_count / total) * 100
    todo_pct = (todo_count / total) * 100

    print(f"Total reports: {total}")
    print()
    print(f"  OK:       {ok_count:4d} ({ok_pct:5.1f}%)")
    print(f"  UNSOUND:  {unsound_count:4d} ({unsound_pct:5.1f}%)")
    print(f"  TODO:     {todo_count:4d} ({todo_pct:5.1f}%)")


def list_reports(reports: list[Report], verdict_filter: Verdict) -> None:
    """Print a list of reports with a specific verdict."""
    filtered = [r for r in reports if r.verdict == verdict_filter]
    for report in sorted(filtered, key=lambda r: r.path.name):
        print(report.path)


def main() -> None:
    # Parent parser with shared arguments
    parent_parser = argparse.ArgumentParser(add_help=False)
    _ = parent_parser.add_argument(
        "--folder",
        type=str,
        default="soundness",
        help="Folder containing the reports",
    )
    _ = parent_parser.add_argument(
        "--linux",
        action="store_true",
        help="Include only Linux reports",
    )
    _ = parent_parser.add_argument(
        "--php",
        action="store_true",
        help="Include only PHP reports",
    )
    _ = parent_parser.add_argument(
        "--ffmpeg",
        action="store_true",
        help="Include only FFmpeg reports",
    )

    parser = argparse.ArgumentParser(
        description="Analyze soundness reports and display statistics",
        parents=[parent_parser],
    )

    # Subcommands
    subparsers = parser.add_subparsers(dest="command")

    _ = subparsers.add_parser(
        "list-ok", help="List reports with OK verdict", parents=[parent_parser]
    )
    _ = subparsers.add_parser(
        "list-unsound",
        help="List reports with UNSOUND verdict",
        parents=[parent_parser],
    )
    _ = subparsers.add_parser(
        "list-todo", help="List reports not yet filled", parents=[parent_parser]
    )

    args = parser.parse_args()

    # Determine which products to include
    products: list[str] | None = None
    if args.linux or args.php or args.ffmpeg:
        products = []
        if args.linux:
            products.append("linux")
        if args.php:
            products.append("php")
        if args.ffmpeg:
            products.append("ffmpeg")

    soundness_dir = Path(cast(str, args.folder))

    print(f"Checking folder {soundness_dir}...", file=sys.stderr)

    reports = collect_reports(soundness_dir, products)

    if args.command == "list-ok":
        list_reports(reports, Verdict.OK)
    elif args.command == "list-unsound":
        list_reports(reports, Verdict.UNSOUND)
    elif args.command == "list-todo":
        list_reports(reports, Verdict.TODO)
    else:
        # Default: show statistics
        print_stats(reports)


if __name__ == "__main__":
    main()
