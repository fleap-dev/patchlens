#!/usr/bin/env -S uv --quiet run --script
# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "z3-solver",
# ]
# ///
"""
Automate Comparison Script

Reads pclocator_flags.csv and final_dataset.csv, joins them on (CVE_ID, PATCH_ID),
compares the flags using Z3, and outputs a comparison results CSV and summary report.
"""

import argparse
import csv
import random
import sys
from collections import Counter
from pathlib import Path
from typing import Optional

from compare_flags import ComparisonResult, FlagComparator, FlagNormalizer


def read_pclocator_csv(filepath: Path) -> dict[tuple[str, str], str]:
    """
    Read pclocator flags CSV file.

    CSV format: cve_id, product, patch_id, pclocator_flag

    Args:
        filepath: Path to the pclocator CSV file.

    Returns:
        Dictionary mapping (cve_id, patch_id) to pclocator_flag.
    """
    flags = {}
    with open(filepath, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cve_id = row["cve_id"].strip()
            patch_id = row["patch_id"].strip()
            flag = row["pclocator_flag"].strip()
            key = (cve_id, patch_id)
            flags[key] = flag
    return flags


def read_patchlens_csv(filepath: Path) -> dict[tuple[str, str], str]:
    """
    Read patchlens flags CSV file (final_dataset.csv).

    CSV format: cve_id, product, id, flag
    Note: 'id' corresponds to 'patch_id' in pclocator

    Args:
        filepath: Path to the patchlens CSV file.

    Returns:
        Dictionary mapping (cve_id, patch_id) to patchlens_flag.
    """
    flags = {}
    with open(filepath, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cve_id = row["cve_id"].strip()
            # Note: patchlens uses 'id' instead of 'patch_id'
            patch_id = row["id"].strip()
            flag = row["flag"].strip()
            key = (cve_id, patch_id)
            flags[key] = flag
    return flags


def compare_datasets(
    pclocator_flags: dict[tuple[str, str], str],
    patchlens_flags: dict[tuple[str, str], str],
    comparator: Optional[FlagComparator] = None,
) -> list[dict]:
    """
    Compare flags from both datasets.

    Args:
        pclocator_flags: Dictionary of pclocator flags.
        patchlens_flags: Dictionary of patchlens flags.
        comparator: Optional FlagComparator instance.

    Returns:
        List of comparison result dictionaries.
    """
    if comparator is None:
        comparator = FlagComparator()

    results = []

    # Find common keys (entries that exist in both datasets)
    common_keys = set(pclocator_flags.keys()) & set(patchlens_flags.keys())

    for cve_id, patch_id in sorted(common_keys):
        pc_flag = pclocator_flags[(cve_id, patch_id)]
        pl_flag = patchlens_flags[(cve_id, patch_id)]

        # Compare flags
        result = comparator.compare(pc_flag, pl_flag)

        # Normalize patchlens flag for output
        normalizer = FlagNormalizer()
        pl_normalized = normalizer.normalize(pl_flag)

        results.append(
            {
                "cve_id": cve_id,
                "patch_id": patch_id,
                "pclocator_flag": pc_flag,
                "patchlens_flag": pl_flag,
                "patchlens_normalized": pl_normalized,
                "result": result.name,
            }
        )

    return results


def generate_summary(results: list[dict], sample_size: int = 10) -> str:
    """
    Generate a summary report of comparison results.

    Args:
        results: List of comparison result dictionaries.
        sample_size: Number of sample cases to show for PClocator more general.

    Returns:
        A formatted summary string.
    """
    # Count results
    result_counts = Counter(r["result"] for r in results)
    total = len(results)

    lines = [
        "=" * 80,
        "FLAG COMPARISON SUMMARY REPORT",
        "=" * 80,
        "",
        f"Total comparisons: {total}",
        "",
        "Results breakdown:",
        "-" * 40,
    ]

    # Define order for display
    order = [
        ComparisonResult.EQUAL,
        ComparisonResult.PATCHLENS_MORE_GENERAL,
        ComparisonResult.PCLOCATOR_MORE_GENERAL,
        ComparisonResult.INCOMPARABLE,
        ComparisonResult.PCLOCATOR_FAILED,
        ComparisonResult.PARSE_ERROR,
    ]

    descriptions = {
        ComparisonResult.EQUAL: "Equal (logically equivalent)",
        ComparisonResult.PATCHLENS_MORE_GENERAL: "Patchlens more general",
        ComparisonResult.PCLOCATOR_MORE_GENERAL: "Pclocator more general",
        ComparisonResult.INCOMPARABLE: "Incomparable",
        ComparisonResult.PCLOCATOR_FAILED: "Pclocator failed (empty flag)",
        ComparisonResult.PARSE_ERROR: "Parse error",
    }

    for result_type in order:
        count = result_counts.get(result_type.name, 0)
        pct = (count / total * 100) if total > 0 else 0
        lines.append(f"  {descriptions[result_type]}: {count} ({pct:.1f}%)")

    lines.extend(
        [
            "",
            "=" * 80,
            "",
            "Interpretation:",
            "- EQUAL: Both tools generated equivalent flags",
            "- PATCHLENS MORE GENERAL: Patchlens covers more configurations",
            "- PCLOCATOR MORE GENERAL: Pclocator covers more configurations",
            "- INCOMPARABLE: Flags have no logical implication relationship",
            "- PCLOCATOR FAILED: Pclocator could not generate a flag",
            "",
        ]
    )

    # Add sample cases where Patchlens is more general
    patchlens_general_cases = [
        r
        for r in results
        if r["result"] == ComparisonResult.PATCHLENS_MORE_GENERAL.name
    ]
    if patchlens_general_cases:
        lines.extend(
            [
                "=" * 80,
                f"SAMPLE: PATCHLENS MORE GENERAL (showing {min(sample_size, len(patchlens_general_cases))} random of {len(patchlens_general_cases)})",
                "=" * 80,
                "",
            ]
        )
        sample = random.sample(
            patchlens_general_cases, min(sample_size, len(patchlens_general_cases))
        )
        for case in sample:
            lines.extend(
                [
                    f"CVE: {case['cve_id']}",
                    f"Patch: {case['patch_id']}",
                    f"  PClocator:  {case['pclocator_flag']}",
                    f"  Patchlens:  {case['patchlens_normalized']}",
                    "",
                ]
            )

    # Add sample cases where PClocator is more general
    pclocator_general_cases = [
        r
        for r in results
        if r["result"] == ComparisonResult.PCLOCATOR_MORE_GENERAL.name
    ]
    if pclocator_general_cases:
        lines.extend(
            [
                "=" * 80,
                f"SAMPLE: PCLOCATOR MORE GENERAL (showing {min(sample_size, len(pclocator_general_cases))} random of {len(pclocator_general_cases)})",
                "=" * 80,
                "",
            ]
        )
        sample = random.sample(
            pclocator_general_cases, min(sample_size, len(pclocator_general_cases))
        )
        for case in sample:
            lines.extend(
                [
                    f"CVE: {case['cve_id']}",
                    f"Patch: {case['patch_id']}",
                    f"  PClocator:  {case['pclocator_flag']}",
                    f"  Patchlens:  {case['patchlens_normalized']}",
                    "",
                ]
            )

    # Add sample cases where flags are incomparable
    incomparable_cases = [
        r for r in results if r["result"] == ComparisonResult.INCOMPARABLE.name
    ]
    if incomparable_cases:
        lines.extend(
            [
                "=" * 80,
                f"SAMPLE: INCOMPARABLE (showing {min(sample_size, len(incomparable_cases))} random of {len(incomparable_cases)})",
                "=" * 80,
                "",
            ]
        )
        sample = random.sample(
            incomparable_cases, min(sample_size, len(incomparable_cases))
        )
        for case in sample:
            lines.extend(
                [
                    f"CVE: {case['cve_id']}",
                    f"Patch: {case['patch_id']}",
                    f"  PClocator:  {case['pclocator_flag']}",
                    f"  Patchlens:  {case['patchlens_normalized']}",
                    "",
                ]
            )

    # Add ALL parse error cases
    parse_error_cases = [
        r for r in results if r["result"] == ComparisonResult.PARSE_ERROR.name
    ]
    if parse_error_cases:
        lines.extend(
            [
                "=" * 80,
                f"ALL PARSE ERRORS ({len(parse_error_cases)} cases)",
                "=" * 80,
                "",
            ]
        )
        for case in parse_error_cases:
            lines.extend(
                [
                    f"CVE: {case['cve_id']}",
                    f"Patch: {case['patch_id']}",
                    f"  PClocator:  {case['pclocator_flag']}",
                    f"  Patchlens:  {case['patchlens_normalized']}",
                    "",
                ]
            )

    return "\n".join(lines)


def write_results_csv(results: list[dict], filepath: Path) -> None:
    """
    Write comparison results to a CSV file.

    Args:
        results: List of comparison result dictionaries.
        filepath: Path to output CSV file.
    """
    fieldnames = [
        "cve_id",
        "patch_id",
        "pclocator_flag",
        "patchlens_flag",
        "patchlens_normalized",
        "result",
    ]

    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)


def main():
    """Main entry point for the automation script."""
    parser = argparse.ArgumentParser(
        description="Compare pclocator and patchlens flags across datasets"
    )
    parser.add_argument(
        "--pclocator",
        "-p",
        type=Path,
        required=True,
        help="Path to pclocator_flags.csv",
    )
    parser.add_argument(
        "--patchlens",
        "-l",
        type=Path,
        required=True,
        help="Path to final_dataset.csv (patchlens)",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=Path("comparison_results.csv"),
        help="Path to output CSV file (default: comparison_results.csv)",
    )
    parser.add_argument(
        "--report",
        "-r",
        type=Path,
        default=None,
        help="Path to output report file (default: print to stdout)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Print progress information"
    )

    args = parser.parse_args()

    # Validate input files
    if not args.pclocator.exists():
        print(f"Error: pclocator file not found: {args.pclocator}", file=sys.stderr)
        sys.exit(1)
    if not args.patchlens.exists():
        print(f"Error: patchlens file not found: {args.patchlens}", file=sys.stderr)
        sys.exit(1)

    # Read CSV files
    if args.verbose:
        print(f"Reading pclocator flags from: {args.pclocator}")
    pclocator_flags = read_pclocator_csv(args.pclocator)

    if args.verbose:
        print(f"Reading patchlens flags from: {args.patchlens}")
    patchlens_flags = read_patchlens_csv(args.patchlens)

    if args.verbose:
        print(f"Found {len(pclocator_flags)} pclocator entries")
        print(f"Found {len(patchlens_flags)} patchlens entries")
        common = len(set(pclocator_flags.keys()) & set(patchlens_flags.keys()))
        print(f"Found {common} common entries to compare")

    # Compare datasets
    if args.verbose:
        print("Comparing flags...")
    comparator = FlagComparator()
    results = compare_datasets(pclocator_flags, patchlens_flags, comparator)

    # Write output CSV
    if args.verbose:
        print(f"Writing results to: {args.output}")
    write_results_csv(results, args.output)

    # Generate and output summary
    summary = generate_summary(results)

    if args.report:
        if args.verbose:
            print(f"Writing report to: {args.report}")
        with open(args.report, "w", encoding="utf-8") as f:
            f.write(summary)
    else:
        print(summary)

    if args.verbose:
        print("Done!")


if __name__ == "__main__":
    main()
