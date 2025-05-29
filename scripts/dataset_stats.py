#!/usr/bin/env -S uv --quiet run --script
# /// script
# requires-python = ">=3.13"
# dependencies = [
# ]
# ///

import argparse
import os
import sqlite3
from typing import Any, Sequence


def format_matrix(matrix: Sequence[Sequence[Any]], padding: int = 1) -> str:
    """
    Returns a formatted string of the matrix with ASCII borders and aligned columns.

    Args:
        matrix: A sequence of sequences representing rows of the matrix.
        padding: Number of spaces to add on each side of a cell.

    Returns:
        A single string containing the entire bordered table.
    """
    if not matrix:
        return "<empty matrix>"

    # Determine number of columns
    num_cols = max(len(row) for row in matrix)
    # Compute maximum width for each column
    col_widths = [0] * num_cols
    for row in matrix:
        for idx in range(num_cols):
            cell = str(row[idx]) if idx < len(row) else ""
            col_widths[idx] = max(col_widths[idx], len(cell))

    # Helper to create a border line
    def make_border() -> str:
        parts = ["+" + "-" * (col_widths[i] + 2 * padding) for i in range(num_cols)]
        return "".join(parts) + "+"

    # Build all lines
    lines = []
    top_border = make_border()
    lines.append("  " + top_border)
    for row in matrix:
        row_cells = []
        for idx in range(num_cols):
            cell = str(row[idx]) if idx < len(row) else ""
            content = " " * padding + cell.ljust(col_widths[idx]) + " " * padding
            row_cells.append("|" + content)
        lines.append("  " + "".join(row_cells) + "|")
        lines.append("  " + make_border())

    return "\n".join(lines)


def cve_count(db: sqlite3.Connection) -> str:
    query = """
        SELECT COUNT(*)
        FROM "cves"
    """

    cursor = db.cursor()
    cursor.execute(query)

    for value in cursor.fetchall():
        return f"{value[0]}"
    return "failed"


def cve_with_patch_ref_count(db: sqlite3.Connection) -> str:
    query = """
        SELECT COUNT(*)
        FROM "cves"
        WHERE "patch_ref_count" > 0
    """

    cursor = db.cursor()
    cursor.execute(query)

    for value in cursor.fetchall():
        return f"{value[0]}"
    return "failed"


def patch_ref_count_distrib(db: sqlite3.Connection) -> str:
    query = """
        SELECT
            COALESCE(patch_ref_count, 0) AS reference_count,
            COUNT(*) AS cve_count
        FROM
            cves
        GROUP BY
            reference_count
        ORDER BY
            reference_count;
    """

    cursor = db.cursor()
    cursor.execute(query)

    matrix = [["Number of patch refs", "Number of CVEs"]]

    for ref_count, cve_count in cursor.fetchall():
        matrix.append([f"{ref_count}", f"{cve_count}"])

    return "\n" + format_matrix(matrix)


def patch_count(db: sqlite3.Connection) -> str:
    query = """
        SELECT COUNT(*)
        FROM "patches"
    """

    cursor = db.cursor()
    cursor.execute(query)

    for value in cursor.fetchall():
        return f"{value[0]}"
    return "failed"


def most_common_products(db: sqlite3.Connection) -> str:
    query = """
        SELECT "calculated_product", COUNT(*) AS frequency
        FROM "cves"
        JOIN "patches" on "cves"."cve_id" = "patches"."cve_id"
        GROUP BY "calculated_product"
        ORDER BY frequency DESC
        LIMIT 10
    """

    cursor = db.cursor()
    cursor.execute(query)

    matrix = [["Product", "Number of patches"]]

    for value, freq in cursor.fetchall():
        matrix.append([f"{value}", f"{freq}"])

    return "\n" + format_matrix(matrix)


def github_ref_patch_count(db: sqlite3.Connection) -> str:
    query = """
        SELECT COUNT(*)
        FROM "patches"
        WHERE "github_patch_url" IS NOT NULL;
    """

    cursor = db.cursor()
    cursor.execute(query)

    for value in cursor.fetchall():
        return f"{value[0]}"
    return "failed"


def patchdb_patch_count(db: sqlite3.Connection) -> str:
    query = """
        SELECT COUNT(*)
        FROM "patches"
        WHERE "patch_file" IS NOT NULL;
    """

    cursor = db.cursor()
    cursor.execute(query)

    for value in cursor.fetchall():
        return f"{value[0]}"
    return "failed"


STATISTICS_FUNCTIONS = {
    "Total count of CVEs": cve_count,
    "Total count of patches": patch_count,
    "Total amount of patches from github refs": github_ref_patch_count,
    "Total amount of patches from PatchDB": patchdb_patch_count,
    "Total CVEs with at least one reference to a patch": cve_with_patch_ref_count,
    "Distribution of the number of patch references": patch_ref_count_distrib,
    "Most common products": most_common_products,
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--database",
        default="data/cve-dataset.db",
        help="The location of the database containing the CVEs and their patches",
    )

    args = parser.parse_args()

    database_file: str = args.database

    if not os.path.exists(database_file):
        print(f"Database file at {database_file} does not exist!")
        return

    db = sqlite3.connect(database_file)

    for stat, fn in STATISTICS_FUNCTIONS.items():
        res = fn(db)
        print(f"{stat}: {res}")

    db.close()


if __name__ == "__main__":
    main()
