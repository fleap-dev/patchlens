#!/usr/bin/env -S uv --quiet run --script
# /// script
# requires-python = ">=3.13"
# dependencies = [
# ]
# ///

import argparse
import os
import sqlite3


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
            cve_count DESC;
    """

    cursor = db.cursor()
    cursor.execute(query)

    output = "\n"

    for ref_count, cve_count in cursor.fetchall():
        output += f"  - {cve_count} with {ref_count} refs\n"

    return output


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

    output = "\n"

    for value, freq in cursor.fetchall():
        output += f" - {value}: {freq}\n"

    return output


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
