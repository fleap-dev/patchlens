#!/usr/bin/env -S uv --quiet run --script
# /// script
# requires-python = ">=3.13"
# dependencies = [
# ]
# ///

import argparse
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


def most_common_products(db: sqlite3.Connection) -> str:
    query = """
        SELECT "calculated_product", COUNT(*) AS frequency
        FROM "cves"
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


STATISTICS_FUNCTIONS = {
    "Total count of CVEs": cve_count,
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

    db = sqlite3.connect(database_file)

    for stat, fn in STATISTICS_FUNCTIONS.items():
        res = fn(db)
        print(f"{stat}: {res}")


if __name__ == "__main__":
    main()
