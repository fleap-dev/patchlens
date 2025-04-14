#!/usr/bin/env -S uv --quiet run --script
# /// script
# requires-python = ">=3.13"
# dependencies = [
# ]
# ///

import argparse
from dataclasses import dataclass
import sqlite3
import os
import csv
import ast
from typing import List
import re


@dataclass
class CveFlag:
    cve_id: str
    status: str
    flag: str


def extract_building_files(input_str: str) -> List[str]:
    """
    Extracts file paths from all building("file") occurrences in the given string.

    Args:
        input_str (str): The input string containing building() expressions.

    Returns:
        list of str: A list of file path strings extracted from the building functions.
    """
    pattern = r'building\("([^"]+)"\)'
    return re.findall(pattern, input_str)


def get_cve_description(db: sqlite3.Connection, cve_id: str) -> str:
    query = """
        SELECT "description"
        FROM "cves"
        WHERE "cve_id" = ?
    """

    cursor = db.cursor()
    cursor.execute(query, [cve_id])

    for row in cursor.fetchall():
        desc_raw = row[0]
        desc: List[str] = ast.literal_eval(desc_raw)
        return "\n".join(desc)

    raise Exception(f"failed to get CVE {cve_id} from the database")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--database",
        default="data/cve-dataset.db",
        help="The location of the database containing the CVEs and their patches",
    )
    parser.add_argument(
        "flags-file",
        help="The location of the database containing the CVEs and their patches",
    )

    args = parser.parse_args()
    database_file: str = args.database
    flags_file: str = getattr(args, "flags-file")

    if not os.path.exists(database_file):
        print(f"Database file at {database_file} does not exist!")
        return

    if not os.path.exists(flags_file):
        print(f"Database file at {database_file} does not exist!")
        return

    db = sqlite3.connect(database_file)

    total_processed = 0
    total_that_contain = 0
    with open(flags_file, newline="") as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            cve_flag = CveFlag(row[0], row[1], row[2])
            if cve_flag.status == "ok":
                cve_description = get_cve_description(db, cve_flag.cve_id)
                files_building = extract_building_files(cve_flag.flag)
                search_terms = list(
                    map(lambda path: path.split("/")[-1], files_building)
                )
                for search in search_terms:
                    if cve_description.find(search) != -1:
                        total_that_contain += 1
                        break
            total_processed += 1

    print(f"Processed {total_processed} CVEs!")
    print(
        f"CVEs with at least one of their files in their description: {total_that_contain}"
    )
    print(
        f"Ratio: {total_that_contain}/{total_processed} = {total_that_contain / total_processed}"
    )

    db.close()


if __name__ == "__main__":
    main()
