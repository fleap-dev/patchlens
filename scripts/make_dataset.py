#!/usr/bin/env -S uv --quiet run --script
# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "cpeparser",
#     "gdown",
# ]
# ///

import argparse
import os
import sys
import sqlite3
import csv
import gdown
import tempfile
import zipfile
import ast
from collections import Counter
from cpeparser import CpeParser
from typing import Any, Optional

CVE_DATA_DRIVE_URL = (
    "https://drive.google.com/file/d/1mD9WsWyd7Nk_NyD3aPTpuFJxABm7pVUT/view?usp=sharing"
)
PATCHDB_DRIVE_URL = (
    "https://drive.google.com/file/d/1gJQd5Kk6kI0z71D7HUaxM5KzbyWmmqwQ/view?usp=sharing"
)


def setup_tables(db: sqlite3.Connection):
    cursor = db.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS "cves" (
            "cve_id" TEXT PRIMARY KEY,
            "calculated_product" TEXT NOT NULL,
            "year" INT NOT NULL,
            "assigner" TEXT,
            "problem_type" TEXT,
            "references" TEXT,
            "description" TEXT,
            "configurations" TEXT,
            "severity" TEXT,
            "cve_exploitability_score" REAL,
            "cve_impact_score" REAL,
            "patch_file" TEXT NOT NULL
        )
    """)
    db.commit()


def safe_str_to_float(s: str) -> float | None:
    try:
        return float(s) if s.strip() else None
    except ValueError:
        return None


def calculate_probable_product(configurations_string: str) -> Optional[str]:
    cpe = CpeParser()
    configurations = ast.literal_eval(configurations_string)

    def parse_cpe(conf: str):
        res = cpe.parser(conf)
        vendor = res["vendor"]
        product = res["product"]
        return f"{vendor}/{product}"

    products = list(map(parse_cpe, configurations))
    if len(products) == 0:
        return None
    most_common = Counter(products).most_common(1)[0][0]
    return most_common


def read_cve_data(path: str) -> dict[str, dict[str, str | float | None]]:
    with open(path, mode="r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        entries = dict()
        skipped = 0
        processed = 0
        for row in reader:
            print(f"\rProcessed {processed} rows...", end="")
            calculated_product = calculate_probable_product(row["configurations"])
            if calculated_product is None:
                skipped += 1
                continue
            entry = {
                "cve_id": row["cve_id"],
                "calculated_product": calculated_product,
                "assigner": row["assigner"],
                "problem_type": row["problemtype"],
                "references": row["references"],
                "description": row["description"],
                "configurations": row["configurations"],
                "severity": row["severity"],
                "cve_exploitability_score": safe_str_to_float(
                    row["cve_exploitability_score"]
                ),
                "cve_impact_score": safe_str_to_float(row["cve_impact_score"]),
            }
            entries[row["cve_id"]] = entry
            processed += 1

        print()

        if skipped > 0:
            print(
                f"[WARN] {skipped} cves were skipped due to not having a correct configurations column"
            )
        return entries


def read_patch_db(path: str) -> dict[str, str]:
    patches = dict()
    for filename in os.listdir(path):
        cve, _, _ = filename.rpartition("-")
        patches[cve] = filename
    return patches


def insert_cves(db: sqlite3.Connection, cves: list[dict[str, Any]]):
    query = """
        INSERT INTO "cves" (
            cve_id,
            calculated_product,
            year,
            assigner,
            problem_type,
            "references",
            description,
            configurations,
            severity,
            cve_exploitability_score,
            cve_impact_score,
            patch_file
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(cve_id) DO UPDATE SET
            calculated_product = excluded.calculated_product,
            year = excluded.year,
            assigner = excluded.assigner,
            problem_type = excluded.problem_type,
            "references" = excluded."references",
            description = excluded.description,
            configurations = excluded.configurations,
            severity = excluded.severity,
            cve_exploitability_score = excluded.cve_exploitability_score,
            cve_impact_score = excluded.cve_impact_score,
            patch_file = excluded.patch_file;
    """
    values = [
        (
            cve["cve_id"],
            cve["calculated_product"],
            int(cve["cve_id"].split("-")[1]),
            cve["assigner"],
            cve["problem_type"],
            cve["references"],
            cve["description"],
            cve["configurations"],
            cve["severity"],
            cve["cve_exploitability_score"],
            cve["cve_impact_score"],
            cve["patch_file"],
        )
        for cve in cves
    ]
    db.executemany(query, values)
    db.commit()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--cve-data",
        default="data/cvedata.csv",
        help="The path for the CSV file containing all the CVEs",
    )
    parser.add_argument(
        "--patches-folder",
        default="data/patches",
        help="The folder where the patches are located",
    )
    parser.add_argument(
        "--output",
        default="data/cve-dataset.db",
        help="The output file for the database",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Do not insert the data into de database (read-only mode)",
    )

    args = parser.parse_args()

    cve_data_file: str = args.cve_data
    patches_folder: str = args.patches_folder
    output_file: str = args.output
    dry_run: bool = args.dry_run

    if not os.path.exists(cve_data_file):
        print("CVE data file not found! Downloading...")
        gdown.download(CVE_DATA_DRIVE_URL, cve_data_file, quiet=False, fuzzy=True)
        print("Downloaded CVE information!")

    if not os.path.exists(patches_folder):
        print("Patches folder not found! Downloading patchdb archive...")
        with tempfile.NamedTemporaryFile(delete=True, suffix=".zip") as tmp:
            gdown.download(PATCHDB_DRIVE_URL, tmp, quiet=False, fuzzy=True)
            print("Extracting patches from patchdb archive...")
            os.mkdir(patches_folder)
            with zipfile.ZipFile(tmp, "r") as zip_ref:
                for member in zip_ref.namelist():
                    # Check if the member path starts with the target folder's path
                    FOLDER_PREFIX = "patchDB/security/cve/"
                    if member.startswith(FOLDER_PREFIX):
                        filename = member[len(FOLDER_PREFIX) :].strip()
                        if filename == "":
                            continue
                        print("Extracting", filename)
                        target_path = os.path.join(patches_folder, filename)
                        with (
                            zip_ref.open(member) as source,
                            open(target_path, "wb") as target,
                        ):
                            target.write(source.read())
        print("Downloaded patches from patchdb!")

    csv.field_size_limit(sys.maxsize)

    db = sqlite3.connect(output_file)
    setup_tables(db)
    patches = read_patch_db(patches_folder)
    cve_data = read_cve_data(cve_data_file)

    print("Processing patches and cves...")

    total = len(patches)
    progress = 0
    cves_with_patches = list()
    for cve in patches:
        print(f"\rProgress {progress}/{total}", end="")
        if cve in cve_data:
            patch_file = patches[cve]
            cve_info = cve_data[cve]
            cves_with_patches.append(
                {
                    "cve_id": cve_info["cve_id"],
                    "calculated_product": cve_info["calculated_product"],
                    "assigner": cve_info["assigner"],
                    "problem_type": cve_info["problem_type"],
                    "references": cve_info["references"],
                    "description": cve_info["description"],
                    "configurations": cve_info["configurations"],
                    "severity": cve_info["severity"],
                    "cve_exploitability_score": cve_info["cve_exploitability_score"],
                    "cve_impact_score": cve_info["cve_impact_score"],
                    "patch_file": patch_file,
                }
            )
        else:
            print("\rWarning: CVE", cve, "not found in the CVE DATA!")
        progress += 1

    print()
    print(
        f"Saving {len(cves_with_patches)} CVEs with their respective patches into {output_file}"
    )

    if dry_run:
        print("Skipping inserting data into database because of dry-run mode.")
    else:
        insert_cves(db, cves_with_patches)

    print("Completed.")


if __name__ == "__main__":
    main()
