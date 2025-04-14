#!/usr/bin/env -S uv --quiet run --script
# /// script
# requires-python = ">=3.13"
# dependencies = [
# ]
# ///

import argparse
import os
import csv
import re
import subprocess
from dataclasses import dataclass
import sqlite3
from typing import Tuple, List, Optional


@dataclass
class CveRow:
    cve_id: str
    configurations: str
    patch_file: str


def get_patch_info(patch_file_path: str) -> Tuple[Optional[str], List[str]]:
    """
    Parses the patch file and returns:
      - The commit revision from the "From <revision>" line (or None if not found).
      - A list of modified file paths from diff headers.

    :param patch_file_path: Path to the Git patch file.
    :return: A tuple (commit revision, list of modified files).
    """
    commit_revision: Optional[str] = None
    modified_files: List[str] = []

    # Regex pattern to match the commit revision line
    commit_pattern = re.compile(r"^From\s+([a-fA-F0-9]+)")
    # Regex pattern to capture file paths from diff header lines
    diff_header_pattern = re.compile(r"^diff --git a/(.+) b/(.+)$")

    with open(patch_file_path, "r", encoding="utf-8") as file:
        for line in file:
            line = line.rstrip()

            # Get the commit revision if not already found
            if commit_revision is None:
                commit_match = commit_pattern.match(line)
                if commit_match:
                    commit_revision = commit_match.group(1)

            # Capture modified file paths from diff headers
            diff_match = diff_header_pattern.match(line)
            if diff_match:
                # Use the new file path from the diff header (group 2)
                modified_file: str = diff_match.group(2)
                modified_files.append(modified_file)

    return commit_revision, modified_files


def get_cves(db: sqlite3.Connection, product: str) -> list[CveRow]:
    cursor = db.cursor()
    cursor.execute(
        """
           SELECT "cve_id", "configurations", "patch_file" FROM "cves" WHERE "calculated_product" = ? ORDER BY "year" DESC
        """,
        [product],
    )
    results = cursor.fetchall()
    rows = []
    for row in results:
        rows.append(CveRow(row[0], row[1], row[2]))
    return rows


class CheckoutError(Exception):
    """Raised when the git checkout command fails."""

    pass


class PatchlensError(Exception):
    """Raised when the patchlens tool fails."""

    pass


def process_patch(
    repo_path: str, cve_info: CveRow, patches_folder: str, patchlens_executable: str
) -> str:
    patch_file = os.path.join(patches_folder, cve_info.patch_file)
    rev, _ = get_patch_info(patch_file)
    try:
        # Checkout the commit in the repository
        subprocess.run(
            ["git", "clean", "-fd"],
            cwd=repo_path,  # Set the working directory to the repo
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            ["git", "checkout", f"{rev}~1"],
            cwd=repo_path,  # Set the working directory to the repo
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError as error:
        raise CheckoutError(f"Failed to checkout revision {rev}: {error}")

    try:
        # Run your custom command on the checked-out commit
        command = [patchlens_executable, repo_path, patch_file]
        proc = subprocess.run(
            command,  # Command to run (as a string)
            cwd=repo_path,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            decoded = proc.stdout.decode("utf-8")
            return decoded
        except UnicodeError as error:
            raise PatchlensError(
                f"Invalid unicode output from patchlens on {rev}: {error}"
            )
    except subprocess.CalledProcessError as error:
        raise PatchlensError(f"Error processing commit {rev}: {error}\nSTDOUT: {error.stdout}\nSTDERR: {error.stderr}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--patchlens",
        type=str,
        required=False,
        help="Custom path for the patchlens tool",
    )
    parser.add_argument(
        "--database",
        default="data/cve-dataset.db",
        help="The location of the database containing the CVEs and their patches",
    )
    parser.add_argument(
        "--patches-folder",
        default="data/patches",
        help="The folder containing the patches",
    )
    parser.add_argument(
        "--output",
        default="data/flags.csv",
        help="The CSV file to write the output data",
    )
    parser.add_argument(
        "product",
        help="The product you will be automating. E.g. linux/linux_kernel",
    )
    parser.add_argument(
        "repository_path",
        help="The path to the repository of the software being tested",
    )

    args = parser.parse_args()

    database_file: str = args.database
    product: str = args.product
    repository_path: str = os.path.abspath(args.repository_path)
    patches_folder: str = os.path.abspath(args.patches_folder)
    output_file: str = os.path.abspath(args.output)
    custom_patchlens_path: Optional[str] = args.patchlens

    if not os.path.exists(database_file):
        print(f"Database file at {database_file} does not exist!")
        return

    if not os.path.isdir(repository_path):
        print(f"Repository not found at {repository_path}!")
        return

    if not os.path.isdir(patches_folder):
        print(f"Patches folder not found at {patches_folder}!")
        return

    if os.path.exists(output_file):
        print("[WARN] Output file already exists! Appending data...")

    if custom_patchlens_path is None:
        custom_patchlens_path = "patchlens"  # default for a patchlens binary in $PATH
    else:
        custom_patchlens_path = os.path.abspath(custom_patchlens_path)
        if not os.path.exists(custom_patchlens_path):
            print(f"[ERROR] Patchlens binary not found at {custom_patchlens_path}")
            return

    db = sqlite3.connect(database_file)

    cves = get_cves(db, product)

    print(f"Found {len(cves)} CVEs for product {product}!")

    processed_count = 0
    total = len(cves)
    with open(output_file, "w", newline="") as csvfile:
        spamwriter = csv.writer(
            csvfile, delimiter=",", quotechar='"', quoting=csv.QUOTE_ALL
        )
        for cve in cves:
            try:
                result = process_patch(
                    repository_path, cve, patches_folder, custom_patchlens_path
                )

                # Ensure the result does not contain any newline to avoid corrupting the CSV structure
                result = result.replace("\n", "").replace("\r", "")
                spamwriter.writerow([cve.cve_id, "ok", result])
                print(f"\r[FLAGS] {cve.cve_id} = {result}")
            except CheckoutError as error:
                print(f"\r[ERROR] Checkout error for {cve.cve_id}: {error}")
                spamwriter.writerow([cve.cve_id, "CheckoutError", error.__str__()])
            except PatchlensError as error:
                print(f"\r[ERROR] Patchlens failed on {cve.cve_id}: {error}")
                spamwriter.writerow([cve.cve_id, "PatchlensError", error.__str__()])
            finally:
                processed_count += 1

            csvfile.flush()
            print(f"\rProgress: {processed_count}/{total}", end="")

    print()

    db.close()

    print("Completed.")


if __name__ == "__main__":
    main()
