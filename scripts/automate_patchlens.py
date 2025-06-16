#!/usr/bin/env -S uv --quiet run --script
# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "requests",
#     "z3-solver",
# ]
# ///

import argparse
import os
import re
import sqlite3
import subprocess
from dataclasses import dataclass
from datetime import datetime
from typing import List, Literal, Optional, Tuple

import requests
from simplifier import ExpressionSimplifier


@dataclass
class PatchRow:
    patch_id: str
    cve_id: str
    configurations: str
    source: Literal["github", "patchdb"]
    patch_file: str | None
    github_patch_url: str | None


@dataclass
class FlagRow:
    patch_id: str
    status: Literal["ok", "CheckoutError", "PatchlensError", "DoesNotModifyCSource"]
    flag: str | None
    error: str | None


class CheckoutError(Exception):
    """Raised when the git checkout command fails."""

    pass


class PatchlensError(Exception):
    """Raised when the patchlens tool fails."""

    pass


class DoesNotModifyCSource(Exception):
    """Raised when the patch does not modify a C source file."""

    pass


def setup_tables(db: sqlite3.Connection):
    cursor = db.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS "flags" (
            "run_started_at" DATETIME NOT NULL,
            "patchlens_version" TEXT NOT NULL,
            "patch_id" TEXT NOT NULL REFERENCES "patches"("id"),
            "status" TEXT NOT NULL,
            "flag" TEXT,
            "error" TEXT
        )
    """)
    db.commit()


def insert_flags(
    db: sqlite3.Connection,
    flags: List[FlagRow],
    run_started_at: datetime,
    patchlens_version: str,
):
    query = """
        INSERT INTO "flags" (
            "run_started_at",
            "patchlens_version",
            "patch_id",
            "status",
            "flag",
            "error"
        ) VALUES (?, ?, ?, ?, ?, ?)
    """
    db.executemany(
        query,
        [
            (
                run_started_at.isoformat(),
                patchlens_version,
                f.patch_id,
                f.status,
                f.flag,
                f.error,
            )
            for f in flags
        ],
    )
    db.commit()


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


def get_patches(db: sqlite3.Connection, product: str) -> list[PatchRow]:
    cursor = db.cursor()
    cursor.execute(
        """
           SELECT
                "patches"."id",
                "patches"."cve_id",
                "cves"."configurations",
                "patches"."source",
                "patches"."github_patch_url",
                "patches"."patch_file"
            FROM "patches"
            JOIN "cves" ON "cves"."cve_id" = "patches"."cve_id"
            WHERE
                "calculated_product" = ?
            ORDER BY "cves"."year" DESC
        """,
        [product],
    )
    results = cursor.fetchall()
    rows = []
    for row in results:
        rows.append(
            PatchRow(
                patch_id=row[0],
                cve_id=row[1],
                configurations=row[2],
                source=row[3],
                github_patch_url=row[4],
                patch_file=row[5],
            )
        )
    return rows


def download_patch_from_github(url: str, output_path: str) -> str:
    response = requests.get(url + ".patch")
    if response.status_code != 200:
        raise ValueError(f"Failed to download patch from {url}")
    with open(output_path, "wb") as f:
        f.write(response.content)
    return output_path


def process_patch(
    repo_path: str,
    patch_info: PatchRow,
    patches_folder: str,
    patchlens_executable: str,
    expand_building_flags_with: Optional[str],
) -> str:
    patch_file = patch_info.patch_file

    if patch_info.patch_file is not None:
        patch_file = os.path.join(patches_folder, patch_info.patch_file)
    else:
        if patch_info.github_patch_url is None:
            raise ValueError("No patch file or github URL provided")
        github_patches_folder = os.path.join(patches_folder, "github")
        if not os.path.isdir(github_patches_folder):
            os.makedirs(github_patches_folder)
        patch_file = download_patch_from_github(
            patch_info.github_patch_url,
            os.path.join(github_patches_folder, patch_info.patch_id + ".txt"),
        )

    try:
        rev, _ = get_patch_info(patch_file)
    except UnicodeDecodeError:
        raise CheckoutError(f"Failed to decode UTF-8 in patch file {patch_file}")

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
        command = (
            [
                patchlens_executable,
                "-e",
                expand_building_flags_with,
                "analyze-git",
                repo_path,
                patch_file,
            ]
            if expand_building_flags_with
            else [patchlens_executable, "analyze-git", repo_path, patch_file]
        )
        proc = subprocess.run(
            command,  # Command to run (as a string)
            cwd=repo_path,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            decoded = proc.stdout.decode("utf-8")
            simplifier = ExpressionSimplifier()
            simp = simplifier.simplify(decoded)
            print(f"{decoded} -> {simp}")
            return simp
        except UnicodeError as error:
            raise PatchlensError(
                f"Invalid unicode output from patchlens on {rev}: {error}"
            )
    except subprocess.CalledProcessError as error:
        if error.stderr:
            try:
                decoded: str = error.stderr.decode("utf-8")
                if "this patch modifies a file that is not a c file" in decoded:
                    raise DoesNotModifyCSource(
                        f"Patch does not modify a C source file on {rev}: {error}"
                    )
            except UnicodeError as _:
                pass
        raise PatchlensError(
            f"Error processing commit {rev}: {error}\nSTDOUT: {error.stdout}\nSTDERR: {error.stderr}"
        )


def get_patchlens_version(patchlens_executable):
    command = [patchlens_executable, "--version"]
    proc = subprocess.run(
        command,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        decoded = proc.stdout.decode("utf-8")
        return decoded.replace("\n", "").replace("\r", "")
    except Exception as error:
        raise PatchlensError(f"Error getting patchlens version: {error}")


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
        "-E",
        "--expand-building-flags-with",
        type=str,
        required=False,
        help="Program that will be used to expand the building flags. This script will execute <program> passing <path_to_file> as the first argument.",
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
    expand_building_flags_with: Optional[str] = args.expand_building_flags_with

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

    setup_tables(db)

    patches = get_patches(db, product)

    print(f"Found {len(patches)} CVEs for product {product}!")

    patchlens_version = get_patchlens_version(custom_patchlens_path)
    run_started_at = datetime.now()

    processed_count = 0
    total = len(patches)
    for patch in patches:
        try:
            result = process_patch(
                repository_path,
                patch,
                patches_folder,
                custom_patchlens_path,
                expand_building_flags_with,
            )

            # Ensure the result does not contain any newline to avoid corrupting the CSV structure
            result = result.replace("\n", "").replace("\r", "")
            insert_flags(
                db,
                [
                    FlagRow(
                        patch_id=patch.patch_id, status="ok", flag=result, error=None
                    )
                ],
                run_started_at,
                patchlens_version,
            )
            print(f"\r[FLAGS] {patch.cve_id}/{patch.patch_id} = {result}")
        except CheckoutError as error:
            print(
                f"\r[ERROR] Checkout error for {patch.cve_id}/{patch.patch_id}: {error}"
            )
            insert_flags(
                db,
                [
                    FlagRow(
                        patch_id=patch.patch_id,
                        status="CheckoutError",
                        flag=None,
                        error=error.__str__(),
                    )
                ],
                run_started_at,
                patchlens_version,
            )
        except PatchlensError as error:
            print(
                f"\r[ERROR] Patchlens failed on {patch.cve_id}/{patch.patch_id}: {error}"
            )
            insert_flags(
                db,
                [
                    FlagRow(
                        patch_id=patch.patch_id,
                        status="PatchlensError",
                        flag=None,
                        error=error.__str__(),
                    )
                ],
                run_started_at,
                patchlens_version,
            )
        except DoesNotModifyCSource as error:
            print(
                f"\r[ERROR] Patch does not modify only C source files {patch.cve_id}/{patch.patch_id}: {error}"
            )
            insert_flags(
                db,
                [
                    FlagRow(
                        patch_id=patch.patch_id,
                        status="DoesNotModifyCSource",
                        flag=None,
                        error=error.__str__(),
                    )
                ],
                run_started_at,
                patchlens_version,
            )
        finally:
            processed_count += 1

        print(f"\rProgress: {processed_count}/{total}", end="")

    print()

    db.close()

    print("Completed.")


if __name__ == "__main__":
    main()
