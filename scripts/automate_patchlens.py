#!/usr/bin/env -S uv --quiet run --script
# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "requests",
#     "z3-solver",
# ]
# ///

import argparse
import io
import os
import re
import sqlite3
import subprocess
import tempfile
import time
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
    source: Literal["github", "patchdb", "git-kernel"]
    patch_file: str | None
    github_patch_url: str | None


@dataclass
class FlagRow:
    patch_id: str
    status: Literal[
        "ok",
        "CheckoutError",
        "PatchlensError",
        "DoesNotModifyCSource",
        "ModifiesHeaderFiles",
    ]
    flag: str | None
    error: str | None
    time_processing: int | None
    checkout_time: int | None


class CheckoutError(Exception):
    """Raised when the git checkout command fails."""

    pass


class PatchlensError(Exception):
    """Raised when the patchlens tool fails."""

    pass


class DoesNotModifyCSource(Exception):
    """Raised when the patch does not modify a C source file."""

    pass


class ModifiesHeaderFiles(Exception):
    """Raised when the patch modify a header file."""

    pass


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
            "error",
            "time_processing_ms",
            "checkout_time_ms"
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
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
                f.time_processing,
                f.checkout_time,
            )
            for f in flags
        ],
    )
    db.commit()


def get_patch_info(patch_file_path: str) -> Tuple[Optional[str], List[str]]:
    """
    Parses the patch file and returns:
      - The commit revision from the "From <revision>" line (or None if not found).
      - A list of modified file paths from diff headers. Renamed files appear under both names.

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
                # The new path (group 2), plus the old one (group 1) for renames:
                # `patch` reads the old file, PatchLens's expanders look up the new one.
                old_file, new_file = diff_match.group(1), diff_match.group(2)
                modified_files.append(new_file)
                if old_file != new_file:
                    modified_files.append(old_file)

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


def download_patch(url: str, output_path: str) -> str:
    response = requests.get(url)
    if response.status_code != 200:
        raise ValueError(f"Failed to download patch from {url}")
    with open(output_path, "wb") as f:
        f.write(response.content)
    return output_path


# Writes the patch of a commit in the local clone, in the mail format `analyze-git` expects.
def format_patch(repo_path: str, rev: str, output_path: str) -> str:
    # `<rev>^!` limits the output to `rev` itself. With `-1 <rev>`, a merge commit would
    # yield the patch of an unrelated commit, because `format-patch` skips merges.
    patch = subprocess.run(
        ["git", "format-patch", "--stdout", f"{rev}^!"],
        cwd=repo_path,
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    if not patch:
        raise CheckoutError(f"Commit {rev} has no patch (merge or empty commit)")
    with open(output_path, "wb") as f:
        f.write(patch)
    return output_path


def commit_exists(repo_path: str, rev: str) -> bool:
    proc = subprocess.run(
        ["git", "cat-file", "-e", f"{rev}^{{commit}}"],
        cwd=repo_path,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return proc.returncode == 0


# Writes to `output_dir` the files PatchLens reads with `-e linux` at `rev`, as a checkout would.
# These are the patched files, plus `Kbuild`, `Kbuild.src` and `Makefile` in each of their parent
# directories up to the root. Paths missing at `rev` are left out, so `find_makefile`
# (`core/src/build_expanders/linux.rs`) picks the same one as in a checkout. If the Linux
# expander starts reading other files, this list must change too.
def write_linux_tree(
    repo_path: str, rev: str, patched_files: List[str], output_dir: str
) -> None:
    if not commit_exists(repo_path, rev):
        raise CheckoutError(f"Revision {rev} not found in the repository")

    paths = set(patched_files)
    for file in patched_files:
        directory = os.path.dirname(file)
        while True:
            for name in ("Kbuild", "Kbuild.src", "Makefile"):
                paths.add(os.path.join(directory, name))
            if not directory:
                break
            directory = os.path.dirname(directory)

    # One `cat-file --batch` call answers every lookup, in order, with the raw blob bytes
    # (Linux has no checkout filters).
    queries = sorted(paths)
    output = io.BytesIO(
        subprocess.run(
            ["git", "cat-file", "--batch"],
            cwd=repo_path,
            input="".join(f"{rev}:{path}\n" for path in queries).encode(),
            check=True,
            stdout=subprocess.PIPE,
        ).stdout
    )
    for path in queries:
        # Each answer is "<query> missing\n" or "<oid> <type> <size>\n<content>\n".
        header = output.readline().rstrip(b"\n")
        if header.endswith(b" missing"):
            continue
        _, object_type, size = header.split()
        content = output.read(int(size))
        output.read(1)
        if object_type != b"blob":
            continue
        destination = os.path.join(output_dir, path)
        os.makedirs(os.path.dirname(destination), exist_ok=True)
        with open(destination, "wb") as f:
            f.write(content)


# Runs PatchLens on `patch_file` against the source tree at `tree`, and returns the
# simplified flag and the time PatchLens took.
def run_patchlens(
    patchlens_executable: str,
    expand_building_flags_with: Optional[str],
    tree: str,
    patch_file: str,
    rev: Optional[str],
) -> Tuple[str, float]:
    try:
        command = (
            [
                patchlens_executable,
                "-e",
                expand_building_flags_with,
                "analyze-git",
                tree,
                patch_file,
            ]
            if expand_building_flags_with
            else [patchlens_executable, "analyze-git", tree, patch_file]
        )
        patchlens_time_start = time.perf_counter()
        proc = subprocess.run(
            command,  # Command to run (as a string)
            cwd=tree,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            patchlens_time_end = time.perf_counter()
            patchlens_time_ms = patchlens_time_end - patchlens_time_start
            decoded = proc.stdout.decode("utf-8")
            simplifier = ExpressionSimplifier()
            simp = simplifier.simplify(decoded)
            print(f"{decoded} -> {simp}")
            return (simp, patchlens_time_ms)
        except UnicodeError as error:
            raise PatchlensError(
                f"Invalid unicode output from patchlens on {rev}: {error}"
            )
    except subprocess.CalledProcessError as error:
        if error.stderr:
            try:
                decoded: str = error.stderr.decode("utf-8")
                if (
                    "flag expansion for header files is still not implemented"
                    in decoded
                ):
                    raise ModifiesHeaderFiles(
                        f"Patch modifies a C header file on {rev}: {error}"
                    )
                if "this patch modifies a file that is not a c file" in decoded:
                    raise DoesNotModifyCSource(
                        f"Patch does not modify a C source file on {rev}: {error}"
                    )
            except UnicodeError as _:
                pass
        raise PatchlensError(
            f"Error processing commit {rev}: {error}\nSTDOUT: {error.stdout}\nSTDERR: {error.stderr}"
        )


def process_patch(
    repo_path: str,
    patch_info: PatchRow,
    patches_folder: str,
    patchlens_executable: str,
    expand_building_flags_with: Optional[str],
) -> (str, int, int):
    patch_file = patch_info.patch_file

    if patch_info.patch_file is not None:
        patch_file = os.path.join(patches_folder, patch_info.patch_file)
    elif patch_info.github_patch_url is not None:
        github_patches_folder = os.path.join(patches_folder, "github")
        if not os.path.isdir(github_patches_folder):
            os.makedirs(github_patches_folder)
        patch_file = download_patch(
            patch_info.github_patch_url + ".patch",
            os.path.join(github_patches_folder, patch_info.patch_id + ".txt"),
        )
    elif patch_info.source == "git-kernel":
        # Most git.kernel.org refs point to stable backports (`/stable/c/<hash>`), which are
        # missing from mainline clones and can't be checked out. The rest are in the clone,
        # so their patch comes from `git format-patch` instead of a download.
        if not commit_exists(repo_path, patch_info.patch_id):
            raise CheckoutError(
                f"Commit {patch_info.patch_id} not found in the repository"
            )
        git_kernel_patches_folder = os.path.join(patches_folder, "git-kernel")
        if not os.path.isdir(git_kernel_patches_folder):
            os.makedirs(git_kernel_patches_folder)
        patch_file = format_patch(
            repo_path,
            patch_info.patch_id,
            os.path.join(git_kernel_patches_folder, patch_info.patch_id + ".txt"),
        )
    else:
        raise ValueError("No patch file or patch URL provided")

    try:
        rev, modified_files = get_patch_info(patch_file)
    except UnicodeDecodeError:
        raise CheckoutError(f"Failed to decode UTF-8 in patch file {patch_file}")

    # With `-E linux`, PatchLens runs on a temp dir holding only the files it reads at `rev~1`,
    # instead of a checkout of the whole tree. This takes milliseconds instead of about 1 s, and
    # leaves the repository untouched. The other expanders read more of the tree (FFmpeg reads
    # every Makefile), so they keep the clean and checkout below.
    if expand_building_flags_with == "linux":
        with tempfile.TemporaryDirectory(prefix="patchlens-linux-") as tree:
            checkout_start = time.perf_counter()
            write_linux_tree(repo_path, f"{rev}~1", modified_files, tree)
            checkout_time_ms = time.perf_counter() - checkout_start
            flag, patchlens_time_ms = run_patchlens(
                patchlens_executable, expand_building_flags_with, tree, patch_file, rev
            )
            return (flag, patchlens_time_ms, checkout_time_ms)

    checkout_start = time.perf_counter()
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
    checkout_end = time.perf_counter()
    checkout_time_ms = checkout_end - checkout_start

    flag, patchlens_time_ms = run_patchlens(
        patchlens_executable, expand_building_flags_with, repo_path, patch_file, rev
    )
    return (flag, patchlens_time_ms, checkout_time_ms)


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

    # Datasets built without the patchdb source have no patches folder.
    # In that case, it only stores the downloaded patches
    if not os.path.isdir(patches_folder):
        print(f"[WARN] Patches folder not found at {patches_folder}! Creating...")
        os.makedirs(patches_folder)

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

    patches = get_patches(db, product)

    print(f"Found {len(patches)} CVEs for product {product}!")

    patchlens_version = get_patchlens_version(custom_patchlens_path)
    run_started_at = datetime.now()

    processed_count = 0
    total = len(patches)
    for patch in patches:
        try:
            print(
                f"Processing {patch.patch_file or patch.github_patch_url or f'{patch.source}/{patch.patch_id}'} for {patch.cve_id}"
            )
            (result_flag, patchlens_time_ms, checkout_time_ms) = process_patch(
                repository_path,
                patch,
                patches_folder,
                custom_patchlens_path,
                expand_building_flags_with,
            )

            # Ensure the result does not contain any newline to avoid corrupting the CSV structure
            result_flag = result_flag.replace("\n", "").replace("\r", "")
            insert_flags(
                db,
                [
                    FlagRow(
                        patch_id=patch.patch_id,
                        status="ok",
                        flag=result_flag,
                        error=None,
                        time_processing=patchlens_time_ms,
                        checkout_time=checkout_time_ms,
                    )
                ],
                run_started_at,
                patchlens_version,
            )
            print(f"\r[FLAGS] {patch.cve_id}/{patch.patch_id} = {result_flag}")
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
                        time_processing=None,
                        checkout_time=None,
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
                        time_processing=None,
                        checkout_time=None,
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
                        time_processing=None,
                        checkout_time=None,
                    )
                ],
                run_started_at,
                patchlens_version,
            )
        except ModifiesHeaderFiles as error:
            print(
                f"\r[ERROR] Patch modifies C header files {patch.cve_id}/{patch.patch_id}: {error}"
            )
            insert_flags(
                db,
                [
                    FlagRow(
                        patch_id=patch.patch_id,
                        status="ModifiesHeaderFiles",
                        flag=None,
                        error=error.__str__(),
                        time_processing=None,
                        checkout_time=None,
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

    print(f"Completed run {run_started_at}.")


if __name__ == "__main__":
    main()
