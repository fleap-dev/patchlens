#!/usr/bin/env -S uv --quiet run --script
# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "requests",
#     "z3-solver",
# ]
# ///

import argparse
import ast
from dataclasses import dataclass
import os
import csv
from pathlib import Path
import subprocess
import sys
import time
from typing import cast

from pclocator import ProcessPatchResult, calculate_patch_presence_condition
from simplifier import ExpressionSimplifier
from automate_patchlens import CheckoutError, get_patch_info


def main():
    parser = argparse.ArgumentParser()
    _ = parser.add_argument(
        "--dataset-csv",
        default="final_dataset.csv",
        help="The location of the CSV file containing [cve-id, product, patch_id, flag]",
    )
    _ = parser.add_argument(
        "--patches-folder",
        default="data/patches",
        help="The folder containing the patches",
    )
    _ = parser.add_argument(
        "--output",
        default="data/flags.csv",
        help="The CSV file to write the output data",
    )
    _ = parser.add_argument(
        "product",
        help="The product you will be automating. E.g. linux/linux_kernel",
    )
    _ = parser.add_argument(
        "repository_path",
        help="The path to the repository of the software being tested",
    )

    args = parser.parse_args()

    dataset_path = cast(str, args.dataset_csv)
    patches_folder = Path(os.path.abspath(cast(str, args.patches_folder)))
    output_file = os.path.abspath(cast(str, args.output))
    product = cast(str, args.product)
    repository_path = os.path.abspath(cast(str, args.repository_path))

    if not os.path.exists(dataset_path):
        print(f"Database file at {dataset_path} does not exist!", file=sys.stderr)
        return

    if not os.path.isdir(repository_path):
        print(f"Repository not found at {repository_path}!", file=sys.stderr)
        return

    if not os.path.isdir(patches_folder):
        print(f"Patches folder not found at {patches_folder}!", file=sys.stderr)
        return

    if os.path.exists(output_file):
        print("[WARN] Output file already exists!", file=sys.stderr)
        exit(1)

        # Read the dataset CSV

    with open(output_file, mode="w", newline="") as file:
        writer = csv.writer(file, quoting=csv.QUOTE_ALL)
        writer.writerow(
            [
                "cve_id",
                "product",
                "patch_id",
                "pclocator_flag",
                "debug_raw_flag",
                "debug_file_pcs",
            ]
        )
        idx = 0
        for row in dataset_rows(Path(dataset_path)):
            if row.product == product:
                print(row, file=sys.stderr)
                patch_file = find_patch_file(patches_folder, row)

                if not patch_file:
                    print(
                        f"[WARN] Could not find patch for {row.cve_id}! Skipping...",
                        file=sys.stderr,
                    )
                    continue

                idx += 1

                r = process_patch(patch_file, Path(repository_path))

                if r is not None:
                    simplified_flag, result = r

                    writer.writerow(
                        [
                            row.cve_id,
                            row.product,
                            row.patch_id,
                            simplified_flag,
                            result.raw_flag,
                            repr(result.file_pcs),
                        ]
                    )
                    print(f"[DONE {idx}] {row.cve_id} = {result}")
                else:
                    writer.writerow(
                        [
                            row.cve_id,
                            row.product,
                            row.patch_id,
                            "",
                            "",
                            "",
                        ]
                    )
                    print(f"[ERROR {idx}] {row.cve_id} = failed")

                file.flush()

                # Save into output csv
                # [cve_id, product, patch_id, pclocator_flag]

    # For each roll, if the product is `product`, find the patch,
    # checkout the previous version before the patch, use `pclocator.py`
    # to generate the presence condition and store all this information
    # with a new column (pclocator_flag) on the `output_file` CSV.


@dataclass
class DatasetRow:
    cve_id: str
    product: str
    patch_id: str
    flag: str


def dataset_rows(dataset_path: Path):
    with open(dataset_path, "r", encoding="utf-8") as dataset_file:
        dataset_reader = csv.reader(dataset_file, delimiter=",")
        for dataset_row in dataset_reader:
            row_obj = DatasetRow(
                cve_id=dataset_row[0],
                product=dataset_row[1],
                patch_id=dataset_row[2],
                flag=dataset_row[3],
            )
            yield row_obj


def pclocator_script(project_root: Path, patch_file: Path) -> str:
    # This functions runs the `pclocator.py` script
    pclocator_script_path = os.path.join(Path(__file__).parent, "pclocator.py")

    command = [
        pclocator_script_path,
        "-r",
        str(project_root),
        "-p",
        str(patch_file),
    ]
    result = subprocess.run(command, capture_output=True, text=True)

    if result.returncode != 0:
        raise subprocess.SubprocessError(
            f"pclocator script ({' '.join(command)}) failed with code {result.returncode}:\nStderr: {result.stderr}\n"
        )

    presence_condition = result.stdout

    return presence_condition


def find_patch_file(patches_folder: Path, row: DatasetRow) -> Path | None:
    first_attempt = os.path.join(patches_folder, f"{row.cve_id}-{row.patch_id}.txt")
    if os.path.isfile(first_attempt):
        return Path(first_attempt)

    second_attempt = os.path.join(patches_folder, f"github/{row.patch_id}.txt")
    if os.path.isfile(second_attempt):
        return Path(second_attempt)

    return None


def process_patch(
    patch_file: Path, project_root: Path
) -> tuple[str, ProcessPatchResult] | None:
    try:
        rev, _ = get_patch_info(str(patch_file))
    except UnicodeDecodeError:
        raise CheckoutError(f"Failed to decode UTF-8 in patch file {patch_file}")
    print(f"Processing patch {patch_file}...", file=sys.stderr)

    checkout_start = time.perf_counter()
    try:
        # Checkout the commit in the repository
        _ = subprocess.run(
            ["git", "clean", "-fd"],
            cwd=project_root,  # Set the working directory to the repo
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        _ = subprocess.run(
            ["git", "checkout", f"{rev}~1"],
            cwd=project_root,  # Set the working directory to the repo
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError as error:
        raise CheckoutError(f"Failed to checkout revision {rev}: {error}")
    checkout_end = time.perf_counter()
    checkout_time_ms = checkout_end - checkout_start

    print(f"Checked out commit {rev} in {checkout_time_ms}ms!", file=sys.stderr)

    try:
        result = calculate_patch_presence_condition(str(patch_file), str(project_root))

        simplifier = ExpressionSimplifier()
        simp = simplifier.simplify(result.raw_flag)
        print(f"{result} -> {simp}", file=sys.stderr)

        return (simp, result)
    except Exception as e:
        print(f"Failed to run pclocator+kmax: {e}", file=sys.stderr)
        return None


if __name__ == "__main__":
    main()
