#!/usr/bin/env -S uv --quiet run --script
# /// script
# requires-python = ">=3.13"
# dependencies = [
# ]
# ///

import math
import argparse
import csv
from dataclasses import asdict, dataclass
import random
import sys
from typing import cast


@dataclass
class FlagEntry:
    cve_id: str
    product: str
    id: str
    flag: str


def required_sample_size(population_size: int):
    # Calculates the required sample size for a population of size N
    # with a confidence level of 95%, a margin of error of 5%, and
    # a population proportion of 50%.

    z_score = 1.96
    margin_of_error = 0.05
    population_proportion = 0.5

    num = (z_score**2 * population_proportion * (1 - population_proportion)) / (
        margin_of_error**2
    )
    den = 1 + (
        (z_score**2 * population_proportion * (1 - population_proportion))
        / (margin_of_error**2 * population_size)
    )

    return math.ceil(num / den)


def main():
    parser = argparse.ArgumentParser()
    _ = parser.add_argument(
        "csv_file",
        default="final_dataset.csv",
        help="Path to final dataset CSV file (default: final_dataset.csv) containing [cve_id, product, id, flag]",
    )

    args = parser.parse_args()

    csv_file = cast(str, args.csv_file)

    flags_by_product: dict[str, list[FlagEntry]] = {}

    with open(csv_file, "r") as f:
        reader = csv.DictReader(f)

        for row in reader:
            flag_entry = FlagEntry(
                row["cve_id"], row["product"], row["id"], row["flag"]
            )
            flags_by_product.setdefault(flag_entry.product, []).append(flag_entry)

    for key in flags_by_product:
        population_size = len(flags_by_product[key])
        sample_size = required_sample_size(population_size)

        print(f"{key}: {population_size} -> {sample_size}", file=sys.stderr)

    # Now, for each product, select randomly the required number of samples
    writer = csv.DictWriter(
        sys.stdout,
        fieldnames=["cve_id", "product", "id", "flag"],
        quoting=csv.QUOTE_ALL,
    )
    writer.writeheader()

    for key in flags_by_product:
        population_size = len(flags_by_product[key])
        sample_size = required_sample_size(population_size)

        samples = random.sample(flags_by_product[key], sample_size)
        writer.writerows(asdict(s) for s in samples)


if __name__ == "__main__":
    main()
