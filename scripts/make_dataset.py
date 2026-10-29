#!/usr/bin/env -S uv --quiet run --script
# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "cpeparser",
#     "gdown>=6",
# ]
# ///

import argparse
import csv
import gzip
import json
import os
import re
import shutil
import sqlite3
import sys
import tempfile
import zipfile
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

import gdown
import requests
from cpeparser import CpeParser
from typing_extensions import Literal

CVE_DATA_DRIVE_URL = (
    "https://drive.google.com/file/d/1mD9WsWyd7Nk_NyD3aPTpuFJxABm7pVUT/view?usp=sharing"
)
PATCHDB_DRIVE_URL = (
    "https://drive.google.com/file/d/1gJQd5Kk6kI0z71D7HUaxM5KzbyWmmqwQ/view?usp=sharing"
)

GITHUB_COMMIT_REGEX = re.compile(
    r"^https?://github\.com/"  # protocol + domain
    r"[^/]+/"  # owner (one or more non-slashes)
    r"[^/]+/"  # repo
    r"commit/"
    r"(?P<hash>[0-9a-f]{40})$"  # exactly 40 lowercase hex chars
)

# Commits from Linux kernel trees hosted on git.kernel.org. Matches the short links
# (e.g. `/stable/c/<hash>`, used by the kernel CNA) and cgit pages of any tree under
# `linux/kernel/git/` (e.g. `/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=<hash>`).
# Other projects hosted on git.kernel.org (bluez, connman, ...) are not matched.
GIT_KERNEL_COMMIT_REGEX = re.compile(
    r"^https?://git\.kernel\.org/"  # protocol + domain
    r"(?:"
    r"(?:stable/c|linus)/"  # short links
    r"|(?:pub/scm|cgit)/linux/kernel/git/[^?]+\?(?:[^&]+&)*id="  # cgit commit/patch pages
    r")"
    r"(?P<hash>[0-9a-f]{40})$"  # exactly 40 lowercase hex chars
)

# Valid values for the `--sources` flag
SOURCES = ("github-refs", "patchdb", "git-kernel")


@dataclass
class Patch:
    id: str
    cve_id: str
    github_patch_url: str | None
    patch_file: str | None


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
            "cvss_base_score" REAL,
            "cve_exploitability_score" REAL,
            "cve_impact_score" REAL,
            "patch_ref_count" INT NOT NULL DEFAULT 0,
            "published_at" DATE NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS "patches" (
            "id" TEXT PRIMARY KEY,
            "source" TEXT NOT NULL,
            "cve_id" TEXT NOT NULL REFERENCES "cves"("cve_id"),
            "github_patch_url" TEXT,
            "patch_file" TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS "flags" (
            "run_started_at" DATETIME NOT NULL,
            "patchlens_version" TEXT NOT NULL,
            "patch_id" TEXT NOT NULL REFERENCES "patches"("id"),
            "status" TEXT NOT NULL,
            "flag" TEXT,
            "error" TEXT,
            "time_processing_ms" INTEGER,
            "checkout_time_ms" INTEGER
        )
    """)
    db.commit()


def safe_str_to_float(s: str | float | None) -> float | None:
    try:
        return (float(s) if s.strip() else None) if isinstance(s, str) else s
    except ValueError:
        return None


def calculate_probable_product(configurations: list[str]) -> Optional[str]:
    cpe = CpeParser()

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


def read_patch_db(path: str) -> list[Patch]:
    patches = []
    for filename in os.listdir(path):
        # Skip the folders of patches downloaded by automate_patchlens.py (e.g. `github/`)
        if not os.path.isfile(os.path.join(path, filename)):
            continue
        cve, _, _ = filename.rpartition("-")
        id = filename[(len(cve) + 1) : -4]
        patches.append(
            Patch(
                id=id,
                cve_id=cve,
                patch_file=filename,
                github_patch_url=None,
            )
        )
    return patches


def upsert_patches(
    db: sqlite3.Connection,
    patches: list[Patch],
    source: Literal["patchdb", "github", "git-kernel"],
):
    if source == "patchdb":
        query = """
            INSERT INTO "patches" (
                id,
                source,
                cve_id,
                patch_file
            ) VALUES (?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                cve_id = excluded.cve_id,
                source = excluded.source,
                patch_file = excluded.patch_file;
        """
        values = [(p.id, source, p.cve_id, p.patch_file) for p in patches]
        db.executemany(query, values)
        db.commit()
    elif source == "github":
        query = """
            INSERT INTO "patches" (
                id,
                source,
                cve_id,
                github_patch_url
            ) VALUES (?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                cve_id = excluded.cve_id,
                source = excluded.source,
                github_patch_url = excluded.github_patch_url;
        """
        values = [(p.id, source, p.cve_id, p.github_patch_url) for p in patches]
        db.executemany(query, values)
        db.commit()
    elif source == "git-kernel":
        # No URL is stored: automate_patchlens.py downloads these patches by commit hash (the id)
        query = """
            INSERT INTO "patches" (
                id,
                source,
                cve_id
            ) VALUES (?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                cve_id = excluded.cve_id,
                source = excluded.source;
        """
        values = [(p.id, source, p.cve_id) for p in patches]
        db.executemany(query, values)
        db.commit()
    else:
        raise ValueError(f"Invalid source: {source}")
    print("Inserted", len(values), "patch records")


def upsert_cves(db: sqlite3.Connection, cves: list[dict[str, Any]]):
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
            cvss_base_score,
            cve_exploitability_score,
            cve_impact_score,
            patch_ref_count,
            published_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(cve_id) DO UPDATE SET
            calculated_product = excluded.calculated_product,
            year = excluded.year,
            assigner = excluded.assigner,
            problem_type = excluded.problem_type,
            "references" = excluded."references",
            description = excluded.description,
            configurations = excluded.configurations,
            severity = excluded.severity,
            cvss_base_score = excluded.cvss_base_score,
            cve_exploitability_score = excluded.cve_exploitability_score,
            cve_impact_score = excluded.cve_impact_score,
            patch_ref_count = excluded.patch_ref_count,
            published_at = excluded.published_at;
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
            cve["cvss_base_score"],
            cve["cve_exploitability_score"],
            cve["cve_impact_score"],
            cve["patch_ref_count"],
            cve["published_at"],
        )
        for cve in cves
    ]
    db.executemany(query, values)
    db.commit()
    print("Inserted", len(values), "cve records")


def download_nvd_data(cve_data_folder):
    """
    Download the NVD data from the official website.
    """
    url = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"
    for year in range(2002, datetime.now().year + 1):
        filename = f"nvdcve-1.1-{year}.json.gz"
        filepath = os.path.join(cve_data_folder, filename)
        if not os.path.exists(filepath):
            print(f"Downloading {filename}...")
            response = requests.get(url.format(year=year))
            with open(filepath, "wb") as f:
                f.write(response.content)
            with gzip.open(filepath, "rb") as gz:
                with open(filepath[:-3], "wb") as f:
                    shutil.copyfileobj(gz, f)


def extract_github_commit_hash(url: str) -> str | None:
    m = GITHUB_COMMIT_REGEX.match(url)
    return m.group("hash") if m else None


def extract_git_kernel_commit_hash(url: str) -> str | None:
    m = GIT_KERNEL_COMMIT_REGEX.match(url)
    return m.group("hash") if m else None


def collect_cve_data(
    cve_data_folder, year
) -> tuple[list[dict[str, Any]], list[Patch], list[Patch]]:
    """
    Collect the CVE data from the NVD data.
    Returns the CVEs, the GitHub patches and the git.kernel.org patches
    (both taken from references tagged as `patch`).
    """
    filename = f"nvdcve-1.1-{year}.json"
    filepath = os.path.join(cve_data_folder, filename)

    print(f"Collecting CVE data for year {year} from {filename}")

    if not os.path.exists(filepath):
        print(f"File {filename} not found!")
        raise Exception(f"File {filename} not found!")

    with open(filepath, "r") as f:
        data = json.load(f)

    cves = data["vulnerabilities"]

    entries = []
    github_patches = []
    git_kernel_patches = []
    skipped = 0
    processed = 0
    for row in cves:
        print(f"\rProcessed {processed} rows...", end="")
        configurations = []
        if "configurations" in row["cve"] and len(row["cve"]["configurations"]) > 0:
            cfg = row["cve"]["configurations"][0]
            nodes = cfg["nodes"]
            for node in nodes:
                for match in node["cpeMatch"]:
                    configurations.append(match["criteria"])
        calculated_product = calculate_probable_product(configurations)
        if calculated_product is None:
            skipped += 1
            continue
        entry = {
            "cve_id": row["cve"]["id"],
            "calculated_product": calculated_product,
            "assigner": row["cve"]["sourceIdentifier"],
            "problem_type": json.dumps(
                list(
                    map(
                        lambda weakness: list(
                            map(lambda d: d["value"], weakness["description"])
                        ),
                        row["cve"]["weaknesses"],
                    )
                )
            )
            if "weaknesses" in row["cve"]
            else None,
            "references": json.dumps(row["cve"]["references"]),
            "description": row["cve"]["descriptions"][0]["value"],
            "configurations": json.dumps(configurations),
            "severity": row["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"][
                "baseSeverity"
            ]
            if row["cve"]["metrics"].get("cvssMetricV31")
            else None,
            "cvss_base_score": row["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"][
                "baseScore"
            ]
            if row["cve"]["metrics"].get("cvssMetricV31")
            else (
                row["cve"]["metrics"]["cvssMetricV2"][0]["cvssData"]["baseScore"]
                if row["cve"]["metrics"].get("cvssMetricV2")
                else None
            ),
            "cve_exploitability_score": safe_str_to_float(
                row["cve"]["metrics"]["cvssMetricV31"][0]["exploitabilityScore"]
                if row["cve"]["metrics"].get("cvssMetricV31")
                else (
                    row["cve"]["metrics"]["cvssMetricV2"][0]["exploitabilityScore"]
                    if row["cve"]["metrics"].get("cvssMetricV2")
                    else None
                ),
            ),
            "cve_impact_score": safe_str_to_float(
                row["cve"]["metrics"]["cvssMetricV31"][0]["impactScore"]
                if row["cve"]["metrics"].get("cvssMetricV31")
                else (
                    row["cve"]["metrics"]["cvssMetricV2"][0]["impactScore"]
                    if row["cve"]["metrics"].get("cvssMetricV2")
                    else None
                ),
            ),
            "patch_ref_count": 0,
            "published_at": row["cve"]["published"],
        }
        for ref in row["cve"]["references"]:
            url = ref["url"]
            if ref.get("tags") and "patch" in list(
                map(lambda x: x.lower(), ref["tags"])
            ):
                entry["patch_ref_count"] += 1
                commit = extract_github_commit_hash(url)
                if commit is not None:
                    github_patches.append(
                        Patch(
                            id=commit,
                            cve_id=entry["cve_id"],
                            github_patch_url=url,
                            patch_file=None,
                        )
                    )
                commit = extract_git_kernel_commit_hash(url)
                if commit is not None:
                    git_kernel_patches.append(
                        Patch(
                            id=commit,
                            cve_id=entry["cve_id"],
                            github_patch_url=None,
                            patch_file=None,
                        )
                    )

        entries.append(entry)
        processed += 1

    print()

    if skipped > 0:
        print(
            f"[WARN] {skipped} cves were skipped due to not having a correct configurations column"
        )

    return (entries, github_patches, git_kernel_patches)


def collect_patchdb_patches(db: sqlite3.Connection, patches_folder: str):
    """
    Downloads the PatchDB archive (if `patches_folder` does not exist) and inserts its patches.
    """
    if not os.path.exists(patches_folder):
        print("Patches folder not found! Downloading patchdb archive...")
        with tempfile.NamedTemporaryFile(delete=True, suffix=".zip") as tmp:
            gdown.download(PATCHDB_DRIVE_URL, tmp, quiet=False)
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

    patchdb_patches = read_patch_db(patches_folder)

    print("Processing patches from patchdb...")

    upsert_patches(db, patchdb_patches, "patchdb")


def parse_sources(value: str) -> set[str]:
    """
    Parses the comma-separated list of the `--sources` flag (e.g. `github-refs,git-kernel`).
    """
    sources = {source.strip() for source in value.split(",") if source.strip()}
    if not sources:
        raise argparse.ArgumentTypeError("at least one source is required")
    invalid = sources - set(SOURCES)
    if invalid:
        raise argparse.ArgumentTypeError(
            f"invalid source(s): {', '.join(sorted(invalid))}. Valid options are: {', '.join(SOURCES)}"
        )
    return sources


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--cve-data-folder",
        default="data/nvd",
        help="The folder where the nvd data is located",
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
        "--sources",
        type=parse_sources,
        default="github-refs,patchdb",
        help=f"Comma-separated list of patch sources. Valid options: {', '.join(SOURCES)} (default: github-refs,patchdb)",
    )

    args = parser.parse_args()

    cve_data_folder: str = args.cve_data_folder
    patches_folder: str = args.patches_folder
    output_file: str = args.output
    sources: set[str] = args.sources

    # Check if the default ./data folder is being used.
    # If so, create it if it does not exist
    if (
        cve_data_folder.startswith("data/")
        or patches_folder.startswith("data/")
        or output_file.startswith("data/")
    ):
        if not os.path.isdir("data"):
            os.mkdir("data")

    if not os.path.isdir(cve_data_folder):
        print("NVD data folder not found! Creating...")
        os.makedirs(cve_data_folder)

    download_nvd_data(cve_data_folder)

    csv.field_size_limit(sys.maxsize)

    db = sqlite3.connect(output_file)
    setup_tables(db)

    for year in range(2002, datetime.now().year + 1):
        cves, github_patches, git_kernel_patches = collect_cve_data(
            cve_data_folder, year
        )
        upsert_cves(db, cves)
        if "github-refs" in sources:
            upsert_patches(db, github_patches, "github")
        if "git-kernel" in sources:
            upsert_patches(db, git_kernel_patches, "git-kernel")

    if "patchdb" in sources:
        collect_patchdb_patches(db, patches_folder)

    print("Completed.")

    db.close()


if __name__ == "__main__":
    main()
