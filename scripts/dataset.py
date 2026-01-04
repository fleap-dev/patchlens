#!/usr/bin/env -S uv --quiet run --script
# /// script
# requires-python = ">=3.13"
# dependencies = [
#   "pandas",
#   "matplotlib",
#   "numpy",
#   "scipy"
# ]
# ///

import argparse
import ast
import csv
import difflib
from ntpath import isfile
import os
import random
import re
import sqlite3
import sys
from collections import Counter
from dataclasses import dataclass
from typing import Dict, List, Literal, Tuple, cast

import matplotlib
import numpy as np
import pandas as pd
from scipy import stats

matplotlib.use("TkAgg")  # or "Qt5Agg"
import matplotlib.pyplot as plt

FLAG_BUILDING_PATTERN = re.compile(r"building\((/[^)]+)\)")
FLAG_COMPARISON_PATTERN = re.compile(
    r"\(\s*"
    r"(\$\([^()]+\)|[A-Za-z_]\w*)"  # group1 = "$(…)" or identifier
    r"\s*=\s*"
    r"([^()]+?)"  # group2 = RHS (not containing parentheses)
    r"\s*\)"
)
FLAG_SINGLE_COMPARISON = re.compile(
    r"(?<!\()"  # no "(" directly before
    r"(\$\([^()]+\)|[A-Za-z_]\w*)"  # group1 = "$(…)" or identifier
    r"\s*=\s*"
    r"([^\s()]+)"  # group2 = VAL (no spaces or parens)
    r"(?!\))"  # no ")" directly after
)


@dataclass
class PatchlensRun:
    run_id: str
    product: str
    flag_count: int


@dataclass
class RunFlag:
    cve_id: str
    cvss_impact: float
    cvss_base_score: float | None
    run_id: str
    patchlens_version: str
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
    product: str


def _get_runs(db: sqlite3.Connection):
    query = """
        SELECT
            f.run_started_at,
            c.calculated_product,
            COUNT(*)            AS flags_count
        FROM flags    AS f
        JOIN patches  AS p  ON f.patch_id      = p.id
        JOIN cves     AS c  ON p.cve_id        = c.cve_id
        GROUP BY
            f.run_started_at,
            c.calculated_product
        ORDER BY
            f.run_started_at;
    """

    cursor = db.cursor()
    cursor.execute(query)

    return list(
        filter(
            lambda run: not ("fedora" in run.product or "debian" in run.product),
            map(
                lambda row: PatchlensRun(
                    run_id=row[0], product=row[1], flag_count=row[2]
                ),
                cursor.fetchall(),
            ),
        )
    )


def _flags_from_run(db: sqlite3.Connection, run: str):
    cursor = db.cursor()
    cursor.execute(
        """
        SELECT
            cves.cve_id,
            cves.cve_impact_score,
            flags.patchlens_version,
            flags.patch_id,
            flags.status,
            flags.flag,
            flags.error,
            cves.cvss_base_score,
            cves.calculated_product
        FROM flags
        JOIN patches ON patches.id = flags.patch_id
        JOIN cves ON cves.cve_id = patches.cve_id
        WHERE
            flags.run_started_at = ?;
    """,
        [run],
    )
    return list(
        map(
            lambda row: RunFlag(
                cve_id=row[0],
                cvss_impact=row[1],
                run_id=run,
                patchlens_version=row[2],
                patch_id=row[3],
                status=row[4],
                flag=row[5],
                error=row[6],
                cvss_base_score=row[7],
                product=row[8],
            ),
            cursor.fetchall(),
        )
    )


def _display_dataframe_to_user(name: str, dataframe: pd.DataFrame) -> None:
    print(f"\n=== {name} ===")
    print(dataframe.to_string(index=False))


def random_error(db: sqlite3.Connection, run_id: str):
    query = """
        SELECT
            flags.patchlens_version,
            flags.patch_id,
            flags.error
        FROM flags
        WHERE
            flags.run_started_at = ?
        AND
            flags.status = 'PatchlensError';
    """

    cursor = db.cursor()
    cursor.execute(query, [run_id])
    choice = random.choice(cursor.fetchall())

    raw_error: str = choice[2]
    error, _stdout, stderr = raw_error.split("\n")

    print(f"Run {run_id}:")
    print(f" - Patchlens version: {choice[0]}")
    print(f" - Patch ID: {choice[1]}")
    print(f" - Error: {error}")
    print("---------- STDERR ----------")
    print(stderr[10:-1].replace("\\n", "\n"))


def run_details(db: sqlite3.Connection, run_id: str):
    query = """
        WITH run_flags AS (
            SELECT *
            FROM flags
            WHERE run_started_at = ?
        ),
        tot AS (
            SELECT COUNT(*) AS total_flags
            FROM run_flags
        )
        SELECT
            rf.status                             AS status,
            COUNT(*)                              AS cnt,
            ROUND( COUNT(*) * 1.0 / tot.total_flags , 4 )  AS pct
        FROM run_flags AS rf
        CROSS JOIN tot
        GROUP BY rf.status
        ORDER BY
            -- put 'ok' first, then errors by descending count
            CASE WHEN rf.status = 'ok' THEN 0 ELSE 1 END,
            cnt DESC;
    """

    cursor = db.cursor()
    cursor.execute(query, [run_id])

    print(f"Run {run_id}:")
    for value in cursor.fetchall():
        percentage = value[2] * 100
        print(f"- {value[0]} -> {value[1]} ({percentage:.2f}%)")


def import_run(src_db: sqlite3.Connection, dst_db: sqlite3.Connection, run_id: str):
    query = """
        SELECT
            *
        FROM flags
        WHERE
            flags.run_started_at = ?;
    """

    cursor = src_db.cursor()
    cursor.execute(query, [run_id])

    data = cursor.fetchall()

    insert_query = """
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
    dst_db.executemany(
        insert_query,
        [
            (
                f[0],
                f[1],
                f[2],
                f[3],
                f[4],
                f[5],
                f[6],
                f[7],
            )
            for f in data
        ],
    )
    dst_db.commit()


def show_runs(db: sqlite3.Connection):
    query = """
        SELECT
            f.run_started_at,
            c.calculated_product,
            COUNT(*)            AS flags_count
        FROM flags    AS f
        JOIN patches  AS p  ON f.patch_id      = p.id
        JOIN cves     AS c  ON p.cve_id        = c.cve_id
        GROUP BY
            f.run_started_at,
            c.calculated_product
        ORDER BY
            f.run_started_at;
    """

    cursor = db.cursor()
    cursor.execute(query)

    print("Runs in this dataset:")
    for value in cursor.fetchall():
        print(f"- [{value[1]}] {value[0]} ({value[2]} flags)")


def fuzzy_match(var: str, text_tokens: list[str], cutoff: float = 0.8) -> bool:
    """
    Return True if var fuzzily matches any token in text_tokens
    with a similarity >= cutoff.
    """
    var_norm = var.lower()
    for tok in text_tokens:
        score = difflib.SequenceMatcher(None, var_norm, tok.lower()).ratio()
        if score >= cutoff:
            return True
    return False


def check_descriptions(db: sqlite3.Connection, cutoff: float = 0.8):
    query = """
    SELECT c.cve_id, c.description, f.flag
      FROM flags AS f
      JOIN patches AS p ON f.patch_id = p.id
      JOIN cves AS c    ON p.cve_id   = c.cve_id
      WHERE f.status = 'ok';
    """
    cur = db.cursor()
    cur.execute(query)

    total, covered, sum_recall = 0, 0, 0.0
    missing_dist = Counter()

    for cve_id, desc, flag in cur.fetchall():
        try:
            _, var_counter = var_count_from_flag(flag)
        except ValueError:
            continue
        vars_ = list(var_counter.keys())
        if not vars_:
            continue

        total += 1
        # tokenize on non-alphanumerics to catch variants like $(ARCH)==x86 or PHP-GD
        tokens = re.findall(r"[A-Za-z0-9_\-]+", desc)

        matched = {v for v in vars_ if fuzzy_match(v, tokens, cutoff)}
        recall = len(matched) / len(vars_)
        sum_recall += recall
        if matched:
            covered += 1

        missing_dist[len(vars_) - len(matched)] += 1

    if total == 0:
        print("No CVEs analyzed.")
        return

    print(f"Total CVEs: {total}")
    print(f"Coverage rate (≥1 fuzzy match): {covered / total:.2%}")
    print(f"Average recall: {sum_recall / total:.2%}")
    print("Missing‐option distribution:")
    for miss, freq in sorted(missing_dist.items()):
        print(f"  {miss} missing: {freq} CVEs")


def check_descriptions_v2(db: sqlite3.Connection, runs: List[str], cutoff: float = 0.8):
    """
    For each CVE, compute:
        proportion = (# flags mentioned in description) / (# flags in impact condition)

    Prints summary stats, shows a binned distribution table, and renders three charts:
        1) Histogram of proportions
        2) Bar chart of binned proportions
        3) Empirical CDF of proportions

    Returns a DataFrame with columns:
        ['cve_id', 'n_required', 'n_mentioned', 'proportion']
    """
    if not runs:
        print("No runs provided.")
        return pd.DataFrame(
            columns=["cve_id", "n_required", "n_mentioned", "proportion"]
        )

    placeholders = ",".join(["?"] * len(runs))
    query = f"""
    SELECT cves.cve_id, cves.description, flags.flag FROM flags
    JOIN patches ON flags.patch_id = patches.id
    JOIN cves ON cves.cve_id = patches.cve_id
    WHERE
    flags.status = 'ok' AND
    flags.run_started_at IN ({placeholders});
    """
    cur = db.cursor()
    cur.execute(query, runs)

    records: List[Dict] = []

    for cve_id, desc, flag in cur.fetchall():
        try:
            # Provided by your codebase: returns (vars_list, Counter(vars))
            _, var_counter = var_count_from_flag(flag)  # type: ignore # noqa: F821
        except Exception:
            continue

        vars_ = list(var_counter.keys())

        # Tokenize on non-alphanumerics to catch variants like $(ARCH)==x86 or PHP-GD
        tokens = re.findall(r"[A-Za-z0-9_\-]+", desc or "")

        matched = {v for v in vars_ if fuzzy_match(v, tokens, cutoff)}
        n_required = len(vars_)
        n_mentioned = len(matched)
        proportion = n_mentioned / n_required if n_required > 0 else 0.0

        records.append(
            {
                "cve_id": cve_id,
                "n_required": n_required,
                "n_mentioned": n_mentioned,
                "proportion": proportion,
            }
        )

    df = pd.DataFrame.from_records(
        records, columns=["cve_id", "n_required", "n_mentioned", "proportion"]
    )

    if df.empty:
        print("No CVEs analyzed.")
        return df

    # --- Summary stats ---
    total = len(df)
    coverage_rate = (df["proportion"] > 0).mean()
    avg_prop = df["proportion"].mean()
    median_prop = df["proportion"].median()

    print(f"Total CVEs: {total}")
    print(f"Coverage rate (≥1 flag mentioned): {coverage_rate:.2%}")
    print(f"Average proportion (mentioned/required): {avg_prop:.2%}")
    print(f"Median proportion: {median_prop:.2%}")

    # --- Histogram of proportions ---
    plt.figure()
    plt.hist(df["proportion"].values, bins=21, edgecolor="black")
    plt.title("Distribution of Mention Proportions per CVE")
    plt.xlabel("Proportion (flags mentioned / flags required)")
    plt.ylabel("Number of CVEs")
    plt.tight_layout()
    plt.show()

    # --- Binned proportions table and bar chart ---
    bins = [-0.0001, 0.0, 0.25, 0.5, 0.75, 1.0 - 1e-9, 1.0 + 1e-9]
    labels = [
        "0.00 exactly",
        "(0.00, 0.25]",
        "(0.25, 0.50]",
        "(0.50, 0.75]",
        "(0.75, 1.00)",
        "1.00 exactly",
    ]
    binned = pd.cut(
        df["proportion"], bins=bins, labels=labels, include_lowest=True, right=True
    )
    bin_counts = binned.value_counts().reindex(labels, fill_value=0).reset_index()
    bin_counts.columns = ["Proportion Bin", "Count"]
    bin_counts["Share"] = (bin_counts["Count"] / total).map(lambda x: f"{x:.2%}")

    _display_dataframe_to_user("Proportion Distribution by Bin", bin_counts)

    plt.figure()
    plt.bar(bin_counts["Proportion Bin"], bin_counts["Count"])
    plt.title("Binned Distribution of Mention Proportions")
    plt.xlabel("Proportion Bin")
    plt.ylabel("Number of CVEs")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.show()

    # --- Empirical CDF ---
    vals = np.sort(df["proportion"].values)
    y = np.arange(1, len(vals) + 1) / len(vals)

    plt.figure()
    plt.plot(vals, y, drawstyle="steps-post")
    plt.title("Empirical CDF of Mention Proportions")
    plt.xlabel("Proportion (flags mentioned / flags required)")
    plt.ylabel("Cumulative Share of CVEs")
    plt.tight_layout()
    plt.show()

    return df


def var_count_from_flag(flag: str) -> Tuple[int, Counter[str]]:
    def ast_to_var_count(node: ast.AST, counter: Counter) -> int:
        # Check for binary operations
        if isinstance(node, ast.BinOp):
            return ast_to_var_count(node.left, counter) + ast_to_var_count(
                node.right, counter
            )
        # Check for `defined` function calls
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "defined"
            and len(node.args) == 1
            and isinstance(node.args[0], ast.Name)
        ):
            counter[f"{node.args[0].id}"] += 1
            return 1
        # Bail out when procesing `building` flags
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "building"
        ):
            raise ValueError("flag contain building functions")
        # Check for negations
        if isinstance(node, ast.UnaryOp):
            return ast_to_var_count(node.operand, counter)
        # Check for True constants
        if isinstance(node, ast.Constant) and node.value:
            return 0
        if isinstance(node, ast.Compare):
            if (
                isinstance(node.left, ast.Constant)
                and len(node.comparators) == 1
                and isinstance(node.comparators[0], ast.Constant)
            ):
                counter[f"{node.left.value} = {node.comparators[0].value}"] += 1
                return 1
        print(f"Failed to understand flag: {ast.dump(node)}")
        exit(1)

    # Quick fixes to make the flag compatible with the ast module
    flag = FLAG_BUILDING_PATTERN.sub(lambda m: f'building("{m.group(1)}")', flag)
    flag = FLAG_COMPARISON_PATTERN.sub(
        lambda m: f'("{m.group(1)}" == "{m.group(2)}")', flag
    )
    flag = FLAG_SINGLE_COMPARISON.sub(
        lambda m: f'"{m.group(1)}" == "{m.group(2)}"', flag
    )

    ast_expr = ast.parse(flag, mode="eval").body
    counter = Counter()
    var_count = ast_to_var_count(ast_expr, counter)
    return (var_count, counter)


def run_var_counts(db: sqlite3.Connection, run: str, label: str):
    cursor = db.cursor()

    cursor.execute(
        """
        SELECT
            flags.flag
        FROM flags
        WHERE
            flags.status = 'ok'
            AND flags.run_started_at = ?;
    """,
        [run],
    )

    var_count = []

    for row in cursor.fetchall():
        try:
            flag = row[0]
            (count_in_flag, var_counter) = var_count_from_flag(flag)
            var_count.append([label, count_in_flag])
        except ValueError:
            continue

    out = csv.writer(sys.stdout)
    out.writerows(var_count)


def run_var_count_plot(db: sqlite3.Connection, runs: List[str]):
    labels: List[str] = []
    per_run_counts: List[List[int]] = []

    for run in runs:
        flags = _flags_from_run(db, run)
        if not flags:
            print(f"No data for run {run}. Skipping.")
            continue

        product = flags[0].product
        var_counts: List[int] = []

        for flag in flags:
            if flag.status != "ok":
                continue
            try:
                count_in_flag, _ = var_count_from_flag(str(flag.flag))
            except ValueError:
                continue
            var_counts.append(count_in_flag)

        if not var_counts:
            print(f"No valid expanded flags for run {run}. Skipping.")
            continue

        labels.append(product)
        per_run_counts.append(var_counts)

    if not per_run_counts:
        print("No runs with plottable variable-count data.")
        return

    plt.figure(figsize=(10, 6))
    plt.boxplot(per_run_counts, tick_labels=labels, showmeans=True)
    plt.title("Number of variables per Patch by System", fontsize=18)
    plt.xlabel("System", fontsize=14)
    plt.ylabel("Number of variables per Patch", fontsize=14)
    plt.xticks(fontsize=12)
    plt.yticks(fontsize=12)
    plt.tight_layout()
    plt.show()


def flag_complexity(db: sqlite3.Connection):
    query = """
        SELECT
            f.run_started_at,
            c.calculated_product,
            COUNT(*)            AS flags_count
        FROM flags    AS f
        JOIN patches  AS p  ON f.patch_id      = p.id
        JOIN cves     AS c  ON p.cve_id        = c.cve_id
        GROUP BY
            f.run_started_at,
            c.calculated_product
        ORDER BY
            f.run_started_at;
    """

    cursor = db.cursor()
    cursor.execute(query)

    for value in cursor.fetchall():
        product = value[1]
        run = value[0]
        flag_count = value[2]

        # We only care about linux/linux
        if "fedora" in product or "debian" in product:
            continue

        cursor.execute(
            """
            SELECT
                flags.flag
            FROM flags
            WHERE
                flags.status = 'ok'
                AND flags.run_started_at = ?;
        """,
            [run],
        )
        var_count = []
        not_expanded = False
        global_counter = Counter()
        for row in cursor.fetchall():
            flag = row[0]
            try:
                (count_in_flag, var_counter) = var_count_from_flag(flag)
                var_count.append(count_in_flag)
                global_counter = global_counter + var_counter
            except ValueError:
                not_expanded = True
                break
        if not_expanded:
            print(f"- [{product}] {run} ({flag_count} flags) -> NOT EXPANDED")
        else:
            avg = sum(var_count) / len(var_count)
            print(f"- [{product}] {run} ({flag_count} flags) -> avg {avg} vars")
            print("Variables that most appear:", global_counter.most_common(10))


def variable_to_severity_correlation(db: sqlite3.Connection, min_patches=6):
    """
    For each run (system) in the database, bucket CVSS base scores into
    Low, Medium, High, Critical, then for each configuration variable compute:
        - How many patches fall into each bucket.
        - The proportion of patches in the 'High' or 'Critical' buckets.
    Finally, print a summary per run listing:
        - The variable most often associated with 'High or Critical' patches.
        - The top 3 variables by proportion of 'High or Critical' patches.
    """

    def bucket(score):
        if score <= 3.9:
            return "Low"
        elif score <= 6.9:
            return "Medium"
        elif score <= 8.9:
            return "High"
        else:
            return "Critical"

    runs = _get_runs(db)  # Retrieve objects with .run_id and .product attributes

    for run in runs:
        records = []
        flags = _flags_from_run(db, run.run_id)
        for flag in flags:
            if flag.status != "ok":
                continue
            try:
                _, var_counter = var_count_from_flag(str(flag.flag))
            except ValueError:
                continue
            severity = flag.cvss_base_score
            sev_bucket = bucket(severity)
            for var in var_counter:
                records.append({"variable": var, "bucket": sev_bucket})

        if not records:
            print(f"No data for run {run.run_id}\n")
            continue

        df = pd.DataFrame(records)
        # Count how many patches per variable per bucket
        stats = df.groupby("variable")["bucket"].value_counts().unstack(fill_value=0)
        # Filter variables with at least min_patches total
        stats = stats[stats.sum(axis=1) >= min_patches].copy()
        # Compute proportion of High+Critical patches
        high_count = stats.get("High", 0)
        crit_count = stats.get("Critical", 0)
        stats["highcrit_prop"] = (high_count + crit_count) / stats.sum(axis=1)
        # Sort by that proportion descending
        stats = stats.sort_values("highcrit_prop", ascending=False)

        # Prepare summary
        top_vars = stats.head(3)
        best_var = top_vars.index[0]
        best_prop = top_vars.loc[best_var, "highcrit_prop"]

        print(f"Run {run.run_id} ({run.product}):")
        print(
            f"Variable most associated with High or Critical severity: {best_var} "
            f"(High/Critical in {best_prop:.1%} of its patches)."
        )
        print("Top 3 variables by High/Critical-patch proportion:")
        for var, row in top_vars.iterrows():
            total = int(row.sum())
            hc_count = int(row.get("High", 0) + row.get("Critical", 0))
            prop = row["highcrit_prop"]
            print(f"  - {var}: {hc_count}/{total} patches ({prop:.1%} high/critical)")
        print()


def most_severe_variables(db: sqlite3.Connection):
    runs = _get_runs(db)  # Retrieve objects with .run_id and .product attributes

    for run in runs:
        print(f"Analysis for {run}")
        records: Dict[str, List[float]] = {}
        flags = _flags_from_run(db, run.run_id)
        for flag in flags:
            if flag.status != "ok":
                continue
            try:
                _, var_counter = var_count_from_flag(str(flag.flag))
            except ValueError:
                continue
            severity = flag.cvss_base_score
            if severity:
                for var in var_counter:
                    if var in records:
                        records[var].append(severity)
                    else:
                        records[var] = [severity]

        averages: Dict[str, float] = {}
        for config in records:
            # Filter out config options with less than 5 appearances
            if len(records[config]) >= 5:
                averages[config] = sum(records[config]) / len(records[config])

        sorted_by_value = dict(
            sorted(averages.items(), key=lambda kv: kv[1], reverse=True)
        )
        for config in sorted_by_value:
            print(config, "=", sorted_by_value[config])


def analyze_common_operations(db: sqlite3.Connection, runs: List[str]):
    per_run_counts: Dict[
        str, Dict[Literal["amp_count", "pipe_count", "flag_count", "not_count"], int]
    ] = {}
    for run in runs:
        flags = _flags_from_run(db, run)
        flags = list(filter(lambda flag: flag.status == "ok", flags))
        num_ampersands = sum(((str)(flag.flag)).count("&") for flag in flags)
        num_pipes = sum(((str)(flag.flag)).count("|") for flag in flags)
        num_not = sum(((str)(flag.flag)).count("~") for flag in flags)
        per_run_counts[run] = {
            "amp_count": num_ampersands,
            "pipe_count": num_pipes,
            "not_count": num_not,
            "flag_count": len(flags),
        }
    print(per_run_counts)


def analyze_system_wide_cvss(db: sqlite3.Connection, filter_runs: list[str]):
    runs = _get_runs(db)
    cvss_syswide = []
    syswide_cves = set()
    for run in runs:
        if run.run_id not in filter_runs:
            continue
        print(f"Processing run {run.run_id} of {run.product}")
        flags = _flags_from_run(db, run.run_id)

        added = 0
        for flag in flags:
            if flag.status == "ok":
                added += 1
                if flag.flag == "True":
                    cvss_syswide.append(flag.cvss_impact)
                    syswide_cves.add(flag.cve_id)

    cursor = db.cursor()
    if syswide_cves:
        result = cursor.execute(
            "SELECT cves.cve_impact_score FROM cves WHERE cves.cve_impact_score IS NOT NULL AND cves.cve_id NOT IN ({})".format(
                ",".join(["?"] * len(syswide_cves))
            ),
            list(syswide_cves),
        ).fetchall()
    else:
        result = cursor.execute(
            "SELECT cves.cve_impact_score FROM cves WHERE cves.cve_impact_score IS NOT NULL"
        ).fetchall()
    cvss_other = list(map(lambda x: x[0], result))

    diff_obs = np.mean(cvss_syswide) - np.mean(cvss_other)

    # Mann–Whitney U (nonparametric location shift)
    u, p_u = stats.mannwhitneyu(cvss_syswide, cvss_other, alternative="two-sided")

    # Bootstrap CI for mean difference
    rng = np.random.default_rng(0)
    B = 10000
    boots = []
    for _ in range(B):
        s = rng.choice(cvss_syswide, size=len(cvss_syswide), replace=True)
        o = rng.choice(cvss_other, size=len(cvss_other), replace=True)
        boots.append(np.mean(s) - np.mean(o))
    ci_low, ci_high = np.percentile(boots, [2.5, 97.5])

    print(
        f"Global Mean: {sum(cvss_other) / len(cvss_other)}. Syswide vulnerabilities mean: {sum(cvss_syswide) / len(cvss_syswide)}"
    )
    print(
        f"Mean diff: {diff_obs:.2f}; 95% bootstrap CI: [{ci_low:.2f}, {ci_high:.2f}]; Mann–Whitney p={p_u:.3g}"
    )


def export_run(db: sqlite3.Connection, run_id: str, output_path: str):
    appending = False

    if os.path.isfile(output_path):
        print("Output file already exists. Appending!!!")
        appending = True

    with open(output_path, mode="a", newline="") as file:
        writer = csv.writer(file, quoting=csv.QUOTE_ALL)

        if not appending:
            # Write header
            # [cve_id, product, patch_id, flag]
            writer.writerow(["cve_id", "product", "id", "flag"])

        flags = _flags_from_run(db, run_id)

        for flag in flags:
            if flag.status == "ok":
                writer.writerow([flag.cve_id, flag.product, flag.patch_id, flag.flag])

        print(f"Exported {len(flags)} flags to {output_path}!")


def main() -> int:
    parser = argparse.ArgumentParser(prog="./cli")
    parser.add_argument(
        "-d",
        "--database",
        default="data/cve-dataset.db",
        help="Path to SQLite DB file (default: data/cve-dataset.db)",
    )
    parser.add_argument(
        "command",
        choices=[
            "runs",
            "run",
            "import",
            "export",
            "random_error",
            "complexity",
            "check-descriptions",
            "var-counts",
            "var-count-plot",
            "variable-severity",
            "common-operations",
            "most-severe-variables",
            "analyze-system-wide-cvss",
        ],
        help="Command to run",
    )

    args, remaining_args = parser.parse_known_args()

    cmd: str = args.command
    database_file: str = args.database

    if not os.path.exists(database_file):
        print(f"Database file at {database_file} does not exist!")
        return 1

    with sqlite3.connect(database_file) as db:
        if cmd == "import":
            p = argparse.ArgumentParser()
            p.add_argument("target", help="Path to CSV file")
            p.add_argument("run_id", help="ID of the run (run_started_at)")
            ns = p.parse_args(remaining_args)
            dst_db_file: str = ns.target
            run_id: str = ns.run_id
            if database_file == dst_db_file:
                print("Cannot import from the same file!")
                return 1
            with sqlite3.connect(dst_db_file) as src_db:
                import_run(src_db, db, run_id)
        elif cmd == "runs":
            show_runs(db)
        elif cmd == "complexity":
            flag_complexity(db)
        elif cmd == "check-descriptions":
            p = argparse.ArgumentParser()
            p.add_argument(
                "runs", help="IDs of the runs to analyze (separated by commas)"
            )
            ns = p.parse_args(remaining_args)
            raw_runs: str = ns.runs
            check_descriptions_v2(db, raw_runs.split(","))
        elif cmd == "run":
            p = argparse.ArgumentParser()
            p.add_argument("run_id", help="ID of the run (run_started_at)")
            ns = p.parse_args(remaining_args)
            run_details(db, ns.run_id)
        elif cmd == "random_error":
            p = argparse.ArgumentParser()
            p.add_argument("run_id", help="ID of the run (run_started_at)")
            ns = p.parse_args(remaining_args)
            random_error(db, ns.run_id)
        elif cmd == "var-counts":
            p = argparse.ArgumentParser()
            p.add_argument("run_id", help="ID of the run (run_started_at)")
            p.add_argument("label", help="Label for the rows in the output csv")
            ns = p.parse_args(remaining_args)
            run_var_counts(db, ns.run_id, ns.label)
        elif cmd == "var-count-plot":
            p = argparse.ArgumentParser()
            p.add_argument(
                "runs", help="IDs of the runs to analyze (separated by commas)"
            )
            ns = p.parse_args(remaining_args)
            raw_runs: str = ns.runs
            run_var_count_plot(db, raw_runs.split(","))
        elif cmd == "variable-severity":
            variable_to_severity_correlation(db)
        elif cmd == "common-operations":
            p = argparse.ArgumentParser()
            p.add_argument(
                "runs", help="IDs of the runs to analyze (separated by commas)"
            )
            ns = p.parse_args(remaining_args)
            raw_runs: str = ns.runs
            analyze_common_operations(db, raw_runs.split(","))
        elif cmd == "most-severe-variables":
            most_severe_variables(db)
        elif cmd == "analyze-system-wide-cvss":
            p = argparse.ArgumentParser()
            p.add_argument(
                "runs", help="IDs of the runs to analyze (separated by commas)"
            )
            ns = p.parse_args(remaining_args)
            raw_runs: str = ns.runs
            analyze_system_wide_cvss(db, raw_runs.split(","))
        elif cmd == "export":
            p = argparse.ArgumentParser()
            _ = p.add_argument("run_id", help="ID of the run (run_started_at)")
            _ = p.add_argument("output", help="Path for the output csv")
            ns = p.parse_args(remaining_args)
            output_path = cast(str, ns.output)
            run_id = cast(str, ns.run_id)
            export_run(db, run_id, output_path)
        else:
            print(f"Unknown command {cmd}!")
            return 1

    return 0


if __name__ == "__main__":
    exit(main())
