#!/usr/bin/env -S uv --quiet run --script
# /// script
# requires-python = ">=3.13"
# dependencies = [
# ]
# ///

import argparse
import ast
import csv
import difflib
import os
import random
import re
import sqlite3
import sys
from collections import Counter
from typing import Tuple

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


def var_count_from_flag(flag: str) -> Tuple[int, Counter]:
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
            "import",
            "runs",
            "run",
            "random_error",
            "complexity",
            "check-descriptions",
            "var-counts",
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
            check_descriptions(db)
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
        else:
            print(f"Unknown command {cmd}!")
            return 1

    return 0


if __name__ == "__main__":
    exit(main())
