#!/usr/bin/env -S uv --quiet run --script
# /// script
# requires-python = ">=3.13"
# dependencies = [
# ]
# ///

import argparse
import os
import sqlite3


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
            "error"
        ) VALUES (?, ?, ?, ?, ?, ?)
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


def main() -> int:
    parser = argparse.ArgumentParser(prog="./cli")
    parser.add_argument(
        "-d",
        "--database",
        default="data/cve-dataset.db",
        help="Path to SQLite DB file (default: data/cve-dataset.db)",
    )
    parser.add_argument(
        "command", choices=["import", "runs", "run"], help="Command to run"
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
        elif cmd == "run":
            p = argparse.ArgumentParser()
            p.add_argument("run_id", help="ID of the run (run_started_at)")
            ns = p.parse_args(remaining_args)
            run_details(db, ns.run_id)
        else:
            print(f"Unknown command {cmd}!")
            return 1

    return 0


if __name__ == "__main__":
    exit(main())
