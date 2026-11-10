#!/usr/bin/env -S uv --quiet run --script
# /// script
# requires-python = ">=3.13"
# dependencies = []
# ///

# Builds a self-contained HTML dashboard of one PatchLens run over the Linux CVEs:
#
#   ./scripts/linux_dashboard.py [--db data/cve-dataset.db] [--run <run_started_at>]
#
# It opens the database read-only, classifies each patch's result into a cause, and
# embeds the rows in `linux_dashboard.template.html`, which does the filtering and
# drawing in the browser. The Linux clone is only read, to tell which failing patches
# sit in a directory without a Makefile or Kbuild.

import argparse
import ast
import json
import os
import re
import sqlite3
import subprocess
from datetime import datetime

PRODUCT = "linux/linux_kernel"
SOURCES = ["git-kernel", "patchdb", "github"]
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", None]
TEMPLATE = os.path.join(os.path.dirname(__file__), "linux_dashboard.template.html")

# Every cause a patch's result can have, in display order, with its label and the
# outcome it rolls up to (ok, backport, checkout, not_c or patchlens).
CAUSES = {
    "ok": ("VIC computed", "ok"),
    "likely_backport": (
        "Commit missing from the clone, likely a stable backport",
        "backport",
    ),
    "missing_commit": (
        "Commit missing from the clone, no mainline sibling",
        "checkout",
    ),
    "missing_parent": ("Parent revision missing from the clone", "checkout"),
    "empty_commit": ("Merge or empty commit", "checkout"),
    "unreadable_patch": ("Patch file isn't valid UTF-8", "checkout"),
    "not_c_source": ("Patch doesn't change a C source file", "not_c"),
    "no_makefile_own_dir": (
        "Kbuild walk: file's own directory has no Makefile",
        "patchlens",
    ),
    "no_makefile_ancestor": (
        "Kbuild walk: a parent directory has no Makefile",
        "patchlens",
    ),
    "obj_not_found": ("Kbuild walk: object not found in Makefile", "patchlens"),
    "target_missing": ("Kbuild walk: target file doesn't exist", "patchlens"),
    "kbuild_else_ifeq": ("Kbuild parser: `else ifeq`", "patchlens"),
    "kbuild_override": ("Kbuild parser: `override`", "patchlens"),
    "kbuild_other": ("Kbuild parser: other syntax", "patchlens"),
    "if_operator": ("Unsupported operator in `#if`", "patchlens"),
    "patch_apply": ("Patch doesn't apply", "patchlens"),
    "patchlens_other": ("Other PatchLens error", "patchlens"),
}
CAUSE_INDEX = {key: index for index, key in enumerate(CAUSES)}

STDERR_PATTERN = re.compile(r"\nSTDERR: (b(['\"]).*\2)\s*$", re.DOTALL)
PANIC_PATTERN = re.compile(r"panicked at [^\n]+:\n(.*?)(?:\nnote: |\Z)", re.DOTALL)
TREE_PATTERN = re.compile(r"/tmp/patchlens-linux-[^/\s\"]+/?")
CONFIGS_PATTERN = re.compile(
    r"failed to find required configs for (\S+?): (.*)", re.DOTALL
)
KBUILD_LINE_PATTERN = re.compile(r'\bline: "((?:[^"\\]|\\.)*)"')
OPTION_PATTERN = re.compile(r"defined\((\w+)\)|\$\((\w+)\)")


# Returns the stderr PatchLens printed, as stored in the error column by
# `automate_patchlens.py`, or "" when the error has none.
def patchlens_stderr(error: str) -> str:
    match = STDERR_PATTERN.search(error)
    if match is None:
        return ""
    return ast.literal_eval(match.group(1)).decode("utf-8", errors="replace")


# Classifies a PatchlensError into a cause. Returns the cause, a short detail for the
# explorer table and, for "no Makefile" panics, the patched file's path in the tree.
def classify_patchlens_error(error: str) -> tuple[str, str, str | None]:
    stderr = TREE_PATTERN.sub("", patchlens_stderr(error))
    panic = PANIC_PATTERN.search(stderr)
    if panic is None:
        lines = [line.strip() for line in stderr.splitlines() if line.strip()]
        detail = " ".join(lines[-4:]) or error[:300]
        cause = (
            "patch_apply" if "failed to apply patch" in stderr else "patchlens_other"
        )
        return cause, detail, None

    message = panic.group(1).strip()
    configs = CONFIGS_PATTERN.match(message)
    if configs is not None:
        path, reason = configs.groups()
        if "no Makefile/Kbuild here" in reason:
            return "no_makefile_own_dir", message, path
        if reason.startswith("could not find"):
            return "obj_not_found", message, None
        if "target file does not exist" in reason:
            return "target_missing", message, None
    if message.startswith("Failed to parse Kbuild"):
        line = KBUILD_LINE_PATTERN.search(message)
        text = line.group(1).encode().decode("unicode_escape") if line else ""
        detail = f"Failed to parse Kbuild line: {text.strip()}"
        if text.strip().startswith("else ifeq"):
            return "kbuild_else_ifeq", detail, None
        if text.strip().startswith("override"):
            return "kbuild_override", detail, None
        return "kbuild_other", detail, None
    if message.startswith("unknown expression inside if macro"):
        return "if_operator", message, None
    return "patchlens_other", message[:300], None


# Classifies a CheckoutError. `has_found_commit` says whether another patch of the same
# CVE was found in the clone, which marks a missing commit as a likely stable backport.
def classify_checkout_error(error: str, has_found_commit: bool) -> str:
    if error.startswith("Commit ") and error.endswith("not found in the repository"):
        return "likely_backport" if has_found_commit else "missing_commit"
    if error.startswith("Revision "):
        return "missing_parent"
    if "has no patch" in error:
        return "empty_commit"
    return "unreadable_patch"


# Whether the run found the patch's commit in the clone.
def commit_found(status: str, error: str | None) -> bool:
    return status != "CheckoutError" or "has no patch" in (error or "")


# Distinct Kconfig options and Make variables (like ARCH) a VIC mentions.
def vic_options(vic: str) -> list[str]:
    return sorted({a or b for a, b in OPTION_PATTERN.findall(vic)})


# For each (revision, file) pair, whether the file's own directory has a Makefile or
# Kbuild at `revision~1`, which is the tree PatchLens ran on. One `git cat-file` call.
def own_dir_has_makefile(repo: str, files: list[tuple[str, str]]) -> list[bool]:
    queries = [
        f"{rev}~1:{os.path.join(os.path.dirname(path), name)}"
        for rev, path in files
        for name in ("Makefile", "Kbuild")
    ]
    output = subprocess.run(
        ["git", "cat-file", "--batch-check"],
        cwd=repo,
        input="".join(f"{query}\n" for query in queries),
        capture_output=True,
        text=True,
        check=True,
    ).stdout.splitlines()
    found = [not line.endswith(" missing") for line in output]
    return [found[2 * i] or found[2 * i + 1] for i in range(len(files))]


def clone_head(repo: str) -> str:
    return subprocess.run(
        ["git", "log", "-1", "--format=%h, committed %cs"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def build_data(db: sqlite3.Connection, run: str | None, repo: str) -> dict:
    if run is None:
        (run,) = db.execute(
            """
            SELECT MAX(f.run_started_at)
            FROM flags f
            JOIN patches p ON p.id = f.patch_id
            JOIN cves c ON c.cve_id = p.cve_id
            WHERE c.calculated_product = ?
            """,
            [PRODUCT],
        ).fetchone()
        if run is None:
            raise SystemExit(f"No PatchLens run over {PRODUCT} in the database")

    cves = db.execute(
        "SELECT cve_id, year, severity FROM cves WHERE calculated_product = ? ORDER BY cve_id",
        [PRODUCT],
    ).fetchall()
    cve_index = {cve_id: index for index, (cve_id, _, _) in enumerate(cves)}

    rows = db.execute(
        """
        SELECT f.patch_id, p.source, p.cve_id, f.status, f.flag, f.error,
               f.time_processing_ms, f.checkout_time_ms, f.patchlens_version
        FROM flags f
        JOIN patches p ON p.id = f.patch_id
        JOIN cves c ON c.cve_id = p.cve_id
        WHERE f.run_started_at = ? AND c.calculated_product = ?
        ORDER BY c.year DESC, p.cve_id, f.patch_id
        """,
        [run, PRODUCT],
    ).fetchall()

    cves_with_found_commit = {
        cve_id
        for _, _, cve_id, status, _, error, *_ in rows
        if commit_found(status, error)
    }

    options: dict[str, int] = {}
    data_rows: dict[str, list] = {
        key: [] for key in ("id", "src", "cve", "cause", "t", "tree", "opts", "detail")
    }
    no_makefile: list[tuple[int, str, str]] = []
    for patch_id, source, cve_id, status, flag, error, seconds, tree_seconds, _ in rows:
        detail = None
        option_ids = None
        if status == "ok":
            cause = "ok"
            detail = flag
            option_ids = [
                options.setdefault(name, len(options)) for name in vic_options(flag)
            ]
        elif status == "DoesNotModifyCSource":
            cause = "not_c_source"
        elif status == "CheckoutError":
            cause = classify_checkout_error(error, cve_id in cves_with_found_commit)
            # "Commit <id> not found" only repeats the commit, which the page already shows.
            if cause not in ("likely_backport", "missing_commit"):
                detail = re.sub(r"/\S*/data/patches/", "", error)
        else:
            cause, detail, path = classify_patchlens_error(error)
            if path is not None:
                no_makefile.append((len(data_rows["id"]), patch_id, path))

        data_rows["id"].append(patch_id)
        data_rows["src"].append(SOURCES.index(source))
        data_rows["cve"].append(cve_index[cve_id])
        data_rows["cause"].append(CAUSE_INDEX[cause])
        # The run stores seconds in the *_ms columns.
        data_rows["t"].append(None if seconds is None else round(seconds * 1000, 2))
        data_rows["tree"].append(
            None if tree_seconds is None else round(tree_seconds * 1000, 2)
        )
        data_rows["opts"].append(option_ids)
        data_rows["detail"].append(detail)

    own_dir = own_dir_has_makefile(repo, [(rev, path) for _, rev, path in no_makefile])
    for (row, _, _), has_makefile in zip(no_makefile, own_dir):
        if has_makefile:
            data_rows["cause"][row] = CAUSE_INDEX["no_makefile_ancestor"]

    return {
        "run": {
            "startedAt": run,
            "patchlensVersion": rows[0][8] if rows else None,
            "cloneHead": clone_head(repo),
            "generatedAt": datetime.now().isoformat(timespec="minutes"),
        },
        "sources": SOURCES,
        "severities": [severity or "UNKNOWN" for severity in SEVERITIES],
        "causes": [
            {"key": key, "label": label, "outcome": outcome}
            for key, (label, outcome) in CAUSES.items()
        ],
        "options": list(options),
        "cves": {
            "id": [cve_id for cve_id, _, _ in cves],
            "year": [year for _, year, _ in cves],
            "sev": [SEVERITIES.index(severity) for _, _, severity in cves],
        },
        "rows": data_rows,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build an HTML dashboard of a PatchLens run over the Linux CVEs."
    )
    parser.add_argument("--db", default="data/cve-dataset.db")
    parser.add_argument(
        "--run", help="run_started_at of the run; defaults to the latest"
    )
    parser.add_argument("--linux-repo", default="data/repos/linux")
    parser.add_argument("--output", default="data/linux-dashboard.html")
    args = parser.parse_args()

    db = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    data = build_data(db, args.run, args.linux_repo)

    with open(TEMPLATE) as f:
        template = f.read()
    # Escaping "</" keeps the JSON from closing its <script> tag early.
    payload = json.dumps(data, separators=(",", ":")).replace("</", "<\\/")
    with open(args.output, "w") as f:
        f.write(template.replace("__DATA__", payload))
    print(
        f"Wrote {args.output} ({len(data['rows']['id'])} patches, run {data['run']['startedAt']})"
    )


if __name__ == "__main__":
    main()
