#!/usr/bin/env -S uv --quiet run --script
# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "pandas",
#     "z3-solver",
# ]
# ///

import argparse
import ast
import os
import re
import sqlite3

import pandas as pd
import z3
from simplifier import ExpressionSimplifier


class VariantChecker(ExpressionSimplifier):
    def __init__(self, enabled_configs):
        super().__init__()
        self.enabled_configs = enabled_configs

    def ast_to_z3(self, node: ast.AST) -> z3.ExprRef:
        # 1) intercept defined(X) → BoolVal(X in enabled_configs)
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "defined"
            and len(node.args) == 1
            and isinstance(node.args[0], ast.Name)
        ):
            name = node.args[0].id
            return z3.BoolVal(name in self.enabled_configs)

        # 2) otherwise, fall back to your original logic
        return super().ast_to_z3(node)


def is_condition_true_z3_ast(condition: str, enabled_configs: set):
    """
    Parse a condition like "(defined(EXT3_FS) | defined(SND)) && !defined(NOUVEAU)"
    into a Z3 expression via ast.parse, then simplify and test for True.
    """
    # — rewrite C operators into Python AST-friendly ones —
    cond_py = condition.replace("&&", "&").replace("||", "|")
    cond_py = re.sub(r"!\s*", "~", cond_py)

    # — parse into AST and feed into the checker —
    tree = ast.parse(cond_py, mode="eval").body
    checker = VariantChecker(enabled_configs)
    z3_expr = checker.ast_to_z3(tree)

    # — simplify and check —
    simplified = z3.simplify(z3_expr)
    return simplified


def main() -> int:
    parser = argparse.ArgumentParser(prog="./cli")
    parser.add_argument(
        "-d",
        "--database",
        default="data/cve-dataset.db",
        help="Path to SQLite DB file (default: data/cve-dataset.db)",
    )
    parser.add_argument(
        "-f",
        "--csv-file",
        required=True,
        help="Path to the csv file containing the sampled configurations",
    )

    args = parser.parse_args()

    csv_file: str = args.csv_file
    database_file: str = args.database

    if not os.path.exists(database_file):
        print(f"Database file at {database_file} does not exist!")
        return 1

    df = pd.read_csv(csv_file, sep=";", index_col=0)

    # 2. Drop any trailing empty column (named '')
    if "" in df.columns:
        df = df.drop(columns=[""])

    # 3. Transpose: now each row is a variant, each column a config
    df_t = df.transpose()

    # 4. Build a dict mapping variant → list of enabled configs
    variant_enabled = {}
    for variant, row in df_t.iterrows():
        # row is a Series: index = config names, values = '-' or 'X'
        enabled = row[row == "X"].index.tolist()
        variant_enabled[variant] = enabled

    cond = "((defined(CONFIG_MPLS_ROUTING)) & (defined(CONFIG_MPLS)))"

    true_variants = []

    for variant in variant_enabled:
        enabled = variant_enabled[variant]
        result = is_condition_true_z3_ast(cond, enabled)
        if result:
            true_variants.append(variant)

    print(f"Total ({len(true_variants)} of {len(variant_enabled)}): {true_variants}")

    with sqlite3.connect(database_file) as db:
        ...

    return 0


if __name__ == "__main__":
    exit(main())
