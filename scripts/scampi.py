#!/usr/bin/env -S uv --quiet run --script
# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "z3-solver",
#     "pandas",
# ]
# ///

import itertools
import random

import pandas as pd
# Generate truth table
from z3 import *

from simplifier import ExpressionSimplifier


def get_vars(expr):
    """Recursively extract all Bool variables from a Z3 expression."""
    if is_const(expr) and expr.decl().kind() == Z3_OP_UNINTERPRETED:
        return {expr}
    return set().union(*(get_vars(c) for c in expr.children()))


def generate_truth_table(z3_vars, expr, as_dataframe=False):
    """Generate truth table for a Z3 expression."""
    vars_list = sorted(get_vars(expr), key=lambda v: v.decl().name())
    var_names = [str(v) for v in vars_list]

    combinations = list(itertools.product([False, True], repeat=len(vars_list)))
    table = []

    for combo in combinations:
        model = dict(zip(var_names, combo))
        z3_subs = [If(z3_vars[name], BoolVal(val), BoolVal(not val)) for name, val in model.items()]
        solver = Solver()
        solver.add(expr)
        val = substitute(expr, [(z3_vars[name], BoolVal(val)) for name, val in model.items()])
        result = is_true(simplify(val))
        table.append({**model, 'Result': result})

    if as_dataframe:
        import pandas as pd
        return pd.DataFrame(table)
    return table


def sample_truth_table_entries(truth_table, n):
    """Randomly select N true and N false rows from a truth table (list of dicts or DataFrame)."""
    if isinstance(truth_table, pd.DataFrame):
        truth_table = truth_table.to_dict(orient="records")

    true_rows = [row for row in truth_table if row["Result"] is True]
    false_rows = [row for row in truth_table if row["Result"] is False]

    if len(true_rows) < n or len(false_rows) < n:
        raise ValueError(f"Not enough rows to sample {n} True and {n} False combinations.")

    return random.sample(true_rows, n), random.sample(false_rows, n)


if __name__ == "__main__":
    # Example usage
    input_expr = "(CONFIG_A) | (((CONFIG_A) | (CONFIG_B)) & ((CONFIG_C) | (CONFIG_K))) | ((CONFIG_J) & ((CONFIG_C) | (CONFIG_O)))"
    simplifier = ExpressionSimplifier()
    z3_vars = simplifier.z3_vars
    simplified_expr = simplifier.str_to_z3(input_expr)
    print("Discovered Variables:")
    print(sorted(simplifier.z3_vars.keys()))
    print("\nOriginal Expression:")
    print(input_expr)
    print("\nSimplified Expression:")
    print(simplified_expr)

    # Sample 5 true and 5 false rows
    truth_table = generate_truth_table(z3_vars, simplified_expr, as_dataframe=True)
    true_samples, false_samples = sample_truth_table_entries(truth_table, 5)

    print("Sampled True Cases:")
    for row in true_samples:
        print(row)

    print("\nSampled False Cases:")
    for row in false_samples:
        print(row)
