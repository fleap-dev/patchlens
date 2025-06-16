#!/usr/bin/env -S uv --quiet run --script
# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "z3-solver",
# ]
# ///
import argparse
import ast
import json

import z3


class ExpressionSimplifier:
    # Map Python AST ops to Z3 functions
    OP_MAP = {
        ast.Or: z3.Or,
        ast.And: z3.And,
        ast.Not: z3.Not,
        ast.BitOr: lambda a, b: z3.Or(a, b),
        ast.BitAnd: lambda a, b: z3.And(a, b),
        ast.Invert: z3.Not,
    }

    def __init__(self):
        self.z3_vars = {}  # Variable map

    def ast_to_z3(self, node: ast.AST) -> z3.ExprRef:
        """
        Convert an AST node to a Z3 expression.
        :param node: An AST node.
        :return: A Z3 expression.
        """
        if isinstance(node, ast.BoolOp):
            op = self.OP_MAP[type(node.op)]
            return op(*[self.ast_to_z3(v) for v in node.values])
        elif isinstance(node, ast.BinOp):
            if type(node.op) in self.OP_MAP:
                return self.OP_MAP[type(node.op)](
                    self.ast_to_z3(node.left), self.ast_to_z3(node.right)
                )
            else:
                raise ValueError(f"Unsupported binary op: {ast.dump(node.op)}")
        elif isinstance(node, ast.UnaryOp):
            if type(node.op) in self.OP_MAP:
                return self.OP_MAP[type(node.op)](self.ast_to_z3(node.operand))
            else:
                raise ValueError(f"Unsupported unary op: {ast.dump(node.op)}")
        elif isinstance(node, ast.Name):
            var_name = node.id
            if var_name not in self.z3_vars:
                self.z3_vars[var_name] = z3.Bool(var_name)
            return self.z3_vars[var_name]
        elif isinstance(node, ast.Expr):
            return self.ast_to_z3(node.value)
        elif isinstance(node, ast.Constant):
            return z3.BoolVal(not not node.value)
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and len(node.args) > 0
            and isinstance(node.args[0], ast.Constant)
        ):
            first_arg = node.args[0].value
            var_name = f"{node.func.id}({first_arg})"
            if var_name not in self.z3_vars:
                self.z3_vars[var_name] = z3.Bool(var_name)
            return self.z3_vars[var_name]
        else:
            raise ValueError(f"Unsupported AST node: {ast.dump(node)}")

    def z3_to_str(self, expr: z3.ExprRef) -> str:
        """
        Convert a Z3 expression to a string representation.
        :param expr: A Z3 expression.
        :return: A string representation of the expression.
        """
        if z3.is_const(expr):  # variable like CONFIG_A
            return str(expr)
        elif z3.is_not(expr):
            return f"~({self.z3_to_str(expr.children()[0])})"
        elif z3.is_or(expr):
            return " | ".join(f"({self.z3_to_str(c)})" for c in expr.children())
        elif z3.is_and(expr):
            return " & ".join(f"({self.z3_to_str(c)})" for c in expr.children())
        else:
            raise ValueError(f"Unsupported Z3 expression: {expr}")

    def str_to_z3(self, input_exp: str) -> z3.ExprRef:
        """
        Convert a string representation of a logical expression to a Z3 expression.
        :param input_exp: A string representing the logical expression.
        :return: A Z3 expression.
        """
        # Parse the input expression into an AST
        ast_expr = ast.parse(input_exp, mode="eval").body

        # Convert AST to Z3 expression
        return self.ast_to_z3(ast_expr)

    def simplify(self, input_exp: str) -> str:
        """
        Simplify a logical expression using Z3.
        :param input_exp: A string representing the logical expression.
        :return: A simplified string representation of the expression.
        """
        # Convert string to Z3 expression
        z3_expr = self.str_to_z3(input_exp)
        # Simplify the Z3 expression
        simplified_expr = z3.simplify(z3_expr)
        # Convert back to string representation
        return self.z3_to_str(simplified_expr)


# ---- CLI ----
def main():
    parser = argparse.ArgumentParser(
        description="Boolean expression simplifier using Z3"
    )
    parser.add_argument(
        "--expr",
        type=str,
        required=True,
        help="Boolean expression in Python syntax (e.g., '(A | B) & C')",
    )
    parser.add_argument(
        "--output", type=str, help="Output file for the simplified expression"
    )
    args = parser.parse_args()
    expr_str = args.expr
    output_file = args.output
    if not expr_str:
        raise ValueError("Expression string cannot be empty")
    if output_file and not output_file.endswith(".json"):
        raise ValueError("Output file must have a .json extension")

    # Parse and simplify
    simplifier = ExpressionSimplifier()
    simplified_str = simplifier.simplify(expr_str)

    print(simplified_str)

    if output_file:
        output = {
            "original": expr_str,
            "simplified": simplified_str,
            "variables": sorted(simplifier.z3_vars.keys()),
        }
        # Write output to JSON file
        with open(output_file, "w") as f:
            json.dump(output, f, indent=4)


if __name__ == "__main__":
    main()
