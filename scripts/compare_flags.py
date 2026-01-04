#!/usr/bin/env -S uv --quiet run --script
# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "z3-solver",
# ]
# ///
"""
Flag Comparison Module

Compares configuration flags from pclocator and patchlens tools using Z3 SMT solver
to determine logical relationships (equivalence, generality, etc.).

Key Concepts:
- Flag A is MORE GENERAL than B if B → A (B implies A)
  Example: CONFIG_NET is more general than (CONFIG_NET & CONFIG_USB)
- Flag A is MORE SPECIFIC than B if A → B (A implies B)
- Flags are EQUIVALENT if A ↔ B (A implies B and B implies A)
- Flags are INCOMPARABLE if neither implies the other
  Example: CONFIG_USB vs CONFIG_NET (neither implies the other)
"""

import ast
import re
from enum import Enum, auto
from typing import Optional

import z3


class ComparisonResult(Enum):
    """Result of comparing two flags."""

    EQUAL = auto()  # Flags are logically equivalent
    PATCHLENS_MORE_GENERAL = (
        auto()
    )  # Patchlens flag is more general (pclocator implies patchlens)
    PCLOCATOR_MORE_GENERAL = (
        auto()
    )  # Pclocator flag is more general (patchlens implies pclocator)
    INCOMPARABLE = auto()  # Neither implies the other
    PCLOCATOR_FAILED = auto()  # Pclocator flag is empty (tool failed)
    PARSE_ERROR = auto()  # Could not parse one or both flags


class FlagNormalizer:
    """
    Normalizes flags from different tools to a common format.

    Patchlens uses various syntaxes:
    - defined(CONFIG_X) -> CONFIG_X
    - $(CONFIG_X) = y -> CONFIG_X (Makefile-style "is set to y")
    - ~($(CONFIG_X) = ) -> CONFIG_X (negated empty check, meaning "is not empty")

    Pclocator uses: CONFIG_X

    This class normalizes all these patterns to enable comparison.
    """

    # Pattern to match defined(CONFIG_X) and extract CONFIG_X
    DEFINED_PATTERN = re.compile(r"\bdefined\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)")

    # Pattern to match $(CONFIG_X) = y and extract CONFIG_X
    # This means "CONFIG_X is set to y" which is equivalent to CONFIG_X being true
    MAKEFILE_EQ_Y_PATTERN = re.compile(r"\$\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*=\s*y")

    # Pattern to match ~($(CONFIG_X) = ) - negated empty check
    # This means "CONFIG_X is not empty" which is equivalent to CONFIG_X being true
    MAKEFILE_NOT_EMPTY_PATTERN = re.compile(
        r"~\s*\(\s*\$\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*=\s*\)"
    )

    # Pattern to match (~("$(CONFIG_X)" == "")) - quoted negated empty check with ==
    # This is another Patchlens syntax meaning "CONFIG_X is not empty"
    # Must match exactly: (~("$(VAR)" == ""))
    QUOTED_NOT_EMPTY_PATTERN = re.compile(
        r'\(\s*~\s*\(\s*"\$\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)"\s*==\s*""\s*\)\s*\)'
    )

    # Pattern to match "$(CONFIG_X)" == "y" - quoted equality check with "y"
    # This means "CONFIG_X is set to y" which is equivalent to CONFIG_X being true
    QUOTED_EQ_Y_PATTERN = re.compile(
        r'"\$\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)"\s*==\s*"y"'
    )

    # Pattern to match standalone $(CONFIG_X) = (empty) - this means "is empty/not set"
    # We convert this to False (since "is empty" = not defined)
    MAKEFILE_EMPTY_PATTERN = re.compile(
        r"\$\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*=\s*(?![y\w])"
    )

    @staticmethod
    def normalize(flag: str) -> str:
        """
        Normalize a flag by converting various syntaxes to standard form.

        Args:
            flag: The flag string to normalize.

        Returns:
            The normalized flag string.
        """
        if not flag or not flag.strip():
            return ""

        normalized = flag

        # Handle (~("$(CONFIG_X)" == "")) -> CONFIG_X
        # This is Patchlens syntax for "CONFIG_X is not empty" (i.e., defined)
        normalized = FlagNormalizer.QUOTED_NOT_EMPTY_PATTERN.sub(r"\1", normalized)

        # Handle ~($(CONFIG_X) = ) -> CONFIG_X
        # This must be done before the empty pattern to avoid double processing
        normalized = FlagNormalizer.MAKEFILE_NOT_EMPTY_PATTERN.sub(r"\1", normalized)

        # Handle $(CONFIG_X) = y -> CONFIG_X
        normalized = FlagNormalizer.MAKEFILE_EQ_Y_PATTERN.sub(r"\1", normalized)

        # Handle "$(CONFIG_X)" == "y" -> CONFIG_X (quoted variant)
        normalized = FlagNormalizer.QUOTED_EQ_Y_PATTERN.sub(r"\1", normalized)

        # Handle $(CONFIG_X) = (empty) -> False
        # But we need to be careful here - an empty check like $(X) =
        # means "X is empty" which is logically ~X
        # However, since we already handled ~($(X) = ) above,
        # remaining $(X) = patterns should become ~(X)
        # But this is complex - for now, let's just remove these as they cause parse errors
        # A standalone empty check is rare; most are negated
        normalized = FlagNormalizer.MAKEFILE_EMPTY_PATTERN.sub(r"(~\1)", normalized)

        # Remove defined() wrapper - replace defined(X) with X
        normalized = FlagNormalizer.DEFINED_PATTERN.sub(r"\1", normalized)

        return normalized.strip()


class FlagParser:
    """
    Parses flag expressions into Z3 boolean expressions.

    Based on the ExpressionSimplifier from simplifier.py but optimized for comparison.
    """

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
        self.z3_vars: dict[str, z3.BoolRef] = {}

    def parse(self, flag: str) -> z3.ExprRef:
        """
        Parse a flag string into a Z3 expression.

        Args:
            flag: The flag string to parse.

        Returns:
            A Z3 boolean expression.

        Raises:
            ValueError: If the flag cannot be parsed.
            SyntaxError: If the flag is not valid Python syntax.
        """
        if not flag or not flag.strip():
            raise ValueError("Empty flag string")

        ast_expr = ast.parse(flag, mode="eval").body
        return self._ast_to_z3(ast_expr)

    def _ast_to_z3(self, node: ast.AST) -> z3.ExprRef:
        """Convert an AST node to a Z3 expression."""
        if isinstance(node, ast.BoolOp):
            op = self.OP_MAP[type(node.op)]
            return op(*[self._ast_to_z3(v) for v in node.values])

        elif isinstance(node, ast.BinOp):
            if type(node.op) in self.OP_MAP:
                return self.OP_MAP[type(node.op)](
                    self._ast_to_z3(node.left), self._ast_to_z3(node.right)
                )
            else:
                raise ValueError(f"Unsupported binary op: {ast.dump(node.op)}")

        elif isinstance(node, ast.UnaryOp):
            if type(node.op) in self.OP_MAP:
                return self.OP_MAP[type(node.op)](self._ast_to_z3(node.operand))
            else:
                raise ValueError(f"Unsupported unary op: {ast.dump(node.op)}")

        elif isinstance(node, ast.Name):
            var_name = node.id
            if var_name not in self.z3_vars:
                self.z3_vars[var_name] = z3.Bool(var_name)
            return self.z3_vars[var_name]

        elif isinstance(node, ast.Expr):
            return self._ast_to_z3(node.value)

        elif isinstance(node, ast.Constant):
            # Handle True/False constants
            return z3.BoolVal(bool(node.value))

        elif isinstance(node, ast.Call):
            # Handle function calls like defined(CONFIG_X) - should be normalized away
            # but handle gracefully if encountered
            if isinstance(node.func, ast.Name) and len(node.args) == 1:
                if isinstance(node.args[0], ast.Name):
                    var_name = node.args[0].id
                    if var_name not in self.z3_vars:
                        self.z3_vars[var_name] = z3.Bool(var_name)
                    return self.z3_vars[var_name]
                elif isinstance(node.args[0], ast.Constant):
                    var_name = f"{node.func.id}({node.args[0].value})"
                    if var_name not in self.z3_vars:
                        self.z3_vars[var_name] = z3.Bool(var_name)
                    return self.z3_vars[var_name]
            raise ValueError(f"Unsupported function call: {ast.dump(node)}")

        elif isinstance(node, ast.Compare):
            # Handle comparisons like "$(CONFIG_X) = y" or similar
            # Convert to a single boolean variable representing the condition
            var_name = ast.unparse(node)
            if var_name not in self.z3_vars:
                self.z3_vars[var_name] = z3.Bool(var_name)
            return self.z3_vars[var_name]

        else:
            raise ValueError(f"Unsupported AST node: {ast.dump(node)}")


class FlagComparator:
    """
    Compares two flags using Z3 SMT solver.

    The comparison is based on logical implication:
    - Flag A is more general than B if: B → A (B implies A)
      This means B is more restrictive, so A covers more cases.
    - Equivalence: A ↔ B (A implies B and B implies A)

    Example:
    - "CONFIG_NET & CONFIG_USB" implies "CONFIG_NET"
    - Therefore "CONFIG_NET" is more general than "CONFIG_NET & CONFIG_USB"

    - "CONFIG_NET" does NOT imply "CONFIG_NET | CONFIG_USB"
    - But "CONFIG_NET" IS implied BY "CONFIG_NET | CONFIG_USB"? No!
    - "CONFIG_NET | CONFIG_USB" being true doesn't mean CONFIG_NET is true
    - So they are incomparable? No wait...

    Let me reconsider:
    - "CONFIG_NET" implies "CONFIG_NET | CONFIG_USB" (if NET is true, NET|USB is true)
    - "CONFIG_NET | CONFIG_USB" does NOT imply "CONFIG_NET"
    - So "CONFIG_NET | CONFIG_USB" is more general than "CONFIG_NET"
    - This makes sense: OR adds more possibilities, so it's more general.
    """

    def __init__(self):
        self.normalizer = FlagNormalizer()

    def _parse_flag(self, flag: str) -> Optional[z3.ExprRef]:
        """Parse a flag string, returning None on error."""
        if not flag or not flag.strip():
            return None

        try:
            parser = FlagParser()
            return parser.parse(flag)
        except (ValueError, SyntaxError) as e:
            return None

    def _implies(self, a: z3.ExprRef, b: z3.ExprRef) -> bool:
        """
        Check if a → b (a implies b) is always true.

        We check this by verifying that a ∧ ¬b is unsatisfiable.
        If there's no assignment where a is true and b is false,
        then a → b is always true.

        Args:
            a: The antecedent expression.
            b: The consequent expression.

        Returns:
            True if a implies b, False otherwise.
        """
        solver = z3.Solver()
        # Check if a ∧ ¬b is satisfiable
        solver.add(z3.And(a, z3.Not(b)))
        result = solver.check()
        # If unsatisfiable, then a → b is always true
        return result == z3.unsat

    def _equivalent(self, a: z3.ExprRef, b: z3.ExprRef) -> bool:
        """
        Check if a ↔ b (a is equivalent to b) is always true.

        We check this by verifying that (a ∧ ¬b) ∨ (¬a ∧ b) is unsatisfiable.
        This is equivalent to checking both a → b and b → a.

        Args:
            a: First expression.
            b: Second expression.

        Returns:
            True if a and b are logically equivalent, False otherwise.
        """
        solver = z3.Solver()
        # Check if (a ∧ ¬b) ∨ (¬a ∧ b) is satisfiable (XOR)
        solver.add(z3.Xor(a, b))
        result = solver.check()
        # If unsatisfiable, then a ↔ b is always true
        return result == z3.unsat

    def compare(
        self, pclocator_flag: str, patchlens_flag: str, normalize_patchlens: bool = True
    ) -> ComparisonResult:
        """
        Compare two flags and determine their logical relationship.

        Args:
            pclocator_flag: The flag from pclocator tool.
            patchlens_flag: The flag from patchlens tool.
            normalize_patchlens: If True, normalize patchlens flags by removing defined().

        Returns:
            A ComparisonResult indicating the relationship between the flags.
        """
        # Check for pclocator failure (empty flag)
        if not pclocator_flag or not pclocator_flag.strip():
            return ComparisonResult.PCLOCATOR_FAILED

        # Normalize patchlens flag if requested
        if normalize_patchlens:
            patchlens_flag = self.normalizer.normalize(patchlens_flag)

        # Parse both flags
        pc_expr = self._parse_flag(pclocator_flag)
        pl_expr = self._parse_flag(patchlens_flag)

        if pc_expr is None or pl_expr is None:
            return ComparisonResult.PARSE_ERROR

        # Check equivalence first (most specific relationship)
        if self._equivalent(pc_expr, pl_expr):
            return ComparisonResult.EQUAL

        # Check for implication relationships
        pc_implies_pl = self._implies(pc_expr, pl_expr)
        pl_implies_pc = self._implies(pl_expr, pc_expr)

        if pc_implies_pl and not pl_implies_pc:
            # pclocator implies patchlens, but not vice versa
            # This means patchlens is more general (covers more cases)
            return ComparisonResult.PATCHLENS_MORE_GENERAL

        if pl_implies_pc and not pc_implies_pl:
            # patchlens implies pclocator, but not vice versa
            # This means pclocator is more general (covers more cases)
            return ComparisonResult.PCLOCATOR_MORE_GENERAL

        # Neither implies the other
        return ComparisonResult.INCOMPARABLE

    def explain_comparison(self, pclocator_flag: str, patchlens_flag: str) -> str:
        """
        Provide a human-readable explanation of the comparison result.

        Args:
            pclocator_flag: The flag from pclocator tool.
            patchlens_flag: The flag from patchlens tool.

        Returns:
            A string explaining the comparison result.
        """
        result = self.compare(pclocator_flag, patchlens_flag)
        normalized_pl = self.normalizer.normalize(patchlens_flag)

        explanations = {
            ComparisonResult.EQUAL: f"EQUAL: '{pclocator_flag}' ≡ '{normalized_pl}' (logically equivalent)",
            ComparisonResult.PATCHLENS_MORE_GENERAL: f"PATCHLENS MORE GENERAL: '{pclocator_flag}' → '{normalized_pl}' "
            f"(pclocator is more specific)",
            ComparisonResult.PCLOCATOR_MORE_GENERAL: f"PCLOCATOR MORE GENERAL: '{normalized_pl}' → '{pclocator_flag}' "
            f"(patchlens is more specific)",
            ComparisonResult.INCOMPARABLE: f"INCOMPARABLE: '{pclocator_flag}' and '{normalized_pl}' "
            f"have no implication relationship",
            ComparisonResult.PCLOCATOR_FAILED: "PCLOCATOR FAILED: pclocator flag is empty",
            ComparisonResult.PARSE_ERROR: f"PARSE ERROR: Could not parse one or both flags",
        }

        return explanations[result]


# ---- CLI ----
def main():
    """Command-line interface for comparing two flags."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Compare two configuration flags using Z3 SMT solver"
    )
    parser.add_argument(
        "--pclocator", "-p", type=str, required=True, help="Flag from pclocator tool"
    )
    parser.add_argument(
        "--patchlens", "-l", type=str, required=True, help="Flag from patchlens tool"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Show detailed explanation"
    )

    args = parser.parse_args()

    comparator = FlagComparator()

    if args.verbose:
        print(comparator.explain_comparison(args.pclocator, args.patchlens))
    else:
        result = comparator.compare(args.pclocator, args.patchlens)
        print(result.name)


if __name__ == "__main__":
    main()
