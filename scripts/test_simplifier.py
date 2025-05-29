import unittest

from simplifier import ExpressionSimplifier


class TestSimplifier(unittest.TestCase):
    def setUp(self):
        # Create a temporary directory for testing
        self.data_dir = "data"

    def run_assertions(self, input: str, simplifier: ExpressionSimplifier, expected_vars: list, expected_output: str):
        simplified_expr = simplifier.simplify(input)
        print("Discovered Variables:")
        print(sorted(simplifier.z3_vars.keys()))
        print("\nOriginal Expression:")
        print(input)
        print("\nSimplified Expression:")
        print(simplified_expr)

        self.assertEqual(len(expected_vars), len(simplifier.z3_vars))
        for var in expected_vars:
            self.assertIn(var, simplifier.z3_vars)
            self.assertIn(var, simplified_expr)
        self.assertEqual(simplified_expr, expected_output)

    def test_valid_expression(self):
        input_expr = "((CONFIG_A | CONFIG_B) & (CONFIG_C | CONFIG_K)) | CONFIG_A | (CONFIG_J & (CONFIG_C | CONFIG_O))"
        simplifier = ExpressionSimplifier()
        expected_vars = ["CONFIG_A", "CONFIG_B", "CONFIG_C", "CONFIG_K", "CONFIG_J", "CONFIG_O"]
        expected_output = "(CONFIG_A) | (((CONFIG_A) | (CONFIG_B)) & ((CONFIG_C) | (CONFIG_K))) | ((CONFIG_J) & ((CONFIG_C) | (CONFIG_O)))"
        self.run_assertions(input_expr, simplifier, expected_vars, expected_output)



    def test_simplifier_with_simple_expression(self):
        input_expr = "A | B | A | C"
        simplifier = ExpressionSimplifier()
        expected_vars = ["A", "B", "C"]
        expected_output = "(A) | (B) | (C)"
        self.run_assertions(input_expr, simplifier, expected_vars, expected_output)

    def test_simplifier_with_empty_input(self):
        simplifier = ExpressionSimplifier()
        with self.assertRaises(SyntaxError):
            simplifier.simplify("")
