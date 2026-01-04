#!/usr/bin/env python3
"""
Unit tests for compare_flags.py
"""

import unittest
from compare_flags import FlagNormalizer, FlagParser, FlagComparator, ComparisonResult


class TestFlagNormalizer(unittest.TestCase):
    """Tests for the FlagNormalizer class."""

    def test_normalize_removes_defined(self):
        """Test that defined() wrapper is removed."""
        normalizer = FlagNormalizer()

        # Simple cases
        self.assertEqual(normalizer.normalize("defined(CONFIG_A)"), "CONFIG_A")
        self.assertEqual(
            normalizer.normalize("defined(CONFIG_A) & defined(CONFIG_B)"),
            "CONFIG_A & CONFIG_B",
        )

    def test_normalize_preserves_operators(self):
        """Test that operators are preserved."""
        normalizer = FlagNormalizer()

        self.assertEqual(
            normalizer.normalize("(defined(CONFIG_A)) | (defined(CONFIG_B))"),
            "(CONFIG_A) | (CONFIG_B)",
        )

    def test_normalize_empty_string(self):
        """Test that empty strings return empty."""
        normalizer = FlagNormalizer()
        self.assertEqual(normalizer.normalize(""), "")
        self.assertEqual(normalizer.normalize("   "), "")

    def test_normalize_no_defined(self):
        """Test that strings without defined() are unchanged."""
        normalizer = FlagNormalizer()
        self.assertEqual(normalizer.normalize("CONFIG_A"), "CONFIG_A")
        self.assertEqual(
            normalizer.normalize("CONFIG_A & CONFIG_B"), "CONFIG_A & CONFIG_B"
        )

    def test_normalize_makefile_eq_y(self):
        """Test that $(CONFIG_X) = y is normalized to CONFIG_X."""
        normalizer = FlagNormalizer()
        self.assertEqual(normalizer.normalize("$(CONFIG_BLOCK) = y"), "CONFIG_BLOCK")
        self.assertEqual(
            normalizer.normalize("$(CONFIG_A) = y & $(CONFIG_B) = y"),
            "CONFIG_A & CONFIG_B",
        )

    def test_normalize_makefile_not_empty(self):
        """Test that ~($(CONFIG_X) = ) is normalized to CONFIG_X."""
        normalizer = FlagNormalizer()
        # The ~($(CONFIG_IPV6) = ) pattern means "CONFIG_IPV6 is not empty"
        self.assertEqual(normalizer.normalize("~($(CONFIG_IPV6) = )"), "CONFIG_IPV6")

    def test_normalize_complex_makefile(self):
        """Test complex expressions with Makefile-style syntax."""
        normalizer = FlagNormalizer()
        # Real case from CSV
        result = normalizer.normalize(
            "(CONFIG_IPV6) & (~($(CONFIG_IPV6) = )) & (CONFIG_NET)"
        )
        self.assertEqual(result, "(CONFIG_IPV6) & (CONFIG_IPV6) & (CONFIG_NET)")


class TestFlagParser(unittest.TestCase):
    """Tests for the FlagParser class."""

    def test_parse_simple_variable(self):
        """Test parsing a simple variable."""
        parser = FlagParser()
        expr = parser.parse("CONFIG_A")
        self.assertIn("CONFIG_A", parser.z3_vars)

    def test_parse_and_expression(self):
        """Test parsing an AND expression."""
        parser = FlagParser()
        expr = parser.parse("CONFIG_A & CONFIG_B")
        self.assertIn("CONFIG_A", parser.z3_vars)
        self.assertIn("CONFIG_B", parser.z3_vars)

    def test_parse_or_expression(self):
        """Test parsing an OR expression."""
        parser = FlagParser()
        expr = parser.parse("CONFIG_A | CONFIG_B")
        self.assertIn("CONFIG_A", parser.z3_vars)
        self.assertIn("CONFIG_B", parser.z3_vars)

    def test_parse_true(self):
        """Test parsing True constant."""
        parser = FlagParser()
        expr = parser.parse("True")
        # Should not raise

    def test_parse_empty_raises(self):
        """Test that empty strings raise an error."""
        parser = FlagParser()
        with self.assertRaises(ValueError):
            parser.parse("")


class TestFlagComparator(unittest.TestCase):
    """Tests for the FlagComparator class."""

    def setUp(self):
        self.comparator = FlagComparator()

    def test_equal_flags(self):
        """Test that identical flags are marked as equal."""
        result = self.comparator.compare("CONFIG_A", "CONFIG_A")
        self.assertEqual(result, ComparisonResult.EQUAL)

    def test_equal_with_defined(self):
        """Test that defined(X) is equivalent to X."""
        result = self.comparator.compare("CONFIG_A", "defined(CONFIG_A)")
        self.assertEqual(result, ComparisonResult.EQUAL)

    def test_and_more_specific(self):
        """Test that A & B is more specific than A."""
        # A & B implies A, so A is more general
        # pclocator: A & B, patchlens: A
        # pclocator implies patchlens -> patchlens is more general
        result = self.comparator.compare("CONFIG_A & CONFIG_B", "CONFIG_A")
        self.assertEqual(result, ComparisonResult.PATCHLENS_MORE_GENERAL)

    def test_or_more_general(self):
        """Test that A | B is more general than A."""
        # A implies A | B, so A | B is more general
        # pclocator: A, patchlens: A | B
        # pclocator implies patchlens -> patchlens is more general
        result = self.comparator.compare("CONFIG_A", "CONFIG_A | CONFIG_B")
        self.assertEqual(result, ComparisonResult.PATCHLENS_MORE_GENERAL)

    def test_true_is_most_general(self):
        """Test that True is the most general flag."""
        # Any flag implies True, so True is more general
        result = self.comparator.compare("CONFIG_A", "True")
        self.assertEqual(result, ComparisonResult.PATCHLENS_MORE_GENERAL)

    def test_incomparable_flags(self):
        """Test that unrelated flags are incomparable."""
        # CONFIG_A and CONFIG_B have no implication relationship
        result = self.comparator.compare("CONFIG_A", "CONFIG_B")
        self.assertEqual(result, ComparisonResult.INCOMPARABLE)

    def test_pclocator_failed(self):
        """Test that empty pclocator flag indicates failure."""
        result = self.comparator.compare("", "CONFIG_A")
        self.assertEqual(result, ComparisonResult.PCLOCATOR_FAILED)

    def test_complex_flags(self):
        """Test more complex flag expressions."""
        # (A & B) | (A & C) should be equivalent to A & (B | C)
        # due to distribution law
        result = self.comparator.compare(
            "(CONFIG_A & CONFIG_B) | (CONFIG_A & CONFIG_C)",
            "CONFIG_A & (CONFIG_B | CONFIG_C)",
        )
        self.assertEqual(result, ComparisonResult.EQUAL)

    def test_pclocator_more_general(self):
        """Test when pclocator is more general."""
        # patchlens: A & B, pclocator: A
        # patchlens implies pclocator -> pclocator is more general
        result = self.comparator.compare("CONFIG_A", "CONFIG_A & CONFIG_B")
        self.assertEqual(result, ComparisonResult.PCLOCATOR_MORE_GENERAL)

    def test_real_world_example_from_csv(self):
        """Test with an example from the actual CSV files."""
        # From pclocator: CONFIG_COMPAT
        # From patchlens: defined(CONFIG_COMPAT)
        result = self.comparator.compare("CONFIG_COMPAT", "defined(CONFIG_COMPAT)")
        self.assertEqual(result, ComparisonResult.EQUAL)

    def test_real_world_complex_example(self):
        """Test with a complex example from the actual CSV files."""
        # Simplified version of a real case
        pclocator = "(CONFIG_IPV6) & (CONFIG_NET)"
        patchlens = "(defined(CONFIG_IPV6)) & (defined(CONFIG_NET))"
        result = self.comparator.compare(pclocator, patchlens)
        self.assertEqual(result, ComparisonResult.EQUAL)


class TestExplainComparison(unittest.TestCase):
    """Tests for the explain_comparison method."""

    def test_explain_returns_string(self):
        """Test that explain_comparison returns a string."""
        comparator = FlagComparator()
        explanation = comparator.explain_comparison("CONFIG_A", "CONFIG_A")
        self.assertIsInstance(explanation, str)
        self.assertIn("EQUAL", explanation)


if __name__ == "__main__":
    unittest.main()
