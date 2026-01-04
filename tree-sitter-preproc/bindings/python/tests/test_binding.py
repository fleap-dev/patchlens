from unittest import TestCase

from tree_sitter import Language, Parser
import tree_sitter_tree_sitter_preproc


class TestLanguage(TestCase):
    def test_can_load_grammar(self):
        try:
            Parser(Language(tree_sitter_tree_sitter_preproc.language()))
        except Exception:
            self.fail("Error loading Tree-Sitter C Preprocessor Parser grammar")
