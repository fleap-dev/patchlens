package tree_sitter_tree_sitter_preproc_test

import (
	"testing"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tree_sitter_tree_sitter_preproc "github.com/tree-sitter/tree-sitter-tree_sitter_preproc/bindings/go"
)

func TestCanLoadGrammar(t *testing.T) {
	language := tree_sitter.NewLanguage(tree_sitter_tree_sitter_preproc.Language())
	if language == nil {
		t.Errorf("Error loading Tree-Sitter C Preprocessor Parser grammar")
	}
}
