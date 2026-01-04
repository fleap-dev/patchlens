import XCTest
import SwiftTreeSitter
import TreeSitterTreeSitterPreproc

final class TreeSitterTreeSitterPreprocTests: XCTestCase {
    func testCanLoadGrammar() throws {
        let parser = Parser()
        let language = Language(language: tree_sitter_tree_sitter_preproc())
        XCTAssertNoThrow(try parser.setLanguage(language),
                         "Error loading Tree-Sitter C Preprocessor Parser grammar")
    }
}
