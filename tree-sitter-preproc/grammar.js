/**
 * @file A minimal parser for reading C-style preprocessor macros
 * @license MIT
 */

/// <reference types="tree-sitter-cli/dsl" />
// @ts-check

// Helper: build a token that matches '#', optional whitespace, then a keyword.
// The C standard allows whitespace between '#' and the directive name.
function directive(keyword) {
	return token(seq("#", /\s*/, keyword));
}

module.exports = grammar({
	name: "preproc",

	extras: ($) => [/\s/, $.comment],

	rules: {
		source_file: ($) => repeat($._item),

		_item: ($) =>
			choice(
				$.preproc_ifdef,
				$.preproc_if,
				$.preproc_other_directive,
				$.text_line,
			),

		// #ifdef MACRO / #ifndef MACRO ... #elif ... #else ... #endif
		preproc_ifdef: ($) =>
			seq(
				field(
					"directive",
					alias(
						choice(directive("ifdef"), directive("ifndef")),
						$.preproc_directive,
					),
				),
				field("name", $.identifier),
				/\n/,
				repeat($._item),
				repeat($.preproc_elif),
				optional($.preproc_else),
				directive("endif"),
				optional(/\n/),
			),

		// #if EXPR ... #elif EXPR ... #else ... #endif
		preproc_if: ($) =>
			seq(
				directive("if"),
				field("condition", $._expression),
				/\n/,
				repeat($._item),
				repeat($.preproc_elif),
				optional($.preproc_else),
				directive("endif"),
				optional(/\n/),
			),

		preproc_elif: ($) =>
			seq(
				directive("elif"),
				field("condition", $._expression),
				/\n/,
				repeat($._item),
			),

		preproc_else: ($) => seq(directive("else"), /\n/, repeat($._item)),

		// #define, #undef, #include, and any other directive we don't need to
		// structurally parse.  Matches the '#' plus everything to end-of-line,
		// including backslash-continued lines.
		preproc_other_directive: ($) =>
			seq(
				token(prec(-1, seq("#", /\s*/, /[a-zA-Z_]\w*/))),
				optional(token(prec(-1, /([^\n\\]|\\.?)+/))),
				optional(/\n/),
			),

		// Expressions for #if / #elif conditions
		_expression: ($) =>
			choice(
				$.preproc_defined,
				$.unary_expression,
				$.binary_expression,
				$.parenthesized_expression,
				$.call_expression,
				$.identifier,
				$.number_literal,
			),

		// defined(MACRO) or defined MACRO
		preproc_defined: ($) =>
			choice(
				seq("defined", "(", field("name", $.identifier), ")"),
				seq("defined", field("name", $.identifier)),
			),

		unary_expression: ($) =>
			prec(
				4,
				seq(
					field("operator", alias("!", $.operator)),
					field("argument", $._expression),
				),
			),

		binary_expression: ($) =>
			choice(
				// Logical operators (lower precedence)
				prec.left(
					1,
					seq(
						field("left", $._expression),
						field("operator", alias("||", $.operator)),
						field("right", $._expression),
					),
				),
				prec.left(
					2,
					seq(
						field("left", $._expression),
						field("operator", alias("&&", $.operator)),
						field("right", $._expression),
					),
				),
				// Comparison operators
				prec.left(
					3,
					seq(
						field("left", $._expression),
						field(
							"operator",
							alias(choice("==", "!=", "<", ">", "<=", ">="), $.operator),
						),
						field("right", $._expression),
					),
				),
			),

		parenthesized_expression: ($) => seq("(", $._expression, ")"),

		// For macro invocations like CONFIG_IS_ENABLED(FOO)
		call_expression: ($) =>
			seq(
				field("function", $.identifier),
				"(",
				optional(seq($._expression, repeat(seq(",", $._expression)))),
				")",
			),

		identifier: ($) => /[a-zA-Z_][a-zA-Z0-9_]*/,

		number_literal: ($) =>
			choice(
				/0[xX][0-9a-fA-F]+[uUlL]*/, // hex
				/0[0-7]+[uUlL]*/, // octal
				/[0-9]+[uUlL]*/, // decimal
			),

		// Any non-preprocessor line (C code, comments, etc.)
		text_line: ($) => seq(token(prec(-2, /[^#\n][^\n]*/)), /\n/),

		// C-style comments (block and line)
		comment: ($) =>
			token(
				choice(seq("/*", /[^*]*\*+([^/*][^*]*\*+)*/, "/"), seq("//", /[^\n]*/)),
			),
	},
});
