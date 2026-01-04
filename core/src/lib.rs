use std::ops::Deref;

use anyhow::{ensure, Context};
use logical_utils::Flag;
use tracing::debug;
use tree_sitter::{Node, Parser};

pub mod build_expanders;
pub mod logical_utils;
pub mod mail_utils;
pub mod patch_utils;
pub mod preprocessor;

#[cfg(test)]
mod test;

pub fn find_patchlens_ifdef_nodes<'a>(source: &'a str, root: Node<'a>) -> Vec<Node<'a>> {
    fn recursive<'a>(source: &str, node: Node<'a>, output: &mut Vec<Node<'a>>) {
        if node.kind() == "preproc_ifdef" {
            let (_ifdef_cmd, flag) =
                parse_ifdef_node(source, &node).expect("failed to parse ifdef node");
            if flag == patch_utils::PATCH_WRAPPER_IFDEF {
                output.push(node);
                return;
            }
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            recursive(source, child, output);
        }
    }

    let mut result = Vec::new();

    recursive(source, root, &mut result);

    result
}

pub fn analyze_variants_affected(source: &str, filename: &str, explain: bool) -> Flag {
    debug!("Analyzing {filename}...");

    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_preproc::LANGUAGE.into())
        .expect("Error loading Rust grammar");

    let tree = parser.parse(source, None).unwrap();
    let root_node = tree.root_node();

    // TODO: how we should handle this?
    // assert!(!root_node.has_error(), "TreeSitter failed to parse the full source code!");

    let patchlens_ifdef_nodes = find_patchlens_ifdef_nodes(source, root_node);

    if explain {
        eprintln!(
            "[Explain] Patchlens ifdef nodes for file '{filename}': {}",
            patchlens_ifdef_nodes.len()
        )
    }

    if patchlens_ifdef_nodes.is_empty() {
        return Flag::Building(filename.to_owned());
    }

    let hunk_configs = Flag::Or(
        patchlens_ifdef_nodes
            .into_iter()
            .map(|node| node.parent().unwrap()) // analyze the parent nodes of the new inserted nodes
            .map(|n| analyze_configs_for_ast_node(source, n))
            .collect::<Vec<_>>(),
    );

    Flag::And(vec![hunk_configs, Flag::Building(filename.to_owned())])
}

pub fn analyze_configs_for_ast_node(source: &str, node: Node) -> Flag {
    let mut conditions = Vec::new();
    let mut current = Some(node);
    let mut last: Option<Node> = None;
    while let Some(inner) = current {
        // TODO: implement for C++
        match inner.kind() {
            "preproc_ifdef" => {
                let last_kind = last.map(|l| l.kind());
                let (cmd, raw_flag) =
                    parse_ifdef_node(source, &inner).expect("failed to parse ifdef node");
                let raw_flag = raw_flag.to_owned();

                let flag: Flag = match (cmd, last_kind) {
                    (IfdefCommand::Ifdef, Some("preproc_else")) => {
                        Flag::Not(Box::new(Flag::Defined(raw_flag)))
                    }
                    (IfdefCommand::Ifndef, Some("preproc_else")) => Flag::Defined(raw_flag),
                    (IfdefCommand::Ifdef, _) => Flag::Defined(raw_flag),
                    (IfdefCommand::Ifndef, _) => Flag::Not(Box::new(Flag::Defined(raw_flag))),
                };

                match flag {
                    // Filter out header guards
                    Flag::Not(b) if matches!(b.deref(), Flag::Defined(s) if s.ends_with("_H") || s.ends_with("_H_") || s.ends_with("_H__")) =>
                        {}
                    _ => conditions.push(flag),
                }
            }
            "preproc_else" => {
                // Ignored because this will be checked on the parent preproc_ifdef...
            }
            "preproc_if" => {
                let fallback_condition = {
                    // Fallback to the first named child that isn't a directive token.
                    let mut cursor = inner.walk();
                    let found = inner
                        .named_children(&mut cursor)
                        .find(|child| child.kind() != "if_directive");
                    found
                };
                let condition = inner
                    .child_by_field_name("condition")
                    .or(fallback_condition)
                    .expect("preproc_if missing condition");
                let last_kind = last.map(|l| l.kind());

                let flag = parse_if_macro_condition(condition, source);

                let flag = match last_kind {
                    Some("preproc_else") => Flag::Not(Box::new(flag)),
                    _ => flag,
                };

                conditions.push(flag);
            }
            _ => {}
        }
        last = current;
        current = inner.parent();
    }

    if conditions.is_empty() {
        Flag::True
    } else {
        Flag::And(conditions)
    }
}

fn parse_if_macro_condition(condition: Node, source: &str) -> Flag {
    fn parse_number_literal(text: &str) -> Option<i64> {
        let trimmed = text.trim_end_matches(|c| matches!(c, 'u' | 'U' | 'l' | 'L'));
        if let Some(hex) = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
        {
            i64::from_str_radix(hex, 16).ok()
        } else if let Some(oct) = trimmed.strip_prefix('0') {
            if oct.is_empty() {
                Some(0)
            } else {
                i64::from_str_radix(oct, 8).ok()
            }
        } else {
            trimmed.parse::<i64>().ok()
        }
    }

    fn parse_operator_text(node: Node, source: &str) -> String {
        node.utf8_text(source.as_bytes())
            .unwrap_or_default()
            .trim()
            .to_string()
    }

    fn extract_defined_identifier(node: Node, source: &str) -> Option<String> {
        match node.kind() {
            "identifier" => Some(node.utf8_text(source.as_bytes()).ok()?.to_string()),
            "preproc_defined" => {
                let name = node.child_by_field_name("name").or_else(|| node.child(2))?;
                Some(name.utf8_text(source.as_bytes()).ok()?.to_string())
            }
            _ => None,
        }
    }

    match condition.kind() {
        "number_literal" => {
            let text = condition.utf8_text(source.as_bytes()).unwrap_or_default();
            match parse_number_literal(text) {
                Some(0) => Flag::False,
                Some(_) => Flag::True,
                None => Flag::True,
            }
        }
        "preproc_defined" => Flag::Defined(
            condition
                .child_by_field_name("name")
                .or_else(|| condition.child(2))
                .unwrap()
                .utf8_text(source.as_bytes())
                .unwrap()
                .to_owned(),
        ),
        "unary_expression" => {
            let operator = condition.child(0).unwrap();
            let operand = condition.named_child(0).unwrap();
            let operator_text = parse_operator_text(operator, source);
            assert_eq!(operator_text, "!", "unknown unary operator in if macro");

            Flag::Not(Box::new(parse_if_macro_condition(operand, source)))
        }
        "binary_expression" => {
            let left = condition.named_child(0).unwrap();
            let right = condition.named_child(1).unwrap();
            let op = condition.child(1).unwrap();
            let op_text = parse_operator_text(op, source);

            match op_text.as_str() {
                "||" => Flag::Or(vec![
                    parse_if_macro_condition(left, source),
                    parse_if_macro_condition(right, source),
                ]),
                "&&" => Flag::And(vec![
                    parse_if_macro_condition(left, source),
                    parse_if_macro_condition(right, source),
                ]),
                "==" | "!=" => {
                    let left_ident = extract_defined_identifier(left, source);
                    let right_ident = extract_defined_identifier(right, source);
                    let left_num = left
                        .utf8_text(source.as_bytes())
                        .ok()
                        .and_then(parse_number_literal);
                    let right_num = right
                        .utf8_text(source.as_bytes())
                        .ok()
                        .and_then(parse_number_literal);

                    let (ident, num) = match (left_ident, right_num) {
                        (Some(i), Some(n)) => (Some(i), Some(n)),
                        _ => match (right_ident, left_num) {
                            (Some(i), Some(n)) => (Some(i), Some(n)),
                            _ => (None, None),
                        },
                    };

                    if let (Some(ident), Some(num)) = (ident, num) {
                        let defined = Flag::Defined(ident);
                        match (op_text.as_str(), num) {
                            ("==", 0) => Flag::Not(Box::new(defined)),
                            ("!=", 0) => defined,
                            ("==", _) => defined,
                            ("!=", _) => Flag::Not(Box::new(defined)),
                            _ => Flag::True,
                        }
                    } else {
                        Flag::True
                    }
                }
                _ => Flag::True,
            }
        }
        "parenthesized_expression" => parse_if_macro_condition(condition.child(1).unwrap(), source),
        "identifier" => {
            let content = condition.utf8_text(source.as_bytes()).unwrap();
            Flag::Defined(content.to_string())
        }
        "call_expression" => {
            let function = condition
                .child_by_field_name("function")
                .or_else(|| condition.named_child(0))
                .unwrap();
            let func_name = function.utf8_text(source.as_bytes()).unwrap_or_default();

            let mut args = Vec::new();
            let mut cursor = condition.walk();
            for child in condition.named_children(&mut cursor) {
                if child.id() != function.id() {
                    args.push(child);
                }
            }

            let arg_flag = args
                .first()
                .map(|arg| parse_if_macro_condition(*arg, source))
                .unwrap_or(Flag::True);

            match func_name {
                "IS_ENABLED" | "IS_BUILTIN" | "IS_MODULE" | "IS_REACHABLE" => arg_flag,
                _ => arg_flag,
            }
        }
        _ => panic!("unknown expression inside if macro: {}", condition.kind()),
    }
}

pub enum IfdefCommand {
    Ifdef,
    Ifndef,
}

impl IfdefCommand {
    fn from_str<T: AsRef<str>>(value: T) -> Option<Self> {
        let s: &str = value.as_ref();

        match s {
            "ifdef" => Some(Self::Ifdef),
            "ifndef" => Some(Self::Ifndef),
            _ => None,
        }
    }
}

pub fn parse_ifdef_node<'a>(
    source: &'a str,
    ifdef_node: &Node,
) -> anyhow::Result<(IfdefCommand, &'a str)> {
    assert_eq!(
        ifdef_node.kind(),
        "preproc_ifdef",
        "node is not an ifdef node"
    );

    let macro_cmd_source = ifdef_node.utf8_text(source.as_bytes())?;
    let first_line = macro_cmd_source
        .trim_start_matches("\n")
        .lines()
        .next()
        .unwrap_or_default()
        .trim_start();

    ensure!(
        first_line.starts_with("#"),
        "macro does not start with #: {first_line}"
    );

    let macro_cmd = first_line[1..] // Skip the # at the beginning
        .replace("\t", " ")
        .split_whitespace()
        .next()
        .unwrap()
        .trim()
        .to_lowercase();

    let macro_cmd = IfdefCommand::from_str(&macro_cmd).with_context(|| {
        format!("unknown ifdef command: \"{macro_cmd}\"\n\n{macro_cmd_source}\n\n")
    })?;

    let condition_name = ifdef_node
        .child_by_field_name("name")
        .or_else(|| ifdef_node.named_child(0))
        .unwrap();
    let condition_name = condition_name.utf8_text(source.as_bytes()).unwrap();

    Ok((macro_cmd, condition_name))
}
