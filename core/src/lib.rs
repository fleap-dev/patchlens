use anyhow::{ensure, Context};
use logical_utils::Flag;
use tree_sitter::{Node, Parser};

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

pub fn analyze_variants_affected(source: &str, filename: &str) -> Flag {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_c::LANGUAGE.into())
        .expect("Error loading Rust grammar");

    let tree = parser.parse(source, None).unwrap();
    let root_node = tree.root_node();

    // TODO: how we should handle this?
    // assert!(!root_node.has_error(), "TreeSitter failed to parse the full source code!");

    let patchlens_ifdef_nodes = find_patchlens_ifdef_nodes(source, root_node);

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
                let condition_name = inner.named_child(0).unwrap();
                let last_kind = last.map(|l| l.kind());

                let macro_cmd = inner
                    .utf8_text(source.as_bytes())
                    .unwrap()
                    .split_once(" ")
                    .unwrap()
                    .0
                    .to_lowercase();

                let raw_flag = condition_name
                    .utf8_text(source.as_bytes())
                    .unwrap()
                    .to_owned();

                let flag: Flag = match (macro_cmd.as_str(), last_kind) {
                    ("#ifdef", Some("preproc_else")) => {
                        Flag::Not(Box::new(Flag::Defined(raw_flag)))
                    }
                    ("#ifndef", Some("preproc_else")) => Flag::Defined(raw_flag),
                    ("#ifdef", _) => Flag::Defined(raw_flag),
                    ("#ifndef", _) => Flag::Not(Box::new(Flag::Defined(raw_flag))),
                    _ => unreachable!(),
                };

                conditions.push(flag);
            }
            "preproc_else" => {
                // Ignored because this will be checked on the parent preproc_ifdef...
            }
            "preproc_if" => {
                todo!("preproc_if blocks are not yet implemented!")
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

enum IfdefCommand {
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

    let macro_cmd_source = ifdef_node.utf8_text(source.as_bytes())?.trim();

    ensure!(
        macro_cmd_source.starts_with("#"),
        "macro does not start with #"
    );

    let macro_cmd = macro_cmd_source[1..] // Skip the # at the beginning
        .replace("\t", " ")
        .split(" ")
        .find(|s| !s.is_empty())
        .unwrap()
        .trim()
        .to_lowercase();

    let macro_cmd = IfdefCommand::from_str(&macro_cmd).with_context(|| {
        format!("unknown ifdef command: \"{macro_cmd}\"\n\n{macro_cmd_source}\n\n")
    })?;

    let condition_name = ifdef_node.named_child(0).unwrap();
    let condition_name = condition_name.utf8_text(source.as_bytes()).unwrap();

    Ok((macro_cmd, condition_name))
}
