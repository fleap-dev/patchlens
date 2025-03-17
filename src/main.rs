use anyhow::Context;
use clap::Parser as ClapParser;
use logical_utils::Flag;
use regex::Regex;
use std::{collections::HashSet, path::PathBuf};
use tracing::{debug, info};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};
use tree_sitter::{Node, Parser};

mod logical_utils;
mod patch_utils;
#[cfg(test)]
mod test;

#[derive(ClapParser, Debug)]
#[command(version, about = "Analyze Git patches to detect the variants affected", long_about = None)]
struct Cli {
    /// The folder where the Git repository is located
    #[arg(short, long)]
    pub git_directory: PathBuf,
    /// The patch file to be analyzed
    #[arg(short, long)]
    pub patch_file: PathBuf,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    let args = Cli::parse();

    let git_repo = args.git_directory;
    let patch_src = std::fs::read_to_string(&args.patch_file)
        .context("failed to read the contents of the patch")?;

    let re = Regex::new(r"\n-- \n(cgit )?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?\n").unwrap();
    let patch_src = re.replace_all(&patch_src, "");

    let patched_source = patch_utils::apply_patch_in_memory(&git_repo, &patch_src)
        .context("failed to apply patch")?;

    for (idx, line) in patched_source.lines().enumerate() {
        debug!("{idx:04} | {line}");
    }

    let flag = analyze_variants_affected(&patched_source);

    info!("All affected variants must match the flag: {flag:?}");

    Ok(())
}

pub fn find_patchlens_ifdef_nodes<'a>(source: &'a str, root: Node<'a>) -> Vec<Node<'a>> {
    fn recursive<'a>(source: &str, node: Node<'a>, output: &mut Vec<Node<'a>>) {
        if node.kind() == "preproc_ifdef" {
            let (ifdef_cmd, flag) = parse_ifdef_node(source, &node);
            match ifdef_cmd {
                IfdefCommand::Ifdef if flag == patch_utils::PATCH_WRAPPER_IFDEF => {
                    output.push(node);
                    return;
                },
                _ => {},
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

pub fn analyze_variants_affected(source: &str) -> Flag {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_c::LANGUAGE.into())
        .expect("Error loading Rust grammar");

    let tree = parser.parse(source, None).unwrap();
    let root_node = tree.root_node();

    let patchlens_ifdef_nodes = find_patchlens_ifdef_nodes(source, root_node);

    let hunk_configs = patchlens_ifdef_nodes
        .into_iter()
        .map(|n| analyze_configs_for_ast_node(source, n))
        .collect::<Vec<_>>();

    Flag::Or(hunk_configs)
}

fn analyze_configs_for_ast_node(source: &str, node: Node) -> Flag {
    let mut conditions = HashSet::new();
    let mut current = Some(node);
    let mut last: Option<Node> = None;
    while let Some(inner) = current {
        // TODO: implement for C++
        match inner.kind() {
            "preproc_ifdef" => {
                let condition_name = inner.named_child(0).unwrap();
                let last_kind = last.map(|l| l.kind());
                println!("{:?}", inner.utf8_text(source.as_bytes()));

                let macro_cmd = inner
                    .utf8_text(source.as_bytes())
                    .unwrap()
                    .split_once(" ")
                    .unwrap()
                    .0
                    .to_lowercase();

                let prefix = match (macro_cmd.as_str(), last_kind) {
                    ("#ifdef", Some("preproc_else")) => "!",
                    ("#ifndef", Some("preproc_else")) => "",
                    ("#ifdef", _) => "",
                    ("#ifndef", _) => "!",
                    _ => "",
                };

                conditions.insert(format!(
                    "({prefix}{})",
                    condition_name.utf8_text(source.as_bytes()).unwrap()
                ));
            }
            "preproc_else" => {
                // Ignored because this will be checked on the parent preproc_ifdef...
            }
            "preproc_if" => {
                todo!()
            }
            _ => {}
        }
        last = current;
        current = inner.parent();
    }
    let conditions = conditions
        .into_iter()
        .map(Flag::Literal)
        .collect::<Vec<_>>();

    Flag::And(conditions)
}

enum IfdefCommand {
    Ifdef,
    Ifndef,
}

impl IfdefCommand {
    fn from_str<T: AsRef<str>>(value: T) -> Option<Self> {
        let s: &str = value.as_ref();

        match s {
            "#ifdef" => Some(Self::Ifdef),
            "#ifndef" => Some(Self::Ifndef),
            _ => None,
        }
    }
}

fn parse_ifdef_node<'a>(source: &'a str, ifdef_node: &Node) -> (IfdefCommand, &'a str) {
    assert_eq!(
        ifdef_node.kind(),
        "preproc_ifdef",
        "node is not an ifdef node"
    );

    let macro_cmd = ifdef_node
        .utf8_text(source.as_bytes())
        .unwrap()
        .split_once(" ")
        .unwrap()
        .0
        .to_lowercase();
    let macro_cmd = IfdefCommand::from_str(macro_cmd).unwrap();

    let condition_name = ifdef_node.named_child(0).unwrap();
    let condition_name = condition_name.utf8_text(source.as_bytes()).unwrap();

    (macro_cmd, condition_name)
}
