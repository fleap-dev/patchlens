use anyhow::Context;
use clap::Parser as ClapParser;
use logical_utils::Flag;
use std::{collections::HashSet, path::PathBuf};
use tracing::{debug, error, info};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};
use tree_sitter::{Node, Parser};

mod logical_utils;
mod mail_utils;
mod patch_utils;
#[cfg(test)]
mod test;

#[derive(ClapParser, Debug)]
#[command(version, about = "Analyze Git patches to detect the variants affected", long_about = None)]
struct Cli {
    /// The folder where the Git repository is located
    #[arg()]
    pub git_directory: PathBuf,
    /// The patch file to be analyzed
    #[arg()]
    pub mail_patch_file: PathBuf,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    let args = Cli::parse();

    let git_repo = args.git_directory;
    let mail_patch_src = std::fs::read_to_string(&args.mail_patch_file)
        .context("failed to read the contents of the patch")?;

    // A patch file from `git format-patch` may patch multiple files. Here we split this patch file
    // into individual patches that only affect one file.
    let single_file_patches = mail_utils::parse_mail_patch(&mail_patch_src);

    // TODO: remove unwraps
    single_file_patches
        .iter()
        .map(|patch| {
            (
                patch_utils::get_patch_original_file(patch),
                patch_utils::apply_patch_in_memory(&git_repo, patch)
                    .context("failed to apply patch"),
            )
        })
        .map(|(filename, patched_source_result)| {
            (
                filename,
                patched_source_result
                    .map(|patched_source| analyze_variants_affected(&patched_source)),
            )
        })
        .for_each(|(filename, flag)| {
            match flag {
                Ok(flag) => {
                    info!("File {filename} needs {flag} variables to be affected!");
                },
                Err(e) => error!("Error computing flag for file {filename}: {e:?}"),
            }
        });

    //let result = Flag::Or(result);
    //
    //info!("All affected variants must match the flag: {result}");
    //info!(
    //    "All affected variants must match the flag: {}",
    //    result.simplify()
    //);

    Ok(())
}

pub fn find_patchlens_ifdef_nodes<'a>(source: &'a str, root: Node<'a>) -> Vec<Node<'a>> {
    fn recursive<'a>(source: &str, node: Node<'a>, output: &mut Vec<Node<'a>>) {
        if node.kind() == "preproc_ifdef" {
            let (_ifdef_cmd, flag) = parse_ifdef_node(source, &node);
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

pub fn analyze_variants_affected(source: &str) -> Flag {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_c::LANGUAGE.into())
        .expect("Error loading Rust grammar");

    let tree = parser.parse(source, None).unwrap();
    let root_node = tree.root_node();

    let patchlens_ifdef_nodes = find_patchlens_ifdef_nodes(source, root_node);

    debug!("NODES: {patchlens_ifdef_nodes:?}");

    let hunk_configs = patchlens_ifdef_nodes
        .into_iter()
        .map(|node| node.parent().unwrap()) // analyze the parent nodes of the new inserted nodes
        .map(|n| analyze_configs_for_ast_node(source, n))
        .collect::<Vec<_>>();

    Flag::Or(hunk_configs)
}

fn analyze_configs_for_ast_node(source: &str, node: Node) -> Flag {
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
                        Flag::Not(Box::new(Flag::Literal(raw_flag)))
                    }
                    ("#ifndef", Some("preproc_else")) => Flag::Literal(raw_flag),
                    ("#ifdef", _) => Flag::Literal(raw_flag),
                    ("#ifndef", _) => Flag::Not(Box::new(Flag::Literal(raw_flag))),
                    _ => unreachable!(),
                };

                conditions.push(flag);
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

    if conditions.is_empty() {
        Flag::Literal("true".into())
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
