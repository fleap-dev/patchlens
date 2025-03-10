use clap::Parser as ClapParser;
use diffy::{Hunk, Line, Patch};
use regex::Regex;
use std::{collections::HashSet, path::PathBuf};
use tracing::{debug, info};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};
use tree_sitter::{Node, Parser, Point};

#[cfg(test)]
mod test;

#[derive(ClapParser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg()]
    pub translation_unit: PathBuf,
    #[arg()]
    pub patch_file: PathBuf,
}

fn main() {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    let args = Cli::parse();

    let source = std::fs::read_to_string(&args.translation_unit).unwrap();
    let patch_src = std::fs::read_to_string(&args.patch_file).unwrap();

    let re = Regex::new(r"\n-- \ncgit .*\n").unwrap();
    let patch_src = re.replace_all(&patch_src, "");

    //if patch_src.lines().filter(|l| l.starts_with("@@")).count() > 1 {
    //    todo!("multiple file patches are not yet implemented!");
    //}
    let patch = Patch::from_str(&patch_src).expect("error reading patch");

    let patched_source = diffy::apply(&source, &patch).expect("failed to apply patch");

    for (idx, line) in patched_source.lines().enumerate() {
        debug!("{idx:04} | {line}");
    }

    let patched_source_lines = patched_source.lines().collect::<Vec<_>>();

    for (idx, hunk) in patch.hunks().iter().enumerate() {
        //println!("Parsing hunk #{idx}...");
        let padding = context_padding_size(hunk);
        let affected = (
            hunk.new_range().start() + padding.0 - 1,
            hunk.new_range().end() - padding.1 - 2,
        );
        let end_line_len = patched_source_lines[affected.1].len();
        debug!(
            "NEW HUNK RANGE: {:?} pad {padding:?} END: {end_line_len}",
            hunk.new_range()
        );
        let configs = presence_condition_of_src_range(
            &patched_source,
            Point::new(affected.0, 0),
            Point::new(affected.1, end_line_len),
        );
        info!(
            "Hunk #{idx} only affect configs that matches: {}",
            configs.into_iter().collect::<Vec<_>>().join(" && ")
        );
    }
    //for (idx, line_src) in lines.enumerate() {
    //    let line = idx + 1;
    //    let point = Point::new(line, 0);
    //    let ifdefs = ifdefs_of_point(&source, root_node, point);
    //    println!("{line} | {line_src} | {ifdefs:?}");
    //}
    //read(root_node, 0);
}

fn context_padding_size(hunk: &Hunk<'_, str>) -> (usize, usize) {
    let mut lines = hunk.lines().to_owned();
    if lines.is_empty() {
        return (0, 0);
    }

    let mut start = 0;
    for line in &lines {
        if !matches!(line, Line::Context(_)) {
            break;
        }
        start += 1;
    }
    lines.reverse();
    let mut end = 0;
    for line in &lines {
        if !matches!(line, Line::Context(_)) {
            break;
        }
        end += 1;
    }

    (start, end)
}

fn print_children_with_field_names(node: tree_sitter::Node, idx: u32, ref_node: Option<Node>) {
    for _ in 1..idx {
        print!("  ");
    }
    println!("{node:?}");
    let mut cursor = node.walk(); // Create a TreeCursor for the node
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            let field_name = cursor.field_name().unwrap_or("None");
            let is_ref = Some(child.id()) == ref_node.map(|n| n.id());
            for _ in 0..idx {
                print!("  ");
            }
            println!(
                "Child node kind: {}, Field name: {} Is_ref: {is_ref}",
                child.kind(),
                field_name
            );

            // Move to the next sibling; if there isn't one, break the loop
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
}

pub fn presence_condition_of_src_range(source: &str, start: Point, end: Point) -> HashSet<String> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_c::LANGUAGE.into())
        .expect("Error loading Rust grammar");

    let tree = parser.parse(source, None).unwrap();
    let root_node = tree.root_node();

    let mut conditions = HashSet::new();
    if let Some(innermost) = root_node.descendant_for_point_range(start, end) {
        debug!("INNERMOST FOR ({start:?}, {end:?}) = {innermost:?}");
        let mut current = Some(innermost);
        let mut last = None;
        let mut idx = 0;
        while let Some(inner) = current {
            print_children_with_field_names(inner, idx, last);

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
            idx += 1;
            last = current;
            current = inner.parent();
        }
    }
    conditions
}
