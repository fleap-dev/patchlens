use std::{collections::BTreeSet, env::args};

use diffy::{Hunk, Line, Patch};
use tree_sitter::{Node, Parser, Point};

fn main() {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_c::LANGUAGE.into())
        .expect("Error loading Rust grammar");

    let args = args().collect::<Vec<_>>();

    let source = std::fs::read_to_string(&args[1]).unwrap();
    let patch_src = std::fs::read_to_string(&args[2]).unwrap();

    let patch = Patch::from_str(&patch_src)
        .expect("error reading patch");

    let patched_source = diffy::apply(&source, &patch)
        .expect("failed to apply patch");

    let tree = parser.parse(&patched_source, None).unwrap();
    let root_node = tree.root_node();

    println!("ROOT: {root_node:#?}");

    for (mut idx, line) in patched_source.lines().enumerate() {
        idx += 1;
        println!("{idx} | {line}")
    }
    for (idx, hunk) in patch.hunks().iter().enumerate() {
        println!("Parsing hunk #{idx}...");
        let padding = context_padding_size(hunk);
        let affected = (hunk.new_range().start() + padding.0 - 1, hunk.new_range().end() - padding.1 - 1);
        println!("Lines affected by hunk: {affected:?}");
        let configs = ifdefs_of_range(
            &patched_source,
            root_node,
            Point::new(affected.0, 0),
            Point::new(affected.1, 0),
        );
        println!("Hunk #{idx} only affect configs: {configs:?}");
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

fn ifdefs_of_range(source: &str, node: Node<'_>, start: Point, end: Point) -> BTreeSet<String> {
    let mut ifdefs = BTreeSet::new();
    if let Some(innermost) = node.descendant_for_point_range(start, end) {
        let mut current = Some(innermost);
        while let Some(inner) = current {
            if inner.kind() == "preproc_ifdef" {
                let next = inner.named_child(0).unwrap();
                ifdefs.insert(next.utf8_text(source.as_bytes()).unwrap().into());
                //ifdefs.push(inner.to_sexp());
            }
            current = inner.parent();
        }
    }
    ifdefs
}

fn read<'a>(node: Node<'a>, depth: usize) {
    for _ in 0..depth {
        print!("  ");
    }
    println!("{}", node.kind());
    for idx in 0..node.child_count() {
        if let Some(child) = node.child(idx) {
            read(child, depth + 1);
        }
    }
}
