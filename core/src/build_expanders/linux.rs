use crate::logical_utils::Flag;
use anyhow::{bail, ensure, Context};
use pest::{iterators::Pair, Parser};
use pest_derive::Parser;
use regex::Regex;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[grammar = "build_expanders/grammars/kbuild.pest"]
pub struct MakeParser;

#[derive(Clone, Debug)]
enum BNodeDetails {
    Makefile,
    Assignment { name: String, value: Vec<String> },
    VariabilityBlock {},
}

#[derive(Clone, Debug)]
struct BNode {
    details: BNodeDetails,
    children: Vec<BNode>,
    condition: Flag,
}

pub fn find_required_configs(linux_root: &Path, target: &Path) -> anyhow::Result<Flag> {
    // 1) Sanity checks
    ensure!(linux_root.is_dir(), "linux root is not a directory");
    ensure!(target.is_file(), "target file does not exist");

    let ext = target.extension().map(|s| s.to_str()).flatten();

    ensure!(
        ext != Some("h"),
        "flag expansion for header files is still not implemented"
    );

    // 2) Normalize paths
    let linux_root = linux_root.canonicalize()?;
    let mut current = target.canonicalize()?;
    let mut conditions = Vec::new();

    // 3) Climb until we hit the repo root
    loop {
        // Derive the “make” object name for this file/dir
        let base = current
            .file_name()
            .context("target has no filename")?
            .to_str()
            .context("filename not valid UTF-8")?;
        let mut make_target = if current.is_dir() {
            format!("{base}/")
        } else if current.extension().and_then(OsStr::to_str) == Some("c") {
            format!("{}.o", base.strip_suffix(".c").unwrap())
        } else {
            bail!("unknown target format: {:?}", current);
        };

        // Move up
        if current != linux_root {
            current = current
                .parent()
                .context("no parent directory")?
                .to_path_buf();
        } else {
            break;
        }

        eprintln!("Checking {current:?} -> {make_target}");

        // Parse this directory’s Makefile/Kbuild
        let makefile = find_makefile(&current).context("no Makefile/Kbuild here")?;
        let text = std::fs::read_to_string(&makefile)?;
        let ast = parse_makefile(&text);

        // (A) Chase composite lists *repeatedly*
        loop {
            let mut hopped = false;
            for node in &ast.children {
                if let BNodeDetails::Assignment { name, value, .. } = &node.details {
                    // Case 1: name ends with "-objs"
                    if let Some(base_name) = name.strip_suffix("-objs") {
                        if value.iter().any(|v| v == &make_target) {
                            // e.g. `nfc-objs := ... klee.o ...`
                            conditions.push(node.condition.clone());
                            make_target = format!("{base_name}.o");
                            hopped = true;
                            break;
                        }
                    }
                    // Case 2: dynamic composite from regex parse (name != "obj" && not "-objs")
                    else if name != "obj" && value.iter().any(|v| v == &make_target) {
                        // e.g. `klee-$(CONFIG_AIBT) := aibt.o` parsed as name="klee"
                        conditions.push(node.condition.clone());
                        make_target = format!("{name}.o");
                        hopped = true;
                        break;
                    }
                }
            }
            if !hopped {
                break;
            }
        }

        // (B) Now pick up the `obj += make_target` guard
        let mut found_obj = false;
        for node in &ast.children {
            if let BNodeDetails::Assignment { name, value, .. } = &node.details {
                if name == "obj" && value.iter().any(|v| v == &make_target) {
                    conditions.push(node.condition.clone());
                    found_obj = true;
                    break;
                }
            }
        }

        ensure!(
            found_obj,
            "could not find either composite-list or `obj += {}` in {:?}",
            make_target,
            makefile
        );
    }

    // 4) Conjoin (or return True)
    if conditions.is_empty() {
        Ok(Flag::True)
    } else {
        Ok(Flag::And(conditions))
    }
}

fn parse_makefile(content: &str) -> BNode {
    let lines = MakeParser::parse(Rule::file, content);

    if let Err(e) = lines {
        eprintln!("{e}");
        panic!("Failed to parse makefile!");
    }

    let lines = lines.unwrap().next().unwrap().into_inner();

    let children = parse_makefile_lines(lines.into_iter());

    BNode {
        details: BNodeDetails::Makefile,
        children: children,
        condition: Flag::True,
    }
}

fn parse_makefile_lines<'a>(lines: impl Iterator<Item = Pair<'a, Rule>>) -> Vec<BNode> {
    lines
        .filter_map(|line| match line.as_rule() {
            Rule::list_assignment | Rule::assignment => {
                let node = parse_assignment(line);
                Some(node)
            }
            Rule::variability_block => {
                let node = parse_variability_block(line);
                Some(node)
            }
            _ => None,
        })
        .collect()
}

fn parse_variability_block(line: Pair<'_, Rule>) -> BNode {
    // TODO: nested elif blocks are still not implemented
    let mut inner = line.into_inner();

    let mut main_block = inner.next().unwrap().into_inner();
    let mut alternative_block = inner.next().unwrap().into_inner();

    let statement = main_block.next().unwrap();
    let statement_rule = statement.as_rule();
    let mut statement_inner = statement.into_inner();

    let condition = match statement_rule {
        Rule::ifeq_stmt => {
            let first_param = statement_inner.next().unwrap().as_str().to_string();
            let second_param = statement_inner
                .next()
                .map(|s| s.as_str().to_string())
                .unwrap_or_default();
            Flag::Equal(first_param, second_param.as_str().to_string())
        }
        Rule::ifneq_stmt => {
            let first_param = statement_inner.next().unwrap().as_str().to_string();
            let second_param = statement_inner
                .next()
                .map(|s| s.as_str().to_string())
                .unwrap_or_default();
            Flag::Not(Box::new(Flag::Equal(
                first_param.as_str().to_string(),
                second_param.as_str().to_string(),
            )))
        }
        Rule::ifdef_stmt => {
            let var_name = statement_inner.next().unwrap().as_str().to_owned();
            Flag::Defined(var_name)
        }
        Rule::ifndef_stmt => {
            let var_name = statement_inner.next().unwrap().as_str().to_owned();
            Flag::Not(Box::new(Flag::Defined(var_name)))
        }
        _ => unreachable!(),
    };

    let main_lines = parse_makefile_lines(main_block);

    let alternative_lines = if alternative_block.len() > 0 {
        let _else_stmt = alternative_block.next().unwrap();

        parse_makefile_lines(alternative_block)
    } else {
        Vec::new()
    };

    let main_node = BNode {
        details: BNodeDetails::VariabilityBlock {},
        children: main_lines,
        condition: condition.clone(),
    };

    if alternative_lines.is_empty() {
        main_node
    } else {
        let alternative_node = BNode {
            details: BNodeDetails::VariabilityBlock {},
            children: alternative_lines,
            condition: Flag::Not(Box::new(condition)),
        };

        // Wrapper
        BNode {
            details: BNodeDetails::VariabilityBlock {},
            children: vec![main_node, alternative_node],
            condition: Flag::True,
        }
    }
}

fn parse_assignment(line: Pair<'_, Rule>) -> BNode {
    let mut inner = line.into_inner();

    let condition: Flag;
    let raw_list_name = inner.next().unwrap();
    let mut var_name: String;

    let cond_assignment_regex =
                Regex::new("^(?<var_name>[a-zA-Z0-9_]+)-(?<cond_var_name>(\\$\\([a-zA-Z0-9_]+\\))|(\\$\\{[a-zA-Z0-9_]+\\}))$")
                    .unwrap();

    match cond_assignment_regex.captures(raw_list_name.as_str()) {
        Some(caps) => {
            let raw_variable = caps.name("cond_var_name").unwrap().as_str();
            let cond_var_name = &raw_variable[2..raw_variable.len() - 1]; // Remove "$(" and ")"
            var_name = caps.name("var_name").unwrap().as_str().to_owned();
            condition = Flag::Defined(cond_var_name.to_owned());
        }
        None => {
            var_name = raw_list_name.as_str().to_owned();

            if var_name.ends_with("-y") || var_name.ends_with("-m") {
                var_name.pop();
                var_name.pop();
            }
            condition = Flag::True;
        }
    };

    let _assignment_op = inner.next().unwrap().as_str();
    let list_val = inner
        .next()
        .unwrap()
        .as_str()
        .split_whitespace()
        .filter(|dep| *dep != "\\")
        .map(str::to_owned)
        .collect::<Vec<_>>();

    BNode {
        details: BNodeDetails::Assignment {
            name: var_name,
            value: list_val,
        },
        children: Vec::new(),
        condition,
    }
}

pub fn find_makefile(folder: &Path) -> Option<PathBuf> {
    let names = ["Kbuild", "Kbuild.src", "Makefile"];

    for name in &names {
        let candidate = folder.join(name);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

// /// Returns:
// /// - `None` if the target `.c`→`.o` never appears
// /// - `Some(groups)` otherwise, where each `groups[i]` is the sorted list
// ///    of `CONFIG_…` symbols all of which must be enabled (AND) for that
// ///    particular assignment.  Different `i` are OR’d together.
// fn find_required_configs(makefile_content: &str, target_c: &str) -> Option<Flag> {
//     let file = MakeParser::parse(Rule::file, makefile_content)
//         .expect("Failed to parse")
//         .next()
//         .unwrap();

//     // collect all assignments
//     let mut assigns = Vec::new();
//     for pair in file.into_inner() {
//         collect_assignments(pair, &mut Vec::new(), &mut assigns);
//     }

//     // normalize
//     let target_o = target_c
//         .strip_suffix(".c")
//         .map(|b| format!("{}.o", b))
//         .unwrap_or_else(|| format!("{}.o", target_c));

//     // gather each assignment’s guard‐set if it references our target
//     let mut raw_groups = Vec::new();
//     for a in assigns {
//         if a.rhs_literals.iter().any(|lit| lit == &target_o) {
//             // take only positive guards (strip off any "!CONFIG_X")
//             let group: BTreeSet<String> = a
//                 .guarded_by
//                 .into_iter()
//                 .filter(|g| !g.starts_with('!'))
//                 .collect();
//             // produce a sorted Vec
//             raw_groups.push(group.into_iter().collect::<Vec<_>>());
//         }
//     }

//     if raw_groups.is_empty() {
//         return None;
//     }

//     // dedupe identical guard‐sets
//     raw_groups.sort();
//     raw_groups.dedup();

//     // If there is exactly one group, but it’s empty, that means unguarded
//     if raw_groups.len() == 1 && raw_groups[0].is_empty() {
//         return Some(Flag::True);
//     } else {
//         let alts: Vec<Flag> = raw_groups
//             .into_iter()
//             .map(|grp| {
//                 if grp.len() == 1 {
//                     Flag::Defined(grp[0].clone())
//                 } else {
//                     Flag::And(grp.into_iter().map(|s| Flag::Defined(s)).collect())
//                 }
//             })
//             .collect();
//         Some(Flag::Or(alts))
//     }
// }

// fn collect_assignments(pair: Pair<Rule>, context: &mut Vec<String>, assigns: &mut Vec<Assignment>) {
//     match pair.as_rule() {
//         Rule::assignment => {
//             let mut inner = pair.into_inner();
//             let lhs = inner.next().unwrap();
//             let _op = inner.next().unwrap();
//             let rhs = inner.next().unwrap();

//             // LHS guards from var-expansions $(CONFIG_X)
//             let mut guarded_by: Vec<String> = lhs
//                 .clone()
//                 .into_inner()
//                 .filter_map(|p| {
//                     if p.as_rule() == Rule::var_expansion {
//                         let ident = p.into_inner().next().unwrap().as_str();
//                         Some(ident.to_string())
//                     } else {
//                         None
//                     }
//                 })
//                 .collect();

//             // plus any enclosing ifdef/ifndef context
//             for g in context.iter() {
//                 guarded_by.push(g.clone());
//             }

//             // RHS literal tokens
//             let rhs_literals = rhs
//                 .into_inner()
//                 .filter_map(|p| match p.as_rule() {
//                     Rule::var_name => {
//                         let s = p.as_str().to_string();
//                         if s.starts_with("$(") || s.starts_with("${") {
//                             None
//                         } else {
//                             Some(s)
//                         }
//                     }
//                     _ => None,
//                 })
//                 .collect();

//             assigns.push(Assignment {
//                 guarded_by,
//                 rhs_literals,
//             });
//         }

//         Rule::variability_block => {
//             let mut inner = pair.into_inner();
//             let cmd = inner.next().unwrap(); // "ifdef" or "ifndef"
//             let expr = inner.next().unwrap(); // e.g. "CONFIG_FOO"

//             let mut new_ctx = context.clone();
//             let var = expr.as_str().to_string();
//             match cmd.as_str() {
//                 "ifdef" => new_ctx.push(var),
//                 "ifndef" => new_ctx.push(format!("!{}", var)),
//                 _ => {}
//             }

//             for child in inner {
//                 collect_assignments(child, &mut new_ctx, assigns);
//             }
//         }

//         _ => {}
//     }
// }
