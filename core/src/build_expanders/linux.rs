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

#[derive(Clone, Debug)]
struct FlatAssign {
    name: String,
    value: Vec<String>,
    condition: Flag,
}

pub trait KBuildReader {
    fn read(path: &Path) -> anyhow::Result<String>;
}

struct NaiveKBuildReader;

impl KBuildReader for NaiveKBuildReader {
    fn read(path: &Path) -> anyhow::Result<String> {
        std::fs::read_to_string(path).context("failed to read Kbuild file")
    }
}

pub fn find_required_configs<R: KBuildReader>(
    linux_root: &Path,
    target: &Path,
) -> anyhow::Result<Flag> {
    find_required_configs_with_reader::<NaiveKBuildReader>(linux_root, target, &["obj", "lib"])
}

pub fn find_required_configs_with_reader<R: KBuildReader>(
    linux_root: &Path,
    target: &Path,
    included_objs: &[&str],
) -> anyhow::Result<Flag> {
    // 1) Sanity checks
    ensure!(linux_root.is_dir(), "linux root is not a directory");
    ensure!(target.is_file(), "target file does not exist");

    if target.extension().and_then(OsStr::to_str) == Some("h") {
        bail!("flag expansion for header files is still not implemented");
    }

    // 2) Normalize
    let linux_root = linux_root.canonicalize()?;
    let arch_root = linux_root.join("arch");
    let mut current = target.canonicalize()?;
    let mut conditions = Vec::new();

    // 3) Climb up until we reach linux_root
    while current != linux_root {
        // Derive make_target
        let base = current
            .file_name()
            .and_then(OsStr::to_str)
            .context("target has no filename")?;
        let mut make_target = if current.is_dir() {
            format!("{base}/")
        } else {
            format!("{}.o", base.strip_suffix(".c").unwrap())
        };

        // Move up one directory
        current = current
            .parent()
            .context("no parent directory")?
            .to_path_buf();

        eprintln!("Checking {current:?} → {make_target}");

        // Skip /lib and /arch at the very top
        if current == linux_root {
            if make_target == "lib/" || make_target == "arch/" {
                continue;
            }
        // Emit ARCH=… when inside arch/<ARCH>
        } else if current == arch_root {
            // strip trailing '/'
            let arch_name = make_target.trim_end_matches('/');
            conditions.push(Flag::Equal("ARCH".into(), arch_name.into()));
            continue;
        }

        // Parse this directory’s Kbuild/Makefile
        let makefile = find_makefile(&current).context("no Makefile/Kbuild here")?;
        let text = R::read(&makefile).context("Failed to read KBuild file")?;
        let ast = flatten_makefile(&text);

        // — Step A: chase composite-lists (unchanged) —

        let mut hops_remaining = 100; // Avoid cyclic references

        while hops_remaining > 0 {
            let mut hopped = false;
            for assign in &ast {
                // static “-objs” lists
                if let Some(parent) = assign.name.strip_suffix("-objs") {
                    if assign.value.iter().any(|v| v == &make_target) {
                        conditions.push(assign.condition.clone());
                        make_target = format!("{parent}.o");
                        hopped = true;
                        break; // breaks out of `for node in…`
                    }
                }
                // dynamic composite lists
                else if included_objs.iter().find(|s| *s == &assign.name).is_none()
                    && assign.value.iter().any(|v| v == &make_target)
                {
                    conditions.push(assign.condition.clone());
                    make_target = format!("{}.o", &assign.name);
                    hopped = true;
                    break;
                }
            }
            if !hopped {
                break;
            }
            hops_remaining -= 1;
        }

        // — Step B: collect *all* `obj += make_target` guards in this dir —
        let obj_guards: Vec<Flag> = ast
            .iter()
            .filter_map(|assign| {
                if included_objs.iter().find(|s| *s == &assign.name).is_some()
                    && assign.value.iter().any(|v| v == &make_target)
                {
                    return Some(assign.condition.clone());
                }
                None
            })
            .collect();

        ensure!(
            !obj_guards.is_empty(),
            "could not find `obj += {}` in {:?}",
            make_target,
            makefile
        );

        // If there’s more than one guard, OR them; otherwise push the single one
        if obj_guards.len() == 1 {
            conditions.push(obj_guards.into_iter().next().unwrap());
        } else {
            conditions.push(Flag::Or(obj_guards));
        }
    }

    // 4) Conjoin (or True)
    Ok(if conditions.is_empty() {
        Flag::True
    } else {
        Flag::And(conditions)
    })
}

fn collect_assignments(node: &BNode, ctx: &Flag, out: &mut Vec<FlatAssign>) {
    // Conjoin the current node’s condition with the incoming context.
    let effective = match ctx {
        Flag::True => node.condition.clone(),
        _ => Flag::And(vec![ctx.clone(), node.condition.clone()]),
    };

    // If this node is an assignment, emit it
    if let BNodeDetails::Assignment { name, value } = &node.details {
        out.push(FlatAssign {
            name: name.clone(),
            value: value.clone(),
            condition: effective.clone(),
        });
    }

    // Recurse into all children
    for child in &node.children {
        collect_assignments(child, &effective, out);
    }
}

/// Parse & flatten a Kbuild file into a vector of FlatAssigns
fn flatten_makefile(content: &str) -> Vec<FlatAssign> {
    // Parse into the original BNode AST
    let root_pair = MakeParser::parse(Rule::file, content)
        .expect("Failed to parse Kbuild")
        .next()
        .unwrap();

    let mut root = BNode {
        details: BNodeDetails::Makefile,
        condition: Flag::True,
        children: Vec::new(),
    };
    // Build children via your existing `parse_makefile_lines` logic:
    root.children = parse_makefile_lines(root_pair.into_inner());

    // Now collect assignments
    let mut out = Vec::new();
    collect_assignments(&root, &Flag::True, &mut out);
    out
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
    let mut inner = line.into_inner();

    let command = inner.next().unwrap().as_str();

    let expression = inner.next().unwrap().as_str().trim();

    let body = inner
        .next()
        .map(|b| b.into_inner())
        .map(|b| parse_makefile_lines(b));

    let alternative_body = inner
        .next()
        .map(|b| b.into_inner())
        .map(|b| parse_makefile_lines(b));

    fn parse_eq_expression(expr: &str) -> Option<Flag> {
        let eq_regex = Regex::new(
            r#"^\(\s*((?:"(?:[^"\\]|\\.)*"|[^,])*)\s*,\s*((?:"(?:[^"\\]|\\.)*"|.)*?)\s*\)$"#,
        )
        .unwrap();
        let eq_regex_alt =
            Regex::new(r#"^\s*"((?:[^"\\]|\\.)*)"\s+"((?:[^"\\]|\\.)*)"\s*$"#).unwrap();

        if let Some(cap) = eq_regex.captures(expr) {
            Some(Flag::Equal(cap[1].to_string(), cap[2].to_string()))
        } else if let Some(cap) = eq_regex_alt.captures(expr) {
            Some(Flag::Equal(cap[1].to_string(), cap[2].to_string()))
        } else {
            None
        }
    }

    let condition = match command {
        "ifdef" => {
            let condition = expression.trim().to_owned();
            Flag::Defined(condition)
        }
        "ifndef" => {
            let condition = expression.trim().to_owned();
            Flag::Defined(condition).not()
        }
        "ifeq" => parse_eq_expression(expression)
            .expect(&format!("Failed to parse ifeq expression: {expression}")),
        "ifneq" => parse_eq_expression(expression)
            .map(|e| e.not())
            .expect(&format!("Failed to parse ifeq expression: {expression}")),
        _ => unimplemented!("unknown if macro: {command}"),
    };

    let main_node = body.map(|b| BNode {
        details: BNodeDetails::VariabilityBlock {},
        children: b,
        condition: condition.clone(),
    });

    let alternative_node = alternative_body.map(|b| BNode {
        details: BNodeDetails::VariabilityBlock {},
        children: b,
        condition: condition.not(),
    });

    match (main_node, alternative_node) {
        (Some(m), None) => m,
        (None, Some(a)) => a,
        (Some(m), Some(a)) => BNode {
            details: BNodeDetails::VariabilityBlock {},
            children: vec![m, a],
            condition: Flag::True,
        },
        _ => unreachable!(),
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
    let mut list_val = inner.next().unwrap();

    while matches!(list_val.as_rule(), Rule::continuation) {
        list_val = inner.next().unwrap();
    }

    let list_val = list_val
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
