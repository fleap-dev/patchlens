use crate::Flag;
use anyhow::{bail, ensure, Context};
use regex::Regex;
use std::path::Path;

/// Analyzes the PHP source code to find the build conditions for a target C file.
///
/// # Arguments
///
/// * `php_root` - The absolute path to the root of the php-src repository.
/// * `target` - The absolute path to the target C source file.
///
/// # Returns
///
/// A `Flag` enum representing the conjoined presence conditions (e.g., --enable-foo).
pub fn find_required_configs(php_root: &Path, target: &Path) -> anyhow::Result<Flag> {
    // 1. Sanity checks
    ensure!(php_root.is_dir(), "PHP root is not a directory");
    ensure!(target.is_file(), "Target file does not exist");
    ensure!(
        target.extension().and_then(|s| s.to_str()) == Some("c"),
        "Target must be a .c file"
    );

    // 2. Normalize paths and determine module
    let php_root = php_root.canonicalize()?;
    let target = target.canonicalize()?;
    let relative_path = target.strip_prefix(&php_root).with_context(|| {
        format!(
            "Target file {:?} is not inside the PHP root {:?}",
            target, php_root
        )
    })?;

    let c_filename = target
        .file_name()
        .and_then(|s| s.to_str())
        .context("Could not get C file name")?;

    let mut parts = relative_path.components().map(|c| c.as_os_str());
    let module_type = parts.next().context("Invalid path")?.to_str().unwrap();

    // 3. Route to the correct analysis logic based on module type
    match module_type {
        "ext" => {
            let ext_name = parts
                .next()
                .context("Path is not a valid extension")?
                .to_str()
                .unwrap();
            let mut config_path = php_root.join("ext").join(ext_name).join("config.m4");
            if !config_path.exists() {
                config_path = php_root.join("ext").join(ext_name).join("config0.m4");
            }
            analyze_config_file(&config_path, c_filename)
        }
        "sapi" => {
            let sapi_name = parts
                .next()
                .context("Path is not a valid SAPI")?
                .to_str()
                .unwrap();
            let config_path = php_root.join("sapi").join(sapi_name).join("config.m4");
            analyze_config_file(&config_path, c_filename)
        }
        "Zend" | "main" | "TSRM" => {
            let mut config_path = php_root.join("configure.ac");
            if !config_path.exists() {
                config_path = php_root.join("configure.in");
            }
            let result = analyze_config_file(&config_path, c_filename)?;
            // Core files are almost always unconditional within configure.ac
            if matches!(result, Flag::True) {
                Ok(Flag::True)
            } else {
                Ok(result)
            }
        }
        _ => bail!("Unknown module type for file: {:?}", target),
    }
}

/// The core analysis function that parses a .m4 or .ac file.
fn analyze_config_file(config_path: &Path, c_filename: &str) -> anyhow::Result<Flag> {
    let content = std::fs::read_to_string(config_path)
        .with_context(|| format!("Could not read config file: {:?}", config_path))?;

    // Step 1: locate the C file in a PHP_NEW_EXTENSION / PHP_ADD_SOURCES macro
    let inclusion_regex = Regex::new(&format!(
        r"(?s)(?:PHP_NEW_EXTENSION|PHP_ADD_SOURCES)\s*\(.*?\b{}\b",
        regex::escape(c_filename)
    ))?;
    let inclusion_match = inclusion_regex
        .find(&content)
        .context("Could not find file in a build macro")?;

    // Steps 2–3: scan all enclosing `if test …` blocks (innermost→outermost)
    let var_regex = Regex::new(r"\$([A-Z0-9_]+)")?;
    let mut chosen_var: Option<String> = None;
    for stmt in find_all_enclosing_if_blocks(&content, inclusion_match.start()) {
        if let Some(cap) = var_regex.captures(&stmt) {
            let var_name = cap.get(1).unwrap().as_str().to_string();
            // build the short option name, e.g. PHP_MYEXT → "myext"
            let short = var_name
                .trim_start_matches("PHP_")
                .to_lowercase()
                .replace('_', "-");
            // check if this file actually defines a PHP_ARG_WITH or PHP_ARG_ENABLE for it
            let macro_re = Regex::new(&format!(
                r"(?s)PHP_ARG_(?:WITH|ENABLE)\s*\(.*?\b{}\b",
                regex::escape(&short)
            ))?;
            if macro_re.is_match(&content) {
                chosen_var = Some(var_name);
                break;
            }
        }
    }
    // if we never saw a guarding if-test with a matching macro, it's unconditional
    let variable_name = match chosen_var {
        Some(v) => v,
        None => return Ok(Flag::True),
    };

    // Step 4: find that PHP_ARG_WITH/ENABLE definition
    let flag_short = variable_name
        .trim_start_matches("PHP_")
        .to_lowercase()
        .replace('_', "-");
    let flag_def_regex = Regex::new(&format!(
        r"(?s)PHP_ARG_(?:WITH|ENABLE)\s*\(.*?\b{}\b",
        regex::escape(&flag_short)
    ))?;
    let flag_def_match = flag_def_regex
        .find(&content)
        .context("Could not find flag definition for variable")?;
    let (macro_type, flag, default_val) = parse_php_arg_macro(&content, flag_def_match.start())?;

    // Step 5: compute the main presence condition
    let main_cond = match (macro_type, default_val) {
        ("PHP_ARG_ENABLE", "no") => Flag::Defined(variable_name.clone()),
        ("PHP_ARG_WITH", "yes") => {
            Flag::Not(Box::new(Flag::Equal(variable_name.clone(), "no".into())))
        }
        _ => Flag::Defined(variable_name.clone()),
    };
    let mut conditions = vec![main_cond];

    // Step 6: append any PHP_ADD_EXTENSION_DEP(...) flags
    let dep_regex = Regex::new(r"PHP_ADD_EXTENSION_DEP\([^,]+?,\s*(\w+)\)")?;
    for cap in dep_regex.captures_iter(&content) {
        let dep = cap
            .get(1)
            .unwrap()
            .as_str()
            .to_uppercase()
            .replace('-', "_");
        conditions.push(Flag::Defined(format!("PHP_{}", dep)));
    }

    // combine or return single
    Ok(match conditions.len() {
        0 | 1 => conditions.into_iter().next().unwrap_or(Flag::True),
        _ => Flag::And(conditions),
    })
}

fn find_all_enclosing_if_blocks(content: &str, pos: usize) -> Vec<String> {
    let mut stack = 0;
    let mut blocks = Vec::new();
    for line in content[..pos].lines().rev() {
        let s = line.trim_start();
        if s.starts_with("fi") {
            stack += 1;
        } else if s.starts_with("if test") {
            if stack == 0 {
                blocks.push(s.to_string());
            } else {
                stack -= 1;
            }
        }
    }
    blocks
}

/// Finds the `if test ...` block that encloses a given position.
fn find_enclosing_if_block(content: &str, search_pos: usize) -> Option<String> {
    let mut if_stack = 0;
    // Iterate backwards line-by-line from the match position
    for line in content[..search_pos].lines().rev() {
        let stripped = line.trim_start();
        if stripped.starts_with("fi") {
            if_stack += 1;
        } else if stripped.starts_with("if test") {
            if if_stack == 0 {
                return Some(stripped.to_string()); // Found our match
            }
            if_stack -= 1;
        }
    }
    None
}

/// Parses the body of a `PHP_ARG_WITH` or `PHP_ARG_ENABLE` macro.
fn parse_php_arg_macro<'a>(
    content: &'a str,
    macro_start: usize,
) -> anyhow::Result<(&'a str, String, &'a str)> {
    let body_start = content[macro_start..]
        .find('(')
        .context("Invalid macro syntax")?
        + macro_start
        + 1;

    let mut bracket_level = 1;
    let mut body_end = 0;
    for (i, char) in content[body_start..].char_indices() {
        match char {
            '(' => bracket_level += 1,
            ')' => {
                bracket_level -= 1;
                if bracket_level == 0 {
                    body_end = body_start + i;
                    break;
                }
            }
            _ => {}
        }
    }
    ensure!(body_end > 0, "Could not find end of macro body");

    let body = &content[body_start..body_end];

    // A simple, robust parser for bracketed arguments
    let mut args = Vec::new();
    let mut current_arg_start = 0;
    let mut in_brackets = false;
    for (i, char) in body.char_indices() {
        if char == '[' {
            in_brackets = true;
        } else if char == ']' {
            in_brackets = false;
        } else if char == ',' && !in_brackets {
            args.push(body[current_arg_start..i].trim());
            current_arg_start = i + 1;
        }
    }
    args.push(body[current_arg_start..].trim());

    let macro_type = if content[macro_start..].starts_with("PHP_ARG_ENABLE") {
        "PHP_ARG_ENABLE"
    } else {
        "PHP_ARG_WITH"
    };

    // Extract the --with-foo from the AS_HELP_STRING
    let help_string = args.get(2).context("Missing help string argument")?;
    let flag_regex = Regex::new(r"--([\w-]+)")?;
    let flag = flag_regex
        .captures(help_string)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str())
        .context("Could not parse flag from help string")?;

    // Default value is usually the 4th or 5th argument
    let default_val = args
        .get(3)
        .map(|s| s.trim_matches(|c| c == '[' || c == ']'))
        .filter(|s| *s == "yes" || *s == "no")
        .or_else(|| {
            args.get(4)
                .map(|s| s.trim_matches(|c| c == '[' || c == ']'))
                .filter(|s| *s == "yes" || *s == "no")
        })
        .unwrap_or(if macro_type == "PHP_ARG_ENABLE" {
            "no"
        } else {
            "yes"
        });

    Ok((macro_type, format!("--{}", flag), default_val))
}
