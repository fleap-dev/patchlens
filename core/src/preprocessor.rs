use anyhow::{bail, Context};
use regex::Regex;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::{fs, io};

pub fn expand_include_macros<P: AsRef<Path>>(
    c_source: &str,
    source_path: &Path,
    include_paths: &[P],
) -> anyhow::Result<String> {
    fn expand_include_macros_recursive<P: AsRef<Path>>(
        c_source: &str,
        source_path: &Path,
        include_paths: &[P],
        visited: &mut HashSet<PathBuf>,
    ) -> anyhow::Result<String> {
        let include_regex = Regex::new(r#"^\s*#\s*include\s*(?:<([^>]+)>|"([^"]+)")"#)
            .context("include regex is invalid")?;

        let lines = c_source.split_inclusive("\n");

        let mut output = String::with_capacity(c_source.len());

        for line in lines {
            if let Some(caps) = include_regex.captures(line) {
                let header_name = caps.get(1).or_else(|| caps.get(2)).unwrap().as_str();

                let is_angled = caps.get(1).is_some();

                let mut candidates = Vec::new();
                if !is_angled {
                    candidates.push(source_path.join(header_name));
                }
                for dir in include_paths {
                    candidates.push(dir.as_ref().join(header_name));
                }

                let header_path = candidates
                    .into_iter()
                    .find(|p| p.is_file())
                    .map(|p| p.canonicalize().unwrap());

                if let Some(path) = header_path {
                    // Skip if already expanded
                    if let Some(extension) = path.extension() {
                        if extension == "h" && !visited.insert(path.clone()) {
                            continue;
                        }
                    }

                    // Read and recurse
                    let text = fs::read_to_string(&path)?;
                    let inlined =
                        expand_include_macros_recursive(&text, &path, include_paths, visited)?;

                    output.push_str(&format!("/* Begin include {header_name} */\n"));
                    output.push_str(&inlined);
                    output.push_str(&format!("/* End include {header_name} */\n"));
                } else {
                    let err_msg = format!("/* Warning: include '{header_name}' not found */\n");
                    output.push_str(&err_msg);
                    eprintln!("{}", &err_msg);
                    continue;
                }
            } else {
                // Line is not a #include directive
                output.push_str(line);
            }
        }

        Ok(output)
    }

    let mut visited = HashSet::new();

    expand_include_macros_recursive(c_source, source_path, include_paths, &mut visited)
}

pub fn find_platform_default_include_dirs() -> anyhow::Result<Vec<PathBuf>> {
    let compilers = ["gcc", "clang"];
    let mut last_err = None;

    for &cc in &compilers {
        // Spawn `cc -xc -E -v -` with empty stdin, capture stderr
        let output = Command::new(cc)
            .args(["-xc", "-E", "-v", "-"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output();

        let output = match output {
            Ok(o) => o,
            Err(e) => {
                last_err = Some((cc, e));
                continue;
            }
        };

        // If the process didn't run successfully, skip to next compiler
        if !output.status.success() {
            last_err = Some((
                cc,
                io::Error::other(format!("{} exited with {:?}", cc, output.status.code())),
            ));
            continue;
        }

        // Parse stderr for the include search block
        let stderr = String::from_utf8_lossy(&output.stderr);
        let mut paths = Vec::new();
        let mut in_block = false;

        for line in stderr.lines() {
            let line = line.trim_end();
            if !in_block {
                if line.starts_with("#include <...> search starts here:") {
                    in_block = true;
                }
                continue;
            }

            if line.starts_with("End of search list.") {
                break;
            }

            // Otherwise, this is one of the include dirs
            paths.push(PathBuf::from(line.trim()));
        }

        if !paths.is_empty() {
            return Ok(paths);
        } else {
            // Unexpected: no paths found but compiler ran
            bail!("{} did not report any include paths", cc);
        }
    }

    // If we get here, neither gcc nor clang worked
    if let Some((cc, err)) = last_err {
        bail!("failed to invoke compiler `{}`: {}", cc, err);
    } else {
        bail!("could not find gcc or clang in $PATH");
    }
}
