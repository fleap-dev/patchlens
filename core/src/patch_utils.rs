use anyhow::{ensure, Result};
use std::{
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

pub const PATCH_WRAPPER_IFDEF: &str = "__PATCHLENS_INTERNAL_CURRENT_PATCH__";

pub fn apply_patch_in_memory(
    directory: &Path,
    patch_content: &str,
    strip_dir_prefix: Option<u8>,
) -> Result<String> {
    let mut child = Command::new("patch");

    child.arg(format!("-p{}", strip_dir_prefix.unwrap_or(0)));

    let mut child = child
        .arg("-D")
        .arg(PATCH_WRAPPER_IFDEF)
        .arg("-o")
        .arg("-")
        .current_dir(directory)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    if let Some(ref mut stdin) = child.stdin {
        stdin.write_all(patch_content.as_bytes())?;
    }

    let output = child.wait_with_output()?;

    ensure!(
        output.status.success(),
        "failed to apply patch: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout)?;

    Ok(stdout)
}

pub fn get_patch_original_file(single_file_patch_src: &str, strip_dir_prefix: Option<u8>) -> &str {
    let line = single_file_patch_src
        .lines()
        .find(|line| line.starts_with("+++"))
        .unwrap();

    let mut filename = line.split(&['\t', ' ']).nth(1).unwrap();

    // Strip n prefix folders from the filename
    let strip = strip_dir_prefix.unwrap_or(0);

    for _ in 0..strip {
        if let Some(pos) = filename.find("/") {
            filename = &filename[pos..];
        }
    }

    filename
}
