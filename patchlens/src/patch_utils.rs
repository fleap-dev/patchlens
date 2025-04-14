use std::{
    io::Write, path::Path, process::{Command, Stdio}
};
use anyhow::{ensure, Result};
use tracing::debug;

pub const PATCH_WRAPPER_IFDEF: &str = "__PATCHLENS_INTERNAL_CURRENT_PATCH__";

pub fn apply_patch_in_memory(directory: &Path, patch_content: &str) -> Result<String> {
    let mut child = Command::new("patch")
        .arg("-p1")
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

    ensure!(output.status.success(), "failed to apply patch");

    let stdout = String::from_utf8(output.stdout)?;

    debug!("Output from patch: {}", String::from_utf8_lossy(&output.stderr));

    Ok(stdout)
}

pub fn get_patch_original_file(single_file_patch_src: &str) -> &str {
    let line = single_file_patch_src.lines().find(|line| line.starts_with("+++")).unwrap();
    let (_, raw_filename) = line.split_once(" ").unwrap();
    &raw_filename[2..]
}
