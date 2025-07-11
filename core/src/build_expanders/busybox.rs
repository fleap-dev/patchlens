// NOTE: This implementation for busybox is ALMOST the same as Linux, as busybox uses an adaptation of the Linux kernel's build system.
// However, busybox uses some sed calls to generate the final versions of the Kbuild files, so we have to do that before we can parse them.

use std::{
    path::Path,
    process::{Command, Stdio},
};

use anyhow::{ensure, Context};

use crate::{build_expanders::linux::KBuildReader, logical_utils::Flag};

struct BusyboxKBuildReader;

impl KBuildReader for BusyboxKBuildReader {
    fn read(path: &std::path::Path) -> anyhow::Result<String> {
        ensure!(path.is_file(), "KBuild passed does not exist");

        let parent_folder = path
            .parent()
            .context("Failed to find the parent folder of the Kbuild file")?;

        let command = Command::new("bash")
            .args([
                "-c",
                &format!(
                    r#"""
                (
                    sed -n '/^INSERT$/ q; p' {};
                    sed -n 's@^//kbuild:@@p' {}/*.c;
                    sed -n '/^INSERT$/ {{ :l; n; p; bl; }}' {}
                )
                """#,
                    path.display(),
                    parent_folder.display(),
                    path.display(),
                ),
            ])
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .output()
            .with_context(|| {
                format!(
                    "failed to generate the final version of the {} file",
                    path.display()
                )
            })?;

        let output = String::from_utf8(command.stdout)
            .context("KBuild generator script generated invalid utf8")?;

        Ok(output)
    }
}

pub fn find_required_configs(linux_root: &Path, target: &Path) -> anyhow::Result<Flag> {
    super::linux::find_required_configs_with_reader::<BusyboxKBuildReader>(
        linux_root,
        target,
        &["obj", "lib", "core", "libs"],
        &[],
    )
}
