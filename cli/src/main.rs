use anyhow::{Context, bail};
use clap::{Parser as ClapParser, Subcommand};
use patchlens::logical_utils::Flag;
use patchlens::{
    analyze_variants_affected, build_expanders, mail_utils, patch_utils, preprocessor,
};
use std::path::{Path, PathBuf};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

#[derive(ClapParser, Debug)]
#[command(version, about = "Analyze Git patches to detect the variants affected", long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    #[arg(short = 'e', value_enum)]
    build_system_expander: Option<BuildSystemExpander>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// does testing things
    AnalyzeGit {
        /// The folder where the Git repository is located
        #[arg()]
        git_directory: PathBuf,
        /// The patch file to be analyzed
        #[arg()]
        mail_patch_file: PathBuf,
    },
    AnalyzeSingle {
        #[arg()]
        root_dir: PathBuf,
        #[arg()]
        diff_file: PathBuf,
    },
}

#[derive(clap::Parser, Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
#[clap(rename_all = "kebab_case")]
enum BuildSystemExpander {
    Linux,
    PHP,
    FFMPEG,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    let args = Cli::parse();

    let include_dirs = preprocessor::find_platform_default_include_dirs()
        .context("failed to find the default include dirs on this platform")?;

    match args.command {
        Commands::AnalyzeGit {
            git_directory: git_repo,
            mail_patch_file,
        } => {
            let mail_patch_src = std::fs::read_to_string(&mail_patch_file)
                .context("failed to read the contents of the patch")?;

            // A patch file from `git format-patch` may patch multiple files. Here we split this patch file
            // into individual patches that only affect one file.
            let single_file_patches = mail_utils::parse_mail_patch(&mail_patch_src)
                .into_iter()
                .collect::<Vec<_>>();

            // Verify if the patch file only modify .c files
            // If the patch modify something else, we cannot be certain about its effects
            single_file_patches
                .iter()
                .map(|patch| patch_utils::get_patch_original_file(patch, Some(1)))
                .map(|filename| {
                    match Path::new(filename)
                        .extension()
                        .and_then(std::ffi::OsStr::to_str)
                    {
                        Some("c") => Ok(filename),
                        // Ignored extensions
                        Some("phpt") => Ok(filename),
                        Some(_) | None => bail!(
                            "this patch modifies a file that is not a c file: {}",
                            filename
                        ),
                    }
                })
                .collect::<Result<Vec<_>, _>>()?;

            // TODO: remove unwraps
            let result = single_file_patches
                .iter()
                .filter(|patch| {
                    let file = Path::new(patch_utils::get_patch_original_file(patch, Some(1)));
                    let ext = file.extension().and_then(|ext| ext.to_str());
                    ext == Some("c") || ext == Some("h")
                })
                .map(|patch| {
                    (
                        patch_utils::get_patch_original_file(patch, Some(1)),
                        patch_utils::apply_patch_in_memory(&git_repo, patch, Some(1))
                            .context("failed to apply patch"),
                    )
                })
                .map(|(filename, patched_source_result)| {
                    (
                        filename,
                        patched_source_result.and_then(|patched_source| {
                            preprocessor::expand_include_macros(
                                &patched_source,
                                Path::new(filename),
                                &include_dirs,
                            )
                        }),
                    )
                })
                .map(|(filename, patched_source_result)| {
                    (
                        filename,
                        patched_source_result.map(|patched_source| {
                            analyze_variants_affected(&patched_source, filename)
                        }),
                    )
                })
                .map(|(_filename, flag)| flag)
                .collect::<anyhow::Result<Vec<_>>>()
                .context("failed to process patch")?;

            let mut final_flags = Flag::Or(result);

            if let Some(expander) = args.build_system_expander {
                final_flags = final_flags.map_building_flags(|mut file| {
                    if file.starts_with("/") {
                        file = file[1..].to_string();
                    }
                    let file = git_repo.join(file);

                    match expander {
                        BuildSystemExpander::Linux => {
                            build_expanders::linux::find_required_configs(&git_repo, &file).expect(
                                &format!("failed to find required configs for {}", file.display()),
                            )
                        }
                        BuildSystemExpander::PHP => {
                            build_expanders::linux::find_required_configs(&git_repo, &file).expect(
                                &format!("failed to find required configs for {}", file.display()),
                            )
                        }
                        BuildSystemExpander::FFMPEG => {
                            build_expanders::ffmpeg::find_required_configs(&git_repo, &file).expect(
                                &format!("failed to find required configs for {}", file.display()),
                            )
                        }
                    }
                });
            }

            println!("{final_flags}");
        }
        Commands::AnalyzeSingle {
            mut root_dir,
            diff_file,
        } => {
            root_dir = root_dir.canonicalize()?;
            let patch_content = std::fs::read_to_string(&diff_file)
                .context("failed to read the contents of the patch")?;

            let patched_file = patch_utils::get_patch_original_file(&patch_content, Some(0));
            let patched_source =
                patch_utils::apply_patch_in_memory(&root_dir, &patch_content, Some(0))?;

            let expanded_source = preprocessor::expand_include_macros(
                &patched_source,
                Path::new(patched_file),
                &include_dirs,
            )?;

            let variants = analyze_variants_affected(&expanded_source, patched_file);

            println!("{variants}");
        }
    }

    Ok(())
}
