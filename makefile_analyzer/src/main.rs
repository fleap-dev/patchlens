use clap::Parser as ClapParser;
use std::path::PathBuf;

#[derive(ClapParser, Debug)]
#[command(version, about = "Analyze kernel Makefiles to tell what variables need to be set in order to build a specific file", long_about = None
)]
struct Cli {
    #[arg(help = "Path to the root of the linux repo")]
    linux_root: PathBuf,
    #[arg(help = "Name of the C file to search for")]
    c_file: PathBuf,
}

fn main() {
    let args = Cli::parse();

    match patchlens::build_expanders::linux::find_required_configs(&args.linux_root, &args.c_file) {
        Err(e) => {
            eprintln!("▶ Failed to find configs for {:?}: {e}", args.c_file);
            std::process::exit(1);
        }
        Ok(flag) => {
            println!("{flag:?}");
        }
    }
}
