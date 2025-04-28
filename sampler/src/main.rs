mod sampling_algorithm;

use std::collections::HashSet;
use std::env::args;
use std::fs::File;
use std::io;
use std::io::{BufRead, BufReader};
use std::path::Path;
use itertools::Itertools;
use regex::Regex;
use walkdir::WalkDir;
use sampling_algorithm::*;

fn find_linux_configs<P: AsRef<Path>>(root: P) -> io::Result<HashSet<String>> {
    let root = root.as_ref();
    if !root.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a directory", root.display()),
        ));
    }
    // Same regex as in Python: optional whitespace, "config", then the name
    let re = Regex::new(r"^\s*config\s+([A-Za-z0-9_]+)").unwrap();
    let mut options = HashSet::new();

    for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() && entry.file_name() == "Kconfig" {
            let path = entry.path();
            match File::open(path) {
                Ok(file) => {
                    let reader = BufReader::new(file);
                    for line in reader.lines().filter_map(Result::ok) {
                        if let Some(cap) = re.captures(&line) {
                            if let Some(m) = cap.get(1) {
                                options.insert(format!("CONFIG_{}", m.as_str()));
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to read {}: {}", path.display(), e);
                }
            }
        }
    }

    Ok(options)
}

fn solve(enabled_configs: &[&str], flag: ()) {
    
}

fn main() {
    let args = args().skip(1).collect::<Vec<_>>();
    
    // let options = vec!["A".into(), "B".into(), "C".into()];
    let options = find_linux_configs(args.first().expect("missing linux path"))
        .expect("failed to get linux configs")
        .into_iter()
        .take(100)
        .collect_vec();

    let sampling_algorithms: Vec<Box<dyn SamplingAlgorithm>> = vec![
        Box::new(MostEnabledDisabled),
        Box::new(OneDisabled),
        Box::new(OneEnabled),
        Box::new(StatementCoverage),
        Box::new(RandomSampling { n: 5 }),
        Box::new(TWiseGreedy {
            t: 2,
            default: false,
        }),
    ];

    for algo in sampling_algorithms {
        let samples = algo.sample(&options);
        println!("{algo:?} => {}", samples.count());
    }
}
