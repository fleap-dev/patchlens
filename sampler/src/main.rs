mod sampling_algorithm;

use itertools::Itertools;
use regex::Regex;
use sampling_algorithm::*;
use std::collections::HashSet;
use std::env::args;
use std::fs::File;
use std::io;
use std::io::{BufRead, BufReader};
use std::path::Path;
use walkdir::WalkDir;
use patchlens::logical_utils::Flag;

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
                    for line in reader.lines().map_while(Result::ok) {
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

fn main() -> anyhow::Result<()> {
    let args = args().skip(1).collect::<Vec<_>>();

    // let options = vec!["A".into(), "B".into(), "C".into()];
    let options = find_linux_configs(args.first().expect("missing linux path"))
        .expect("failed to get linux configs")
        .into_iter()
        // .take(100)
        .collect_vec();

    println!("Linux flags:\n{:#?}", options);

    let sampling_algorithms: Vec<Box<dyn SamplingAlgorithm>> = vec![
        Box::new(MostEnabledDisabled),
        Box::new(OneDisabled),
        Box::new(OneEnabled),
        Box::new(StatementCoverage),
        Box::new(RandomSampling { n: 5 }),
        // Box::new(TWiseGreedy {
        //     t: 2,
        //     default: false,
        // }),
    ];
    
    println!("Starting test for algorithms: {sampling_algorithms:?}");
    println!("\n--------------\n");
    
    std::thread::sleep(std::time::Duration::from_secs(2));

    // From CVE-2017-1000252
    let flag = Flag::And(vec![
        Flag::Defined("CONFIG_HAVE_KVM_IRQFD".into()),
        Flag::Building("virt/kvm/eventfd.c".into()),
    ]);

    for algo in sampling_algorithms {
        println!("Running {algo:?}...");
        let mut samples = algo.sample(&options);
        let matching = samples.find(
            |config| flag.solve(
                &mut |definition| {
                    config.iter().any(|d| d.as_str() == definition)
                },
                &mut |_building| {
                    true
                }
            )
        );

        match matching {
            Some(config) => {
                println!("{algo:?} FOUND CONFIG THAT MATCHES => {config:?}");
            },
            None => {
                println!("{algo:?} => Did not find any config matching the flag");
            }
        }
    }

    Ok(())
}
