use anyhow::{ensure, Context, Result};
use regex::Regex;
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
};

use crate::Flag;

pub fn find_required_configs(ffmpeg_root: &Path, target: &Path) -> Result<Flag> {
    // 1) Sanity checks
    ensure!(ffmpeg_root.is_dir(), "ffmpeg root is not a directory");
    ensure!(target.is_file(), "target file does not exist");
    ensure!(
        target
            .extension()
            .and_then(|s| s.to_str())
            .map(|ext| ext.eq_ignore_ascii_case("c"))
            .unwrap_or(false),
        "target must be a .c file"
    );

    // 2) Normalize and compute relative path + obj name
    let ffmpeg_root = ffmpeg_root.canonicalize()?;
    let target = target.canonicalize()?;
    let relative = target
        .strip_prefix(&ffmpeg_root)
        .context("target not inside ffmpeg root")?;
    let c_filename = target
        .file_name()
        .and_then(|s| s.to_str())
        .context("could not get C filename")?;
    let base = c_filename.strip_suffix(".c").unwrap_or(c_filename);
    let obj_name = format!("{}.o", base);

    // 3) Parse all Makefiles into an obj → Vec<condition-groups> map
    //    Only consider Makefiles from the same directory as the target file
    //    to avoid cross-directory basename collisions (e.g., libavcodec/takdec.o
    //    vs libavformat/takdec.o are completely different files).
    let target_dir = relative
        .parent()
        .context("could not get target directory")?;
    let makefiles = find_all_makefiles(&ffmpeg_root)?;
    let obj_to_groups =
        parse_makefiles_for_full_dependency_map(&ffmpeg_root, &makefiles, target_dir)?;

    // 4) Lookup our .o
    let groups = obj_to_groups
        .get(&obj_name)
        .with_context(|| format!("no build conditions found for {}", obj_name))?;

    // 5) Turn Vec<Vec<Flag>> into one Flag (Or/And/True)
    let base_flag = compute_base_condition(groups);

    // 6) Mix in the “component” guard (libavcodec → CONFIG_AVCODEC, fftools → !CONFIG_DISABLE_PROGRAMS)
    let comp_flag = get_component_condition(relative);

    // 7) Conjoin if both non-trivial
    let final_flag = match (comp_flag.clone(), base_flag.clone()) {
        (Flag::True, rf) => rf,
        (cf, Flag::True) => cf,
        (cf, rf) => Flag::And(vec![cf, rf]),
    };

    Ok(final_flag)
}

fn find_all_makefiles(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).with_context(|| format!("reading {:?}", dir))? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            out.append(&mut find_all_makefiles(&path)?);
        } else if path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n == "Makefile")
            .unwrap_or(false)
        {
            out.push(path);
        }
    }
    Ok(out)
}

fn parse_makefiles_for_full_dependency_map(
    ffmpeg_root: &Path,
    makefiles: &[PathBuf],
    target_dir: &Path,
) -> Result<HashMap<String, Vec<Vec<Flag>>>> {
    let mut obj_to_groups: HashMap<String, Vec<Vec<Flag>>> = HashMap::new();
    let mut prog_to_conds: HashMap<String, HashSet<String>> = HashMap::new();
    let mut prog_to_objs: HashMap<String, HashSet<String>> = HashMap::new();

    // Precompile our regexes
    let re_arch_objs = Regex::new(r"^([A-Z0-9_]+-OBJS)-\$\((.*?)\)\s*\+=\s*(.*)$").unwrap();
    let re_prog_cond = Regex::new(r"^AVPROGS-\$\((.*?)\)\s*\+=\s*([a-zA-Z0-9_]+)$").unwrap();
    let re_obj_prog = Regex::new(r"^OBJS-([a-zA-Z0-9_]+)\s*\+=\s*(.*)$").unwrap();
    let re_direct_cond =
        Regex::new(r"^(?:OBJS|SHLIBOBJS|STLIBOBJS)-\$\((.*?)\)\s*\+=\s*(.*)$").unwrap();
    let re_uncond = Regex::new(r"^(?:OBJS|SHLIBOBJS|STLIBOBJS)\s*\+?=\s*(.*)$").unwrap();

    for mf in makefiles {
        // Only process Makefiles from the same directory as the target file
        let mf_dir = mf
            .parent()
            .and_then(|p| p.strip_prefix(ffmpeg_root).ok())
            .unwrap_or(Path::new(""));
        let is_target_dir = mf_dir == target_dir;

        let text = fs::read_to_string(mf)?;
        let mut buffer = String::new();

        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            buffer.push_str(line);
            if buffer.ends_with('\\') {
                buffer.pop();
                buffer.push(' ');
                continue;
            }

            // Case 1: ARCH-specific OBJS
            if let Some(caps) = re_arch_objs.captures(&buffer) {
                if is_target_dir {
                    let var_name = &caps[1];
                    let cfg = &caps[2];
                    let objs = &caps[3];
                    let prefix = var_name.split('-').next().unwrap();
                    let mut conds = HashSet::new();
                    conds.insert(format!("HAVE_{prefix}"));
                    conds.insert(cfg.to_string());
                    for obj in objs.split_whitespace().filter(|o| o.ends_with(".o")) {
                        let name = Path::new(obj)
                            .file_name()
                            .unwrap()
                            .to_str()
                            .unwrap()
                            .to_string();
                        obj_to_groups
                            .entry(name)
                            .or_default()
                            .push(conds.iter().map(|s| Flag::Defined(s.clone())).collect());
                    }
                }
                buffer.clear();
                continue;
            }

            // Case 2: program guard
            if let Some(caps) = re_prog_cond.captures(&buffer) {
                let cfg = &caps[1];
                let prog = &caps[2];
                prog_to_conds
                    .entry(prog.to_string())
                    .or_default()
                    .insert(cfg.to_string());
                buffer.clear();
                continue;
            }

            // Case 3: program → objs
            if let Some(caps) = re_obj_prog.captures(&buffer) {
                let prog = &caps[1];
                let objs = &caps[2];
                let set = prog_to_objs.entry(prog.to_string()).or_default();
                for obj in objs.split_whitespace().filter(|o| o.ends_with(".o")) {
                    let name = Path::new(obj)
                        .file_name()
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .to_string();
                    set.insert(name);
                }
                buffer.clear();
                continue;
            }

            // Case 4: direct conditional objs
            if let Some(caps) = re_direct_cond.captures(&buffer) {
                if is_target_dir {
                    let cfg = &caps[1];
                    let objs = &caps[2];
                    for obj in objs.split_whitespace().filter(|o| o.ends_with(".o")) {
                        let name = Path::new(obj)
                            .file_name()
                            .unwrap()
                            .to_str()
                            .unwrap()
                            .to_string();
                        obj_to_groups
                            .entry(name)
                            .or_default()
                            .push(vec![Flag::Defined(cfg.to_string())]);
                    }
                }
                buffer.clear();
                continue;
            }

            // Case 5: unconditional objs
            if let Some(caps) = re_uncond.captures(&buffer) {
                if is_target_dir {
                    let objs = &caps[1];
                    for obj in objs.split_whitespace().filter(|o| o.ends_with(".o")) {
                        let name = Path::new(obj)
                            .file_name()
                            .unwrap()
                            .to_str()
                            .unwrap()
                            .to_string();
                        obj_to_groups
                            .entry(name)
                            .or_default()
                            .push(vec![Flag::True]);
                    }
                }
                buffer.clear();
                continue;
            }

            buffer.clear();
        }
    }

    // Dependency resolution: propagate program guards into their objects
    for (prog, objs) in &prog_to_objs {
        if let Some(cfgs) = prog_to_conds.get(prog) {
            let group: Vec<Flag> = cfgs.iter().map(|c| Flag::Defined(c.clone())).collect();
            for obj in objs {
                obj_to_groups
                    .entry(obj.clone())
                    .or_default()
                    .push(group.clone());
            }
        }
    }
    // Also make the .o of each program itself conditional
    for (prog, cfgs) in &prog_to_conds {
        let obj = format!("{prog}.o");
        let group: Vec<Flag> = cfgs.iter().map(|c| Flag::Defined(c.clone())).collect();
        obj_to_groups.entry(obj).or_default().push(group);
    }

    Ok(obj_to_groups)
}

fn compute_base_condition(groups: &[Vec<Flag>]) -> Flag {
    // Remove pure-[True] if mixed
    let real: Vec<_> = groups
        .iter()
        .filter(|g| !(g.len() == 1 && g[0] == Flag::True))
        .cloned()
        .collect();
    if real.is_empty() {
        return Flag::True;
    }
    if real.len() == 1 {
        let single = real.into_iter().next().unwrap();
        return if single.len() == 1 {
            single.into_iter().next().unwrap()
        } else {
            Flag::And(single)
        };
    }
    // multiple groups → OR(...)
    let parts: Vec<Flag> = real
        .into_iter()
        .map(|grp| {
            if grp.len() == 1 {
                grp.into_iter().next().unwrap()
            } else {
                Flag::And(grp)
            }
        })
        .collect();
    Flag::Or(parts)
}

fn get_component_condition(relative: &Path) -> Flag {
    let first = relative
        .components()
        .next()
        .and_then(|c| c.as_os_str().to_str())
        .unwrap_or("");

    if first.starts_with("lib") {
        let up = first.to_uppercase();
        let tail = up.trim_start_matches("LIB");
        Flag::Defined(format!("CONFIG_{tail}"))
    } else if first == "fftools" {
        Flag::Not(Box::new(Flag::Defined(
            "CONFIG_DISABLE_PROGRAMS".to_string(),
        )))
    } else {
        Flag::True
    }
}
