# PatchLens

PatchLens is a static analysis tool to determine the Vulnerability Impact Condition (VIC) for security patches in highly configurable C/C++ systems. It is the artifact for the scientific paper "Automated Detection of Configuration-Specific Security Vulnerabilities via Patch Analysis".

The core idea is to formalize the VIC—a Boolean predicate over configuration options that denotes all system variants that contained the original flaw. PatchLens recovers these VICs by aligning Abstract Syntax Tree (AST) level patch hunks with source-level presence conditions and resolving file inclusion via lightweight build-system analysis.

## Repository Structure

This repository contains all code and scripts related to PatchLens.

*   `core/`: Contains the source code for the core PatchLens analysis library.
*   `cli/`: A command-line frontend for the PatchLens library.
*   `makefile_analyzer/`: A small, standalone utility for testing Makefile analysis.
*   `scripts/`: A collection of Python scripts for automating PatchLens, generating datasets, and performing data analysis for the paper.
*   `data/`: (git ignored) This directory contains the generated data used for the evaluation in the paper.

## Building from Source

PatchLens is written in Rust. You can build the project using Cargo:

```bash
# Build the project in release mode
cargo build --release
```

The main executable will be available at `target/release/patchlens-cli`.

## Usage

PatchLens provides a command-line interface to analyze patches.

### Basic Analysis

The `analyze-git` subcommand analyzes a patch file (in mail format, e.g., from `git format-patch`) against a given Git repository.

```bash
# Run via cargo
cargo run --release -- analyze-git <path/to/git/repo> <path/to/patch.eml>

# Or run the compiled binary directly
./target/release/patchlens-cli analyze-git <path/to/git/repo> <path/to/patch.eml>
```

### Build System Specific Analysis

For more precise analysis that considers the project's build system, you can use the `--build-system-expander` (`-e`) flag. This is supported for Linux, PHP, FFmpeg, and Busybox.

```bash
# Example for a Linux kernel patch
cargo run --release -- -e linux analyze-git <path/to/linux/repo> <path/to/kernel/patch.eml>
```

The output will be a Boolean predicate representing the Vulnerability Impact Condition (VIC).

## Scripts
The `scripts/` directory contains various helper scripts used for the research paper.

*   `make_dataset.py`: Script to generate the patch dataset.
*   `automate_patchlens.py`: Automates running PatchLens over the entire dataset.
*   `dataset_stats.py`: Computes statistics on the dataset.
*   `dataset.py`: Dataset management and more complex analysis:
    - List, manage and import runs (automated patchlens executions over the dataset);
    - Analyze the complexity of VICs;
    - Analyze variable mentions in descriptions;
    - Analyze most severe variables and more.

### Requirements:
- [https://www.rust-lang.org/learn/get-started](Rust toolchain)
- [https://github.com/astral-sh/uv](uv)

### Automating Patchlens
To generate the Patch dataset, automate patchlens and analyze the results, do:
1. Clone this repository and `cd` into it.
2. Generate the Patch dataset:
```bash
# Script deps will be automatically downloaded with UV.
./scripts/make_dataset.py
```
3. Analyze a target repo:
```bash
# Analyzing Linux patches, for example
./scripts/automate_patchlens.py --patchlens ./target/release/cli linux/linux_kernel ./data/patchlens-repos/linux/ -E linux
# NOTE: The `linux/linux_kernel` parameter is used to filter patches to match this vendor/product.
# NOTE: The `./data/patchlens-repos/linux/` should point to the path to the Git repository of the target system.
# NOTE: The `-E linux` parameter specifies which type of build-system analysis to be used. In this case, analyze Linux kbuild files.
```

## Citation

If you use PatchLens in your research, please cite our paper.

```bibtex
@inproceedings{patchlens-paper,
  TO BE DONE :)
}
```
