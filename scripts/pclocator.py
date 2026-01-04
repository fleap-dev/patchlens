#!/usr/bin/env -S uv --quiet run --script
# /// script
# requires-python = ">=3.13"
# dependencies = [
# ]
# ///

from curses import raw
from dataclasses import dataclass
import os
import subprocess
from typing import Literal, cast
import argparse
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(
        description="Use pclocator + kmax to find the full presence condition of a line in a file",
    )
    _ = parser.add_argument(
        "-f",
        "--file",
        help="Path to the target file",
    )
    _ = parser.add_argument(
        "-l",
        "--line-range",
        help="Line number or line range to analyze (e.g. 15:25 or 12)",
    )
    _ = parser.add_argument(
        "-r",
        "--root",
        help="Path to the root of the project",
        required=True,
    )
    _ = parser.add_argument(
        "-p",
        "--patch_file",
        help="Instead of passing line ranges, pass a patch file and analyze the lines it modifies",
        required=False,
        default=None,
    )

    args, _ = parser.parse_known_args()

    root = cast(str, args.root)
    file = cast(str | None, args.file)
    line_range = cast(str | None, args.line_range)
    patch_file = cast(str | None, args.patch_file)

    if patch_file:
        pc = calculate_patch_presence_condition(patch_file, root)

        print(pc)
    else:
        if line_range is None or file is None:
            raise RuntimeError(
                "line range and file must be set if not passing a patch file"
            )

        line_start, line_end = parse_line_range(line_range)

        print(
            f"Finding presence condition of '{file}' at line {line_start}:{line_end}...",
            file=sys.stderr,
        )

        build_system_pc = kmax(file, root)
        line_pc = pclocator(file, root, line_start, line_end)

        print(f"Build system PC: {build_system_pc}", file=sys.stderr)
        print(f"Line PC: {line_pc}", file=sys.stderr)

        print("Generating final PC...", file=sys.stderr)

        final_pc = f"({line_pc}) && ({build_system_pc})"

        print(convert_to_python_syntax(final_pc))


@dataclass
class ProcessPatchResult:
    raw_flag: str
    file_pcs: dict[str, str]


def calculate_patch_presence_condition(
    patch_file: str, project_root: str
) -> ProcessPatchResult:
    modified_files = parse_patch(patch_file)

    file_pcs: dict[str, str] = {}
    for file in modified_files:
        file_pc = kmax(str(file.path), project_root)
        print(f"DEBUG: file_pc({file.path}) = {file_pc}", file=sys.stderr)
        hunk_pcs: list[str] = []
        for hunk in file.line_range_of_hunks:
            hunk_pc = pclocator(str(file.path), project_root, hunk[0], hunk[1])
            hunk_pcs.append(f"({hunk_pc})")
        any_hunk_pc = " || ".join(hunk_pcs)
        file_pcs[str(file.path)] = f"(({file_pc}) && ({any_hunk_pc}))"

    any_file_pc = " || ".join(list(file_pcs.values()))

    raw_flag = convert_to_python_syntax(any_file_pc)

    return ProcessPatchResult(
        raw_flag,
        file_pcs,
    )


def kmax(file: str, root: str) -> str:
    @dataclass
    class KmaxOutput:
        kind: Literal["unit_pc", "subdir_pc"]
        target: str
        pc: str

    def kmax_cmd(target: str) -> list[KmaxOutput]:
        command = ["kmax", "-u", target]
        print(f"KMAX: {' '.join(command)}", file=sys.stderr)
        result = subprocess.run(command, capture_output=True, text=True, cwd=root)

        if result.returncode != 0:
            raise subprocess.SubprocessError(
                f"kmax command ({' '.join(command)}) failed with code {result.returncode}:\nStderr: {result.stderr}\n"
            )

        stdout = result.stdout

        lines = stdout.splitlines()

        if len(lines) == 0:
            raise RuntimeError("kmax generated an empty output")

        idx = 0
        while not (
            lines[idx].startswith("unit_pc") or lines[idx].startswith("subdir_pc")
        ):
            idx += 1

        pc_lines = lines[idx:]

        output: list[KmaxOutput] = []

        # Find presence condition for unit_pc
        for pc_line in pc_lines:
            parts = pc_line.split(" ")
            kind = cast(Literal["unit_pc", "subdir_pc"], parts[0])
            target = parts[1]
            pc = " ".join(parts[2:]).strip()

            output.append(KmaxOutput(kind, target, pc))

        return output

    def kmax_output_find(
        output: list[KmaxOutput], kind: Literal["unit_pc", "subdir_pc"], target: str
    ) -> str | None:
        for line in output:
            if line.kind == kind and line.target == target:
                return line.pc
        return None

    pcs: list[str] = []

    root_path = Path(os.path.abspath(root))
    path = Path(file)

    if not path.is_absolute():
        path = Path(os.path.join(root_path, path))

    target_obj = path.with_suffix(".o")

    # This algorithm loops upwards from the target file to the project root until
    # finding the first `unit_pc` (the presence condition of the target translation unit),
    # then it continues appending the presence condition of each subdir until reaching
    # the root dir.
    kind: Literal["unit_pc", "subdir_pc"] = "unit_pc"
    current_target = target_obj
    current_parent = target_obj.parent
    while True:
        target_obj_pc = kmax_output_find(
            kmax_cmd(str(current_parent)),
            kind,
            (str(current_target) + "/") if kind == "subdir_pc" else str(current_target),
        )
        if target_obj_pc is not None:
            pcs.append(target_obj_pc)
            kind = "subdir_pc"  # Change to find subdir pcs after finding the unit pc

        if current_parent == root_path:
            break

        current_target = current_parent
        current_parent = current_parent.parent

    return " && ".join(pcs)


def pclocator(file: str, root: str, line_start: int, line_end: int) -> str:
    path = Path(file)

    if not path.is_absolute():
        path = Path(os.path.join(Path(root), path))

    pcs: list[str] = []
    # Currently, I have not found a better way to get the pc of a line range :(
    for line in range(line_start, line_end + 1):
        command = ["pclocator", f"{path}:{line}"]
        print(f"PCLocator: {' '.join(command)}", file=sys.stderr)

        try:
            result = subprocess.run(command, capture_output=True, text=True)
        except subprocess.SubprocessError as e:
            raise subprocess.SubprocessError(
                f"pclocator command failed. Make sure you have a script named pclocator that calls PCLocator.jar available in $PATH. Error: {e}"
            )

        if result.returncode != 0:
            raise subprocess.SubprocessError(
                f"kmax command failed with code {result.returncode}:\nStderr: {result.stderr}\n"
            )

        stdout = result.stdout.strip()
        pcs.append(f"({stdout})")

    return " || ".join(pcs)


def convert_to_python_syntax(expr: str) -> str:
    # Hacky way to convert an expression generated from kmax+pclocator to the python ast syntax.
    # This is needed in order to use our simplifier.py script.
    return expr.replace(" && ", " & ").replace(" || ", " | ").replace("!", "~")


def parse_line_range(line_range: str) -> tuple[int, int]:
    # Parses a line range string in the format of <start>:<end> or <line_num>
    parts = line_range.split(":")

    if len(parts) == 1:
        line = int(parts[0])
        return (line, line)
    elif len(parts) == 2:
        return (int(parts[0]), int(parts[1]))
    else:
        raise RuntimeError(f"failed to parse line range: {line_range}")


@dataclass
class ModifiedFile:
    path: Path
    line_range_of_hunks: list[tuple[int, int]]


def parse_patch(patch_file: str) -> list[ModifiedFile]:
    import re

    file_path = Path(patch_file)
    content = file_path.read_text()
    lines = content.splitlines()

    modified_files: list[ModifiedFile] = []
    current_file: str | None = None
    current_hunks: list[tuple[int, int]] = []

    # Regex patterns
    diff_pattern = re.compile(r"^diff --git a/(.+) b/(.+)$")
    hunk_pattern = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")

    for line in lines:
        # Check for new file diff
        diff_match = diff_pattern.match(line)
        if diff_match:
            # Save the previous file if exists
            if current_file is not None:
                modified_files.append(
                    ModifiedFile(
                        path=Path(current_file), line_range_of_hunks=current_hunks
                    )
                )
            # Start tracking new file
            current_file = diff_match.group(1)  # Use the 'a/' path (before version)
            current_hunks = []
            continue

        # Check for hunk header
        hunk_match = hunk_pattern.match(line)
        if hunk_match and current_file is not None:
            old_start = int(hunk_match.group(1))
            old_count = int(hunk_match.group(2)) if hunk_match.group(2) else 1

            # Handle new files: old side is 0,0, so use the new side for the range
            if old_start == 0 and old_count == 0:
                new_start = int(hunk_match.group(3))
                new_count = int(hunk_match.group(4)) if hunk_match.group(4) else 1
                if new_count > 0:
                    current_hunks.append((new_start, new_start + new_count - 1))
            else:
                # Normal case: use the old (before) side
                if old_count > 0:
                    current_hunks.append((old_start, old_start + old_count - 1))

    # Don't forget the last file
    if current_file is not None:
        modified_files.append(
            ModifiedFile(path=Path(current_file), line_range_of_hunks=current_hunks)
        )

    return modified_files


if __name__ == "__main__":
    main()
