use std::{cmp::min, collections::LinkedList, env::args, path::Path};

#[derive(Debug)]
struct MacroDirective {
    command: String,
    arguments: Option<String>,
}

#[derive(Debug)]
struct SourceBlock {
    is_macro_directive: bool,
    src: String,
    /// Inclusive
    start_line: usize,
    /// Inclusive
    end_line: usize,
}

fn is_macro_directive(line: &str) -> bool {
    line.trim().starts_with('#')
}

fn parse_macro_directive(raw: &str) -> MacroDirective {
    let m = raw.lines()
        .map(|l| l.trim_end())
        .map(|l| if let Some(s) = l.strip_suffix('\\') { s } else { l })
        .map(|l| l.trim())
        .collect::<Vec<_>>()
        .join(" ");

    let start = m.trim_start()[1..].trim();
    let split = start.split_once(' ');
    if let Some((command, arguments)) = split {
        MacroDirective {
            command: command.to_string(),
            arguments: Some(arguments.trim().to_string()),
        }
    } else {
        MacroDirective {
            command: start.to_string(),
            arguments: None,
        }
    }
}

fn parse_src(src: &str) -> LinkedList<SourceBlock> {
    let mut blocks = LinkedList::<SourceBlock>::new();

    let mut lines = src.lines().enumerate().map(|(i, s)| (i + 1, s)).peekable();

    while let Some((idx, line)) = lines.next() {
        let mut block = SourceBlock {
            is_macro_directive: false,
            src: line.to_owned(),
            start_line: idx,
            end_line: idx,
        };
        if is_macro_directive(line) {
            // PARSE FULL MACRO BLOCK
            block.is_macro_directive = true;
            while block.src.trim_end().ends_with('\\') {
                let (next_idx, next_line) = lines.next().unwrap(); // TODO: remove unwrap
                block.end_line = next_idx;
                block.src.push('\n');
                block.src.push_str(next_line);
            }
        } else {
            // PARSE FULL CODE BLOCK
            while let Some((_, next_line)) = lines.peek() {
                if !is_macro_directive(next_line) {
                    let (next_idx, next_line) = lines.next().unwrap();
                    block.end_line = next_idx;
                    block.src.push('\n');
                    block.src.push_str(next_line);
                } else {
                    break;
                }
            }
        }
        blocks.push_back(block);
    }

    blocks
}

fn print_src(src: &str) {
    src.lines()
        .enumerate()
        .map(|(idx, s)| (idx + 1, s))
        .for_each(|(idx, s)| println!("{idx}  {s}"));
}

fn expand_includes(blocks: &mut LinkedList<SourceBlock>) {
    for block in blocks.iter_mut() {
        if block.is_macro_directive {
            let m = parse_macro_directive(&block.src);
            if m.command == "include" {
                // TODO: improve
                let args = m.arguments.unwrap();
                let file = &args.trim()[1..args.len() - 1];

                let path = Path::new("/usr/include").join(file);
                let target_src = std::fs::read_to_string(&path).unwrap();
                block.src = target_src;
            }
        }
    }
}

fn expand_file(file: &str) {
    let tu_src = std::fs::read_to_string(file).unwrap();

    let mut blocks = parse_src(&tu_src);

    expand_includes(&mut blocks);

    for block in blocks {
        for (idx, line) in block.src.lines().enumerate() {
            println!(
                "{:03}-{:03} | {:03} | {line}",
                block.start_line,
                block.end_line,
                min(block.start_line + idx, block.end_line)
            );
        }
    }
}

fn main() {
    let args = args().collect::<Vec<_>>();

    expand_file(&args[1]);
}
