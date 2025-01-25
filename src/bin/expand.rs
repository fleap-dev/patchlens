use std::env::args;


fn main() {
    let args = args().collect::<Vec<_>>();

    let tu_src = std::fs::read_to_string(&args[1]).unwrap();

    let mut lines = tu_src.lines();
    
    let mut idx = 0;
    while let Some(mut line) = lines.next() {
        idx += 1;
        let start = idx;

        if line.trim_start().starts_with("#") {

            let mut full = line.to_owned();
            while line.ends_with('\\') {
                full.pop();
                line = lines.next().unwrap();
                idx += 1;
                full.push_str(line);
            }

            let split: Vec<_> = full.split(' ').filter(|s| !s.is_empty()).collect();
            println!("MACRO FULL: {start}-{idx} {split:?}");
        }
    }


}
