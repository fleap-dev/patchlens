use std::collections::HashMap;
use std::fs;
use std::path::Path;

// A simple structure to track source location information.
#[derive(Debug, Clone)]
pub struct SourceLocation {
    file: String,
    line: usize,
    column: usize,
}

// A simplified token type. In a real preprocessor tokens would be far more detailed.
#[derive(Debug)]
pub enum Token {
    Directive(String, SourceLocation), // e.g., "#include", "#define", "#ifdef"
    Text(String, SourceLocation),      // any other text
}

/// A simple source manager to load file contents and track file names.
pub struct SourceManager;

impl SourceManager {
    fn get_file_contents(file: &str) -> std::io::Result<String> {
        fs::read_to_string(file)
    }
}

/// The main preprocessor structure.
/// It holds a table of macros and a list of already processed files to avoid recursion.
#[derive(Debug, Default)]
pub struct Preprocessor {
    macros: HashMap<String, String>,
    processed_files: Vec<String>,
}

impl Preprocessor {
    /// Process a file and return the preprocessed output.
    pub fn preprocess_file(&mut self, path: &str) -> String {
        // Avoid recursive inclusion.
        if self.processed_files.contains(&path.to_string()) {
            return String::new();
        }
        self.processed_files.push(path.to_string());

        // Load file contents.
        let content = match SourceManager::get_file_contents(path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Error reading {}: {}", path, e);
                return String::new();
            }
        };

        // Preprocess the content.
        self.preprocess_content(&content, path)
    }

    /// Preprocess the content of a file.
    /// For each line, we handle directives or perform macro expansion.
    fn preprocess_content(&mut self, content: &str, file: &str) -> String {
        let mut output = String::new();
        let mut skipping = false; // used for #ifdef / #endif control

        // Process the file line by line.
        for (line_num, line) in content.lines().enumerate() {
            // Create a basic source location (column is set to 1 for simplicity).
            let loc = SourceLocation {
                file: file.to_string(),
                line: line_num + 1,
                column: 1,
            };

            let trimmed = line.trim_start();
            if trimmed.starts_with('#') {
                // Handle preprocessor directives.
                if trimmed.starts_with("#include") {
                    // Very simple parsing: assume syntax: #include "filename"
                    if let Some(start) = trimmed.find('"') {
                        if let Some(end) = trimmed[start + 1..].find('"') {
                            let include_path = &trimmed[start + 1..start + 1 + end];
                            let included = self.preprocess_file(include_path);
                            output.push_str(&included);
                        }
                    }
                    continue;
                } else if trimmed.starts_with("#define") {
                    // Simple define: assume syntax: #define IDENT VALUE
                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    if parts.len() >= 3 {
                        let ident = parts[1].to_string();
                        let value = parts[2..].join(" ");
                        self.macros.insert(ident, value);
                    }
                    continue;
                } else if trimmed.starts_with("#ifdef") {
                    // Simple ifdef: if macro is defined, process block; otherwise skip.
                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let macro_name = parts[1];
                        skipping = !self.macros.contains_key(macro_name);
                    }
                    continue;
                } else if trimmed.starts_with("#endif") {
                    skipping = false;
                    continue;
                }
                // Other directives can be handled here.
            }

            if skipping {
                // Skip lines until we see a matching #endif.
                continue;
            }

            // For normal lines, perform a simple macro expansion.
            let mut processed_line = line.to_string();
            for (key, value) in &self.macros {
                // This is a naive text replacement. Real implementations work on tokens.
                processed_line = processed_line.replace(key, value);
            }
            output.push_str(&processed_line);
            output.push('\n');
        }
        output
    }
}

