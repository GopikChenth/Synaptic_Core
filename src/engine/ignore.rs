//! Ignore Engine for .synapseignore and .stignore file pattern matching.
//!
//! Supports:
//! - Comments (`#`, `//`)
//! - Inverted inclusion patterns (`!pattern`)
//! - Directory deletion prefixes (`(?d)`)
//! - Case-insensitive matching (`(?i)`)
//! - Globbing (`*`, `**`, `?`)

use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct IgnoreRule {
    pub pattern: String,
    pub is_inverted: bool,
    pub allow_dir_delete: bool,
    pub case_insensitive: bool,
    pub dir_only: bool,
}

#[derive(Debug, Clone, Default)]
pub struct IgnoreEngine {
    rules: Vec<IgnoreRule>,
}

impl IgnoreEngine {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Loads patterns from a file like `.synapseignore` or `.stignore`.
    pub fn load_from_file(file_path: &Path) -> Self {
        let mut engine = Self::new();
        if let Ok(content) = fs::read_to_string(file_path) {
            engine.parse_rules(&content);
        }
        engine
    }

    /// Parses rule strings line by line.
    pub fn parse_rules(&mut self, content: &str) {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
                continue;
            }

            let mut pat = trimmed;
            let mut allow_dir_delete = false;
            let mut case_insensitive = false;
            let mut is_inverted = false;

            if pat.starts_with("(?d)") {
                allow_dir_delete = true;
                pat = &pat[4..].trim_start();
            }

            if pat.starts_with("(?i)") {
                case_insensitive = true;
                pat = &pat[4..].trim_start();
            }

            if pat.starts_with('!') {
                is_inverted = true;
                pat = &pat[1..].trim_start();
            }

            let dir_only = pat.ends_with('/') || pat.ends_with('\\');
            let clean_pat = pat.trim_end_matches(['/', '\\']).to_string();

            self.rules.push(IgnoreRule {
                pattern: clean_pat,
                is_inverted,
                allow_dir_delete,
                case_insensitive,
                dir_only,
            });
        }
    }

    /// Checks if a relative file path matches the ignore rules.
    pub fn is_ignored(&self, relative_path: &str, is_dir: bool) -> bool {
        let norm_path = relative_path.replace('\\', "/");
        let mut ignored = false;

        for rule in &self.rules {
            if rule.dir_only && !is_dir {
                continue;
            }

            let matches = if rule.case_insensitive {
                match_glob(&norm_path.to_lowercase(), &rule.pattern.to_lowercase())
            } else {
                match_glob(&norm_path, &rule.pattern)
            };

            if matches {
                ignored = !rule.is_inverted;
            }
        }

        ignored
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

/// Simple glob matcher supporting `*`, `**`, and `?`.
fn match_glob(path: &str, pattern: &str) -> bool {
    let clean_pat = pattern.trim_start_matches('/');

    // Exact filename match in any subdirectory
    if !clean_pat.contains('/') {
        let file_name = path.rsplit('/').next().unwrap_or(path);
        if match_simple_glob(file_name, clean_pat) {
            return true;
        }
    }

    if match_simple_glob(path, clean_pat) {
        return true;
    }

    // Prefix match for directories
    if path.starts_with(clean_pat) {
        if path.len() == clean_pat.len() || path.as_bytes().get(clean_pat.len()) == Some(&b'/') {
            return true;
        }
    }

    false
}

fn match_simple_glob(text: &str, pattern: &str) -> bool {
    let t_chars: Vec<char> = text.chars().collect();
    let p_chars: Vec<char> = pattern.chars().collect();

    let mut t = 0;
    let mut p = 0;
    let mut star_p = None;
    let mut match_t = 0;

    while t < t_chars.len() {
        if p < p_chars.len() && (p_chars[p] == '?' || p_chars[p] == t_chars[t]) {
            t += 1;
            p += 1;
        } else if p < p_chars.len() && p_chars[p] == '*' {
            star_p = Some(p);
            p += 1;
            match_t = t;
        } else if let Some(sp) = star_p {
            p = sp + 1;
            match_t += 1;
            t = match_t;
        } else {
            return false;
        }
    }

    while p < p_chars.len() && p_chars[p] == '*' {
        p += 1;
    }

    p == p_chars.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ignore_rules() {
        let mut engine = IgnoreEngine::new();
        engine.parse_rules(
            "
            # Comments
            *.tmp
            (?d).git/
            (?i)*.log
            !important.log
            build/**
            node_modules
            ",
        );

        assert!(engine.is_ignored("cache/temp.tmp", false));
        assert!(engine.is_ignored("app.LOG", false));
        assert!(!engine.is_ignored("important.log", false)); // Inverted
        assert!(engine.is_ignored("node_modules/package.json", false));
        assert!(engine.is_ignored(".git", true));
        assert!(!engine.is_ignored("src/main.rs", false));
    }
}
