//! API keys from the environment or a `.env` file.
//!
//! A key is looked up in this order: the process environment, `./.env`, then
//! `.env` in the storage directory (`~/.swordcheck`). Only the names the
//! tool asks for are read; a `.env` file is never loaded into the process
//! environment, so nothing in it reaches the commands the tool runs.

use std::path::PathBuf;

/// Returns the value of `name`, or `None` when it is not set anywhere.
pub fn lookup(name: &str) -> Option<String> {
    let from_env = std::env::var(name).ok().filter(|value| !value.trim().is_empty());
    from_env.or_else(|| {
        files().into_iter().find_map(|path| {
            let text = std::fs::read_to_string(path).ok()?;
            parse(&text, name)
        })
    })
}

fn files() -> Vec<PathBuf> {
    let mut files = vec![PathBuf::from(".env")];
    if let Some(dir) = crate::history::history_path().and_then(|path| path.parent().map(PathBuf::from)) {
        files.push(dir.join(".env"));
    }
    files
}

/// Finds `NAME=value` in `.env` text. Accepts an `export ` prefix, quotes
/// around the value and a trailing comment after an unquoted value. An empty
/// value counts as not set.
fn parse(text: &str, name: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let line = line.trim();
        let line = line.strip_prefix("export ").unwrap_or(line);
        let (key, value) = line.split_once('=')?;
        if key.trim() != name {
            return None;
        }
        let value = value.trim();
        let value = match value.chars().next() {
            Some(quote @ ('"' | '\'')) => value[1..].split(quote).next().unwrap_or_default(),
            _ => value.split(" #").next().unwrap_or_default().trim(),
        };
        (!value.is_empty()).then(|| value.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_are_read_in_the_usual_env_spellings() {
        let text = "# comment\nOTHER=1\nNVD_API_KEY=abc-123\n";
        assert_eq!(parse(text, "NVD_API_KEY").as_deref(), Some("abc-123"));
        assert_eq!(
            parse("export NVD_API_KEY=\"abc 123\" # mine", "NVD_API_KEY").as_deref(),
            Some("abc 123")
        );
        assert_eq!(parse("NVD_API_KEY='abc'", "NVD_API_KEY").as_deref(), Some("abc"));
        assert_eq!(
            parse("  NVD_API_KEY = abc # note", "NVD_API_KEY").as_deref(),
            Some("abc")
        );
    }

    #[test]
    fn empty_missing_and_commented_out_values_are_not_set() {
        assert_eq!(parse("NVD_API_KEY=", "NVD_API_KEY"), None);
        assert_eq!(parse("NVD_API_KEY=\"\"", "NVD_API_KEY"), None);
        assert_eq!(parse("# NVD_API_KEY=abc", "NVD_API_KEY"), None);
        assert_eq!(
            parse("MY_NVD_API_KEY=abc", "NVD_API_KEY"),
            None,
            "the whole name must match"
        );
        assert_eq!(parse("", "NVD_API_KEY"), None);
    }
}
