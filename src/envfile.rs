//! API keys from the environment or a `.env` file.
//!
//! A key is looked up in this order: the process environment, `./.env`, then
//! `.env` in the storage directory (`~/.swordcheck`). Only the names the
//! tool asks for are read; a `.env` file is never loaded into the process
//! environment, so nothing in it reaches the commands the tool runs.

use std::path::PathBuf;

/// Returns the value of `name`, or `None` when it is not set anywhere.
pub fn lookup(name: &str) -> Option<String> {
    lookup_in(std::env::var(name).ok(), &files(), name)
}

/// `lookup` with the environment's value and the files to read given.
fn lookup_in(from_env: Option<String>, files: &[PathBuf], name: &str) -> Option<String> {
    // Trimmed like a value from a file: a CR from a CRLF shell profile or a
    // pasted trailing space would otherwise end up in the request header.
    let from_env = from_env
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    from_env.or_else(|| {
        files.iter().find_map(|path| {
            let text = std::fs::read_to_string(path).ok()?;
            // Some editors start the file with a byte order mark; it is not
            // part of the first name.
            parse(text.strip_prefix('\u{feff}').unwrap_or(&text), name)
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

    #[test]
    fn a_value_from_the_environment_is_trimmed_like_one_from_a_file() {
        let dir = std::env::temp_dir().join(format!("swordcheck-envfile-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join(".env");
        std::fs::write(&file, "NVD_API_KEY=from-file\n").unwrap();
        let files = [dir.join("missing.env"), file];
        let lookup = |from_env: Option<&str>| lookup_in(from_env.map(str::to_string), &files, "NVD_API_KEY");

        // The CR of a CRLF shell profile, a pasted space or newline.
        for value in ["abc123\r", "abc123 ", " abc123\n", "abc123"] {
            assert_eq!(lookup(Some(value)).as_deref(), Some("abc123"), "{value:?}");
        }
        // Not set, or only whitespace: the files are read, in order.
        assert_eq!(lookup(Some(" \r\n")).as_deref(), Some("from-file"));
        assert_eq!(lookup(None).as_deref(), Some("from-file"));
        assert_eq!(lookup_in(None, &[], "NVD_API_KEY"), None);

        // A byte order mark at the start of the file is not part of the name.
        std::fs::write(&files[1], "\u{feff}NVD_API_KEY=with-bom\r\n").unwrap();
        assert_eq!(lookup(None).as_deref(), Some("with-bom"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
