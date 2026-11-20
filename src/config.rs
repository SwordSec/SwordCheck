//! The `audit.toml` configuration file.
//!
//! Example:
//!
//! ```toml
//! min_score = 80
//! skip = ["airdrop"]
//!
//! [weights]
//! filevault = 40
//!
//! [exceptions]
//! ssh = "Development server, SSH is enabled on purpose"
//! ```

use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// The largest weight a check may be given. A cap keeps typos out and the
/// score arithmetic far away from overflow.
pub const MAX_WEIGHT: u32 = 1000;

/// The configuration. All fields are optional (`#[serde(default)]`);
/// `deny_unknown_fields` reports typos instead of silently swallowing them.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// If the score is below this value, the exit code is 1.
    pub min_score: Option<u32>,
    /// Ids of checks that are never run.
    pub skip: Vec<String>,
    /// Check id → weight in the score (at most `MAX_WEIGHT`).
    pub weights: HashMap<String, u32>,
    /// Check id → exception reason. An exempted check still runs and is
    /// shown, but does not affect the score or the exit code.
    pub exceptions: HashMap<String, String>,
}

impl Config {
    /// Loads the configuration.
    ///
    /// If `explicit` is given, that file is required. Otherwise
    /// `./audit.toml` and `~/.config/swordcheck/audit.toml` are tried in
    /// order; if neither exists, the default (empty) configuration is returned.
    pub fn load(explicit: Option<&Path>) -> Result<Self, String> {
        let path = match explicit {
            Some(path) => Some(path.to_path_buf()),
            None => default_paths().into_iter().find(|path| path.is_file()),
        };

        match path {
            Some(path) => {
                let text = std::fs::read_to_string(&path)
                    .map_err(|err| format!("could not read {}: {err}", path.display()))?;
                Self::parse(&text).map_err(|err| format!("{}: {err}", path.display()))
            }
            None => Ok(Self::default()),
        }
    }

    /// Parses TOML text.
    pub fn parse(text: &str) -> Result<Self, String> {
        let config: Config = toml::from_str(text).map_err(|err| err.to_string())?;
        if config.min_score.is_some_and(|score| score > 100) {
            return Err("min_score must be between 0 and 100".to_string());
        }
        // Sorted so the error is the same on every run.
        let mut too_heavy: Vec<(&String, &u32)> = config
            .weights
            .iter()
            .filter(|(_, weight)| **weight > MAX_WEIGHT)
            .collect();
        too_heavy.sort();
        if let Some((id, weight)) = too_heavy.first() {
            return Err(format!(
                "weight for `{id}` is {weight}; it must be between 0 and {MAX_WEIGHT}"
            ));
        }
        Ok(config)
    }

    /// All check ids mentioned in the configuration (for validation).
    pub fn referenced_ids(&self) -> impl Iterator<Item = &str> {
        self.skip
            .iter()
            .chain(self.weights.keys())
            .chain(self.exceptions.keys())
            .map(String::as_str)
    }
}

fn default_paths() -> Vec<PathBuf> {
    let mut paths = vec![PathBuf::from("audit.toml")];
    if let Some(home) = std::env::var_os("HOME") {
        paths.push(Path::new(&home).join(".config/swordcheck/audit.toml"));
    }
    paths
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_example_parses() {
        let config = Config::parse(
            r#"
            min_score = 80
            skip = ["airdrop"]

            [weights]
            filevault = 40

            [exceptions]
            ssh = "enabled on purpose"
            "#,
        )
        .unwrap();

        assert_eq!(config.min_score, Some(80));
        assert_eq!(config.skip, ["airdrop"]);
        assert_eq!(config.weights["filevault"], 40);
        assert_eq!(config.exceptions["ssh"], "enabled on purpose");

        let mut ids: Vec<&str> = config.referenced_ids().collect();
        ids.sort_unstable();
        assert_eq!(ids, ["airdrop", "filevault", "ssh"]);
    }

    #[test]
    fn empty_file_yields_defaults() {
        let config = Config::parse("").unwrap();
        assert!(config.min_score.is_none());
        assert!(config.skip.is_empty());
    }

    #[test]
    fn unknown_field_and_invalid_score_are_rejected() {
        assert!(Config::parse("minscore = 80").is_err());
        assert!(Config::parse("min_score = 150").is_err());
    }

    #[test]
    fn weights_are_capped() {
        let at_cap = Config::parse("[weights]\nfilevault = 1000").unwrap();
        assert_eq!(at_cap.weights["filevault"], MAX_WEIGHT);
        assert!(Config::parse("[weights]\nfilevault = 0").is_ok());

        let err = Config::parse("[weights]\nssh = 5\nfilevault = 1001").unwrap_err();
        assert!(err.contains("filevault") && err.contains("1000"), "{err}");

        // The value that used to overflow `weight * 2`.
        assert!(Config::parse("[weights]\nfilevault = 2147483648").is_err());
        assert!(Config::parse("[weights]\nfilevault = 4294967295").is_err());
        assert!(Config::parse("[weights]\nfilevault = -1").is_err());
    }
}
