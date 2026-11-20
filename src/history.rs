//! Audit history: every run is appended to `~/.swordcheck/history.json`
//! and compared against the previous state on the next run.

use crate::checks::{CheckResult, Status};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Maximum number of records kept in the file.
const MAX_RECORDS: usize = 100;

/// Summary of a single audit run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunRecord {
    /// Local time in RFC 3339 format.
    pub timestamp: String,
    pub os_version: String,
    pub score: u32,
    /// Check id → status. `BTreeMap` keeps its keys sorted, so the file
    /// has the same layout on every write.
    pub checks: BTreeMap<String, Status>,
}

impl RunRecord {
    pub fn new(timestamp: String, os_version: String, score: u32, results: &[CheckResult]) -> Self {
        Self {
            timestamp,
            os_version,
            score,
            checks: results
                .iter()
                .map(|result| (result.id.to_string(), result.status))
                .collect(),
        }
    }
}

/// A check's status change between two runs.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Change {
    pub id: &'static str,
    pub name: &'static str,
    pub from: Status,
    pub to: Status,
}

impl Change {
    /// Is the change for the better? (Pass is best, Fail is worst.)
    pub fn improved(&self) -> bool {
        rank(self.to) > rank(self.from)
    }
}

fn rank(status: Status) -> u8 {
    match status {
        Status::Fail => 0,
        Status::Warn => 1,
        Status::Unknown => 2,
        Status::Pass => 3,
    }
}

/// Path of the history file. The directory can be changed with the
/// `SWORDCHECK_HOME` environment variable (handy in tests and experiments).
pub fn history_path() -> Option<PathBuf> {
    let dir = match std::env::var_os("SWORDCHECK_HOME") {
        Some(dir) => PathBuf::from(dir),
        None => Path::new(&std::env::var_os("HOME")?).join(".swordcheck"),
    };
    Some(dir.join("history.json"))
}

/// Reads the history records. Returns an empty list if the file does not
/// exist; fails if it is corrupt (so we do not overwrite it and lose data).
pub fn load(path: &Path) -> Result<Vec<RunRecord>, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text).map_err(|err| format!("could not parse {}: {err}", path.display())),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(err) => Err(format!("could not read {}: {err}", path.display())),
    }
}

/// Appends the new record and writes the file; the oldest records are
/// dropped once `MAX_RECORDS` is exceeded.
pub fn append(path: &Path, mut records: Vec<RunRecord>, record: RunRecord) -> Result<(), String> {
    records.push(record);
    if records.len() > MAX_RECORDS {
        let excess = records.len() - MAX_RECORDS;
        records.drain(..excess);
    }

    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;
    }
    let json = serde_json::to_string_pretty(&records).map_err(|err| err.to_string())?;
    // Write a sibling file and rename it over the old one: a crash or a
    // second run at the same moment never leaves a half-written history.
    let temp = path.with_extension(format!("json.{}.tmp", std::process::id()));
    std::fs::write(&temp, json)
        .and_then(|()| std::fs::rename(&temp, path))
        .map_err(|err| {
            let _ = std::fs::remove_file(&temp);
            format!("could not write {}: {err}", path.display())
        })
}

/// Checks whose status changed between the previous record and the current
/// results. Checks missing from the previous record (newly added ones) do
/// not count as changes.
pub fn diff(previous: &RunRecord, results: &[CheckResult]) -> Vec<Change> {
    results
        .iter()
        .filter_map(|result| {
            let from = *previous.checks.get(result.id)?;
            (from != result.status).then_some(Change {
                id: result.id,
                name: result.name,
                from,
                to: result.status,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::score::tests::result;

    fn record(score: u32, results: &[CheckResult]) -> RunRecord {
        RunRecord::new("2026-11-10T10:00:00+03:00".into(), "macOS 26".into(), score, results)
    }

    #[test]
    fn finds_changed_checks() {
        let before = record(
            50,
            &[result("firewall", Status::Fail, 20), result("sip", Status::Pass, 20)],
        );
        let now = [
            result("firewall", Status::Pass, 20),
            result("sip", Status::Pass, 20),
            result("new", Status::Fail, 5), // not in the previous record: not counted
        ];

        let changes = diff(&before, &now);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].id, "firewall");
        assert!(changes[0].improved());
    }

    #[test]
    fn regression_is_not_an_improvement() {
        let change = Change {
            id: "x",
            name: "x",
            from: Status::Pass,
            to: Status::Warn,
        };
        assert!(!change.improved());
    }

    #[test]
    fn writes_reads_back_and_truncates() {
        let dir = std::env::temp_dir().join(format!("swordcheck-hist-{}", std::process::id()));
        let path = dir.join("history.json");

        assert!(load(&path).unwrap().is_empty(), "empty list when the file is missing");

        let results = [result("a", Status::Pass, 1)];
        for score in 0..(MAX_RECORDS as u32 + 5) {
            let records = load(&path).unwrap();
            append(&path, records, record(score, &results)).unwrap();
        }

        let records = load(&path).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();

        assert_eq!(records.len(), MAX_RECORDS);
        assert_eq!(records.last().unwrap().score, MAX_RECORDS as u32 + 4);
        assert_eq!(records[0].score, 5, "the 5 oldest records should be dropped");
        assert_eq!(records[0].checks["a"], Status::Pass);
    }

    #[test]
    fn corrupt_file_is_an_error() {
        let dir = std::env::temp_dir().join(format!("swordcheck-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("history.json");
        std::fs::write(&path, "{ broken").unwrap();

        let loaded = load(&path);
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(loaded.is_err());
    }
}
