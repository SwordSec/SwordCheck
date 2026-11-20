//! The user's home directory, as every module that looks in it must see it.
//!
//! An empty or relative `HOME` is no home at all: joined with `.env` or
//! `Library/LaunchAgents` it would point into whatever folder the tool is
//! run from, and a scan there would be reported as the user's.

use std::ffi::OsString;
use std::path::PathBuf;

/// Why there is no home directory, in words for a message.
pub const MISSING: &str = "HOME is not set to an absolute path";

/// The home directory, if `HOME` names an absolute path.
pub fn dir() -> Option<PathBuf> {
    from(std::env::var_os("HOME"))
}

/// `dir` with the value of `HOME` passed in.
pub fn from(home: Option<OsString>) -> Option<PathBuf> {
    home.map(PathBuf::from).filter(|home| home.is_absolute())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_absolute_home_is_a_home() {
        let os = |text: &str| Some(OsString::from(text));
        assert_eq!(from(os("/Users/a")), Some(PathBuf::from("/Users/a")));
        assert_eq!(from(os("")), None);
        assert_eq!(from(os("relative")), None);
        assert_eq!(from(os("./Users/a")), None);
        assert_eq!(from(None), None);
    }
}
