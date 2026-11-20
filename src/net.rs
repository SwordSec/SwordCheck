//! HTTP through the system `curl`.
//!
//! The tool has no HTTP library of its own: `curl` ships with macOS, follows
//! the system proxy and certificate settings, and keeps the dependency list
//! short. Every request goes through `run_curl`, which fails on HTTP errors.

use std::io::Write as _;
use std::process::{Command, Stdio};

/// `GET url`. Headers are passed in a config on stdin rather than as
/// arguments, so an API key never shows up in the process list.
pub fn get(url: &str, headers: &[String]) -> Result<String, String> {
    let mut config = format!("url = {}\n", quote(url));
    for header in headers {
        config.push_str(&format!("header = {}\n", quote(header)));
    }
    run_curl(&["--location", "--max-time", "60", "--config", "-"], Some(&config))
}

/// `POST url` with a JSON body. The body is passed on stdin: a request that
/// covers thousands of packages could exceed the command line length limit.
pub fn post_json(url: &str, body: &str) -> Result<String, String> {
    let args = [
        "--max-time",
        "60",
        "--header",
        "Content-Type: application/json",
        "--data-binary",
        "@-",
        url,
    ];
    run_curl(&args, Some(body))
}

/// Quotes a value for a curl config file.
pub fn quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Runs `curl` quietly; fails on HTTP errors. `stdin` feeds `--config -` or
/// `--data-binary @-`.
pub fn run_curl(args: &[&str], stdin: Option<&str>) -> Result<String, String> {
    let mut child = Command::new("curl")
        .args(["--silent", "--show-error", "--fail"])
        .args(args)
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("could not run `curl`: {err}"))?;

    // Dropping the pipe closes it, which tells curl the input has ended. A
    // failed write is not returned right away: curl has usually exited with
    // a clearer message, and the child must be waited for either way.
    let sent = match (stdin, child.stdin.take()) {
        (Some(input), Some(mut pipe)) => pipe.write_all(input.as_bytes()),
        _ => Ok(()),
    };
    let output = child
        .wait_with_output()
        .map_err(|err| format!("could not wait for `curl`: {err}"))?;
    if !output.status.success() {
        let message = String::from_utf8_lossy(&output.stderr);
        return Err(message.lines().last().unwrap_or("curl failed").trim().to_string());
    }
    sent.map_err(|err| format!("could not send the request: {err}"))?;
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_values_are_quoted() {
        assert_eq!(quote("apiKey: abc"), "\"apiKey: abc\"");
        assert_eq!(quote(r#"/Users/a "b"\c"#), r#""/Users/a \"b\"\\c""#);
    }
}
