//! HTTP through the system `curl`.
//!
//! The tool has no HTTP library of its own: `curl` ships with macOS, follows
//! the system proxy and certificate settings, and keeps the dependency list
//! short. Every request goes through `run_curl`, which fails on HTTP errors.

use std::io::Write as _;
use std::process::{Command, Stdio};

/// `GET url`. Headers are passed in a config on stdin rather than as
/// arguments, so an API key never shows up in the process list.
///
/// curl sends custom headers to every host it is redirected to, so a request
/// that carries headers (an API key) fails on a redirect instead of following it.
pub fn get(url: &str, headers: &[String]) -> Result<String, String> {
    let mut config = format!("url = {}\n", quote(url));
    for header in headers {
        config.push_str(&format!("header = {}\n", quote(header)));
    }
    let mut args = vec!["--location", "--max-time", "60", "--config", "-"];
    if !headers.is_empty() {
        args.extend(["--max-redirs", "0"]);
    }
    run_curl(&args, Some(&config))
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

    use std::io::Read as _;
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn config_values_are_quoted() {
        assert_eq!(quote("apiKey: abc"), "\"apiKey: abc\"");
        assert_eq!(quote(r#"/Users/a "b"\c"#), r#""/Users/a \"b\"\\c""#);
    }

    /// A loopback HTTP server that answers every request with `response(port)`.
    /// The returned function stops it and gives back the requests it received.
    fn serve(response: impl Fn(u16) -> String + Send + 'static) -> (u16, impl FnOnce() -> Vec<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&stop);
        let server = std::thread::spawn(move || {
            let mut requests = Vec::new();
            loop {
                // Read before accepting, so a connection already waiting when
                // we are told to stop is still answered and recorded.
                let stopping = stopped.load(Ordering::SeqCst);
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_nonblocking(false).unwrap();
                        let mut request = Vec::new();
                        let mut buffer = [0; 4096];
                        // Read until the end of the headers, or until the client stops.
                        while !request.windows(4).any(|end| end == b"\r\n\r\n")
                            && let Ok(read @ 1..) = stream.read(&mut buffer)
                        {
                            request.extend_from_slice(&buffer[..read]);
                        }
                        requests.push(String::from_utf8_lossy(&request).into_owned());
                        let _ = stream.write_all(response(port).as_bytes());
                    }
                    Err(_) if stopping => return requests,
                    Err(_) => std::thread::sleep(std::time::Duration::from_millis(2)),
                }
            }
        });
        let finish = move || {
            stop.store(true, Ordering::SeqCst);
            server.join().unwrap()
        };
        (port, finish)
    }

    fn redirect_to(port: u16) -> String {
        format!("HTTP/1.1 302 Found\r\nLocation: http://localhost:{port}/moved\r\nContent-Length: 0\r\n\r\n")
    }

    #[test]
    fn headers_are_not_sent_along_a_redirect() {
        const OK: &str = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";

        // curl would send the key to whatever host the redirect names.
        let (other, other_requests) = serve(|_| OK.to_string());
        let (api, api_requests) = serve(move |_| redirect_to(other));
        let keyed = get(&format!("http://127.0.0.1:{api}/"), &["apiKey: secret".to_string()]);
        assert!(keyed.is_err(), "a redirect must not pass for an answer: {keyed:?}");
        assert!(api_requests()[0].contains("apiKey: secret"));
        assert!(other_requests().is_empty(), "the redirect target was contacted");

        // Requests without headers still follow redirects.
        let (other, other_requests) = serve(|_| OK.to_string());
        let (api, api_requests) = serve(move |_| redirect_to(other));
        assert_eq!(get(&format!("http://127.0.0.1:{api}/"), &[]).as_deref(), Ok("{}"));
        assert_eq!((api_requests().len(), other_requests().len()), (1, 1));
    }
}
