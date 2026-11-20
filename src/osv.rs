//! OSV.dev batch queries, shared by the vulnerability scan and the npm scan.
//!
//! Only package names, ecosystems and versions are sent.

use serde_json::{Value, json};

pub const BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
pub const VULN_URL: &str = "https://api.osv.dev/v1/vulns";
/// OSV accepts at most 1000 queries per request.
const BATCH: usize = 1000;
/// Upper bound on follow-up pages for one batch; a guard against a server
/// that keeps returning page tokens.
const MAX_PAGES: usize = 50;

/// One package version to ask about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Query<'a> {
    pub ecosystem: &'a str,
    pub name: &'a str,
    pub version: &'a str,
}

/// An advisory that applies to a query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vuln {
    pub id: String,
    /// Last modification time; used to refresh cached advisories.
    pub modified: String,
}

/// Asks OSV about every query. The result has one entry per query, in the
/// same order. `progress(done, total)` is called after each request batch.
///
/// If a request fails, what earlier requests found is kept and the error is
/// returned with it: a timeout on the second thousand packages must not hide
/// an advisory already found for the first. The queries that were not
/// answered have no entries.
pub fn query(queries: &[Query], progress: impl FnMut(usize, usize)) -> (Vec<Vec<Vuln>>, Option<String>) {
    query_with(queries, progress, |body| crate::net::post_json(BATCH_URL, body))
}

/// `query` with the transport injected, so tests need no network.
fn query_with(
    queries: &[Query],
    mut progress: impl FnMut(usize, usize),
    mut post: impl FnMut(&str) -> Result<String, String>,
) -> (Vec<Vec<Vuln>>, Option<String>) {
    let batches = queries.len().div_ceil(BATCH);
    let mut all = vec![Vec::new(); queries.len()];
    for (batch_index, chunk) in queries.chunks(BATCH).enumerate() {
        let results = &mut all[batch_index * BATCH..][..chunk.len()];
        if let Err(err) = query_chunk(chunk, results, &mut post) {
            return (all, Some(err));
        }
        progress(batch_index + 1, batches);
    }
    (all, None)
}

/// Asks about one batch, following page tokens, and adds what comes back to
/// `results` as it arrives.
fn query_chunk(
    chunk: &[Query],
    results: &mut [Vec<Vuln>],
    post: &mut impl FnMut(&str) -> Result<String, String>,
) -> Result<(), String> {
    // (position in the chunk, page token); the first round has no tokens.
    let mut pending: Vec<(usize, Option<String>)> = (0..chunk.len()).map(|index| (index, None)).collect();
    let mut pages = 0;
    while !pending.is_empty() {
        pages += 1;
        if pages > MAX_PAGES {
            return Err("OSV kept returning more pages; giving up".to_string());
        }
        let body = request(chunk, &pending);
        let parsed = parse_batch(&post(&body)?, pending.len())?;
        let mut next = Vec::new();
        for ((index, _), (vulns, token)) in pending.iter().zip(parsed) {
            results[*index].extend(vulns);
            // A long result list is cut off; the token asks for the rest.
            if let Some(token) = token {
                next.push((*index, Some(token)));
            }
        }
        pending = next;
    }
    Ok(())
}

fn request(chunk: &[Query], pending: &[(usize, Option<String>)]) -> String {
    let queries: Vec<Value> = pending
        .iter()
        .map(|(index, token)| {
            let query = &chunk[*index];
            let mut body = json!({
                "package": { "name": query.name, "ecosystem": query.ecosystem },
                "version": query.version,
            });
            if let Some(token) = token {
                body["page_token"] = json!(token);
            }
            body
        })
        .collect();
    json!({ "queries": queries }).to_string()
}

/// The advisories of one query and, if the list was cut off, the token that
/// asks for the rest.
type Page = (Vec<Vuln>, Option<String>);

/// Results come back in query order, one entry per query; each may carry a
/// `next_page_token`.
fn parse_batch(response: &str, expected: usize) -> Result<Vec<Page>, String> {
    let value: Value = serde_json::from_str(response).map_err(|err| format!("invalid OSV response: {err}"))?;
    let results = value
        .get("results")
        .and_then(Value::as_array)
        .ok_or("OSV response has no `results`")?;
    if results.len() != expected {
        return Err(format!("OSV returned {} results for {expected} queries", results.len()));
    }
    Ok(results
        .iter()
        .map(|result| {
            let vulns = result
                .get("vulns")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|vuln| {
                    Some(Vuln {
                        id: vuln.get("id")?.as_str()?.to_string(),
                        modified: vuln
                            .get("modified")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string(),
                    })
                })
                .collect();
            let token = result
                .get("next_page_token")
                .and_then(Value::as_str)
                .filter(|token| !token.is_empty())
                .map(str::to_string);
            (vulns, token)
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn queries() -> [Query<'static>; 3] {
        ["a", "b", "c"].map(|name| Query {
            ecosystem: "npm",
            name,
            version: "1.0.0",
        })
    }

    #[test]
    fn results_are_mapped_to_queries() {
        let response = r#"{"results": [
            {"vulns": [{"id": "GHSA-1", "modified": "2024-01-01T00:00:00Z"}, {"id": "GHSA-2"}]},
            {},
            {"vulns": [{"id": "MAL-1", "modified": "m"}]}
        ]}"#;
        let (results, error) = query_with(&queries(), |_, _| {}, |_| Ok(response.to_string()));
        assert_eq!(error, None);
        let ids: Vec<Vec<&str>> = results
            .iter()
            .map(|vulns| vulns.iter().map(|v| v.id.as_str()).collect())
            .collect();
        assert_eq!(ids, [vec!["GHSA-1", "GHSA-2"], vec![], vec!["MAL-1"]]);
        assert_eq!(results[0][0].modified, "2024-01-01T00:00:00Z");
        assert_eq!(results[0][1].modified, "");
    }

    #[test]
    fn further_pages_are_fetched_for_the_right_query() {
        let mut bodies = Vec::new();
        let (results, error) = query_with(
            &queries(),
            |_, _| {},
            |body| {
                bodies.push(body.to_string());
                Ok(match bodies.len() {
                    1 => r#"{"results": [{"vulns": [{"id": "A-1"}]}, {"vulns": [{"id": "B-1"}], "next_page_token": "t1"}, {}]}"#,
                    2 => r#"{"results": [{"vulns": [{"id": "B-2"}], "next_page_token": "t2"}]}"#,
                    _ => r#"{"results": [{"vulns": [{"id": "B-3"}]}]}"#,
                }
                .to_string())
            },
        );
        assert_eq!(error, None);
        let ids: Vec<Vec<&str>> = results
            .iter()
            .map(|vulns| vulns.iter().map(|v| v.id.as_str()).collect())
            .collect();
        assert_eq!(ids, [vec!["A-1"], vec!["B-1", "B-2", "B-3"], vec![]]);
        assert_eq!(bodies.len(), 3);
        assert!(
            bodies[1].contains(r#""name":"b""#) && bodies[1].contains(r#""page_token":"t1""#),
            "{}",
            bodies[1]
        );
        assert!(!bodies[1].contains(r#""name":"a""#));
        assert!(bodies[2].contains(r#""page_token":"t2""#));
    }

    #[test]
    fn broken_responses_are_errors() {
        let run = |response: &str| query_with(&queries(), |_, _| {}, |_| Ok(response.to_string())).1;
        assert!(run(r#"{"results": [{}]}"#).is_some(), "one result for three queries");
        assert!(run("<html>").is_some());
        // A server that keeps returning page tokens is given up on.
        let pages = |_: &str| Ok(r#"{"results": [{"next_page_token": "x"}]}"#.to_string());
        let endless = query_with(&queries()[..1], |_, _| {}, pages);
        assert_eq!(endless.1.as_deref(), Some("OSV kept returning more pages; giving up"));
        let (results, error) = query_with(&queries(), |_, _| {}, |_| Err("offline".to_string()));
        assert_eq!(error.as_deref(), Some("offline"));
        assert_eq!(results, vec![Vec::new(); 3], "one empty entry per query");
    }

    #[test]
    fn a_failed_request_keeps_what_earlier_requests_found() {
        // 1001 queries take two requests; the second one times out.
        let names: Vec<String> = (0..=BATCH).map(|index| format!("pkg-{index}")).collect();
        let many: Vec<Query> = names
            .iter()
            .map(|name| Query {
                ecosystem: "npm",
                name,
                version: "1.0.0",
            })
            .collect();
        let mut first = vec![serde_json::json!({}); BATCH];
        first[0] = serde_json::json!({"vulns": [{"id": "GHSA-1"}]});
        let first = serde_json::json!({ "results": first }).to_string();
        let mut requests = 0;
        let mut done = Vec::new();
        let (results, error) = query_with(
            &many,
            |batch, total| done.push((batch, total)),
            |_| {
                requests += 1;
                match requests {
                    1 => Ok(first.clone()),
                    _ => Err("curl: (28) Operation timed out".to_string()),
                }
            },
        );
        assert_eq!(error.as_deref(), Some("curl: (28) Operation timed out"));
        assert_eq!(results.len(), many.len(), "one entry per query, in order");
        assert_eq!(results[0][0].id, "GHSA-1");
        assert!(results[1..].iter().all(Vec::is_empty));
        assert_eq!(done, [(1, 2)], "only the answered batch is reported as done");

        // The same within one batch: the first page is kept when the next fails.
        let mut requests = 0;
        let post = |_: &str| {
            requests += 1;
            match requests {
                1 => Ok(r#"{"results": [{"vulns": [{"id": "A-1"}], "next_page_token": "t"}, {}, {}]}"#.to_string()),
                _ => Err("HTTP 503".to_string()),
            }
        };
        let (results, error) = query_with(&queries(), |_, _| {}, post);
        assert_eq!(error.as_deref(), Some("HTTP 503"));
        assert_eq!(results[0][0].id, "A-1");
    }
}
