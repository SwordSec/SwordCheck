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
pub fn query(queries: &[Query], progress: impl FnMut(usize, usize)) -> Result<Vec<Vec<Vuln>>, String> {
    query_with(queries, progress, |body| crate::net::post_json(BATCH_URL, body))
}

/// `query` with the transport injected, so tests need no network.
fn query_with(
    queries: &[Query],
    mut progress: impl FnMut(usize, usize),
    mut post: impl FnMut(&str) -> Result<String, String>,
) -> Result<Vec<Vec<Vuln>>, String> {
    let batches = queries.len().div_ceil(BATCH);
    let mut all = Vec::with_capacity(queries.len());
    for (batch_index, chunk) in queries.chunks(BATCH).enumerate() {
        let mut results: Vec<Vec<Vuln>> = vec![Vec::new(); chunk.len()];
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
        all.extend(results);
        progress(batch_index + 1, batches);
    }
    Ok(all)
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
        let results = query_with(&queries(), |_, _| {}, |_| Ok(response.to_string())).unwrap();
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
        let results = query_with(
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
        )
        .unwrap();
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
        let run = |response: &str| query_with(&queries(), |_, _| {}, |_| Ok(response.to_string()));
        assert!(run(r#"{"results": [{}]}"#).is_err(), "one result for three queries");
        assert!(run("<html>").is_err());
        assert!(
            run(r#"{"results": [{"next_page_token": "x"}, {}, {}]}"#).is_err(),
            "endless pages"
        );
        assert!(query_with(&queries(), |_, _| {}, |_| Err("offline".to_string())).is_err());
    }
}
