//! Score and grade calculation.

use crate::checks::{CheckResult, Status};
use serde::Serialize;

/// The score reported when no check could be scored.
///
/// A run in which every check is Unknown or exempt found no weakness, so it
/// must not look like a failing score (0 / grade F) nor trip `--min-score`.
/// Callers that want to show "n/a" instead can use `score_if_scorable`.
pub const NOTHING_SCORABLE: u32 = 100;

/// Calculates the weighted score (0-100).
///
/// Pass = full points, Warn = half points, Fail = 0 points.
/// Unknown and exempted checks are left out of the denominator, so a state
/// that could not be determined or was knowingly accepted does not lower the
/// score. If that leaves nothing to score, `NOTHING_SCORABLE` is returned.
pub fn calculate_score(results: &[CheckResult]) -> u32 {
    score_if_scorable(results).unwrap_or(NOTHING_SCORABLE)
}

/// Like `calculate_score`, but `None` when there is nothing to score: every
/// check is Unknown, exempt or has weight 0 (or the list is empty).
pub fn score_if_scorable(results: &[CheckResult]) -> Option<u32> {
    // u64 with saturating arithmetic: no combination of weights can overflow.
    let mut earned: u64 = 0;
    let mut possible: u64 = 0;

    for result in results.iter().filter(|result| result.exempt.is_none()) {
        // We multiply everything by 2 so half points stay integers.
        let full = u64::from(result.weight).saturating_mul(2);
        match result.status {
            Status::Pass => {
                earned = earned.saturating_add(full);
                possible = possible.saturating_add(full);
            }
            Status::Warn => {
                earned = earned.saturating_add(u64::from(result.weight));
                possible = possible.saturating_add(full);
            }
            Status::Fail => possible = possible.saturating_add(full),
            Status::Unknown => {}
        }
    }

    if possible == 0 {
        return None;
    }
    // `earned <= possible`, so the quotient is at most 100; the product is
    // computed in u128 so it cannot overflow either.
    let score = u128::from(earned) * 100 / u128::from(possible);
    Some(u32::try_from(score).unwrap_or(100))
}

/// The letter grade for a score.
pub fn grade(score: u32) -> &'static str {
    match score {
        90.. => "A",
        75..=89 => "B",
        60..=74 => "C",
        40..=59 => "D",
        _ => "F",
    }
}

/// Check counts by status.
#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub struct Summary {
    pub pass: usize,
    pub warn: usize,
    pub fail: usize,
    pub unknown: usize,
    pub exempt: usize,
}

impl Summary {
    pub fn from_results(results: &[CheckResult]) -> Self {
        let mut summary = Self::default();
        for result in results {
            if result.exempt.is_some() {
                summary.exempt += 1;
                continue;
            }
            match result.status {
                Status::Pass => summary.pass += 1,
                Status::Warn => summary.warn += 1,
                Status::Fail => summary.fail += 1,
                Status::Unknown => summary.unknown += 1,
            }
        }
        summary
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::checks::Severity;

    /// Short result builder used in tests (other modules use it too).
    pub fn result(id: &'static str, status: Status, weight: u32) -> CheckResult {
        CheckResult {
            id,
            name: id,
            status,
            severity: Severity::Medium,
            weight,
            cis: None,
            detail: format!("{id} detail"),
            advice: "advice",
            exempt: None,
            fix: None,
        }
    }

    #[test]
    fn all_passing_scores_hundred() {
        let results = [result("a", Status::Pass, 25), result("b", Status::Pass, 10)];
        assert_eq!(calculate_score(&results), 100);
    }

    #[test]
    fn warn_is_half_points_fail_is_zero() {
        let results = [
            result("a", Status::Pass, 50),
            result("b", Status::Warn, 30),
            result("c", Status::Fail, 20),
        ];
        // 50 + 15 + 0 = 65
        assert_eq!(calculate_score(&results), 65);
    }

    #[test]
    fn odd_weight_warn_has_no_rounding_error() {
        // The old calculation said 5 / 2 = 2, understating the score.
        let results = [result("a", Status::Warn, 5)];
        assert_eq!(calculate_score(&results), 50);
    }

    #[test]
    fn unknown_and_exempt_stay_out_of_denominator() {
        let mut exempt = result("c", Status::Fail, 50);
        exempt.exempt = Some("reason".into());
        let results = [result("a", Status::Pass, 10), result("b", Status::Unknown, 90), exempt];
        assert_eq!(calculate_score(&results), 100);
    }

    #[test]
    fn nothing_scorable_is_not_a_failing_score() {
        // Empty list: no division by zero, and no grade F.
        assert_eq!(score_if_scorable(&[]), None);
        assert_eq!(calculate_score(&[]), NOTHING_SCORABLE);

        // `--only airdrop` on a machine where the check is Unknown.
        let unknown = [result("airdrop", Status::Unknown, 5)];
        assert_eq!(score_if_scorable(&unknown), None);
        assert!(calculate_score(&unknown) >= 1, "must satisfy --min-score 1");
        assert_ne!(grade(calculate_score(&unknown)), "F");

        // Everything exempt.
        let mut exempt = result("ssh", Status::Fail, 10);
        exempt.exempt = Some("reason".into());
        assert_eq!(score_if_scorable(&[exempt]), None);

        // A real failure is still a zero.
        let failing = [result("a", Status::Fail, 10), result("b", Status::Unknown, 5)];
        assert_eq!(score_if_scorable(&failing), Some(0));
        assert_eq!(calculate_score(&failing), 0);
    }

    #[test]
    fn huge_weights_do_not_overflow() {
        // The configuration rejects these, but the arithmetic must hold anyway.
        let results = [
            result("a", Status::Pass, u32::MAX),
            result("b", Status::Warn, u32::MAX),
            result("c", Status::Fail, 1 << 31),
        ];
        // earned = 3 * MAX, possible = 4 * MAX + 2^32: just under 60 %.
        assert_eq!(calculate_score(&results), 59);

        let zero_weight = [result("a", Status::Fail, 0)];
        assert_eq!(score_if_scorable(&zero_weight), None);
    }

    #[test]
    fn letter_grades() {
        assert_eq!(grade(100), "A");
        assert_eq!(grade(90), "A");
        assert_eq!(grade(89), "B");
        assert_eq!(grade(60), "C");
        assert_eq!(grade(59), "D");
        assert_eq!(grade(0), "F");
    }

    #[test]
    fn summary_counts() {
        let mut exempt = result("d", Status::Warn, 5);
        exempt.exempt = Some("reason".into());
        let results = [
            result("a", Status::Pass, 1),
            result("b", Status::Fail, 1),
            result("c", Status::Unknown, 1),
            exempt,
        ];
        assert_eq!(
            Summary::from_results(&results),
            Summary {
                pass: 1,
                warn: 0,
                fail: 1,
                unknown: 1,
                exempt: 1
            }
        );
    }
}
