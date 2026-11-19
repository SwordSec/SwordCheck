//! Score and grade calculation.

use crate::checks::{CheckResult, Status};
use serde::Serialize;

/// Calculates the weighted score (0-100).
///
/// Pass = full points, Warn = half points, Fail = 0 points.
/// Unknown and exempted checks are left out of the denominator, so a state
/// that could not be determined or was knowingly accepted does not lower the
/// score.
pub fn calculate_score(results: &[CheckResult]) -> u32 {
    let mut earned: u32 = 0;
    let mut possible: u32 = 0;

    for result in results.iter().filter(|result| result.exempt.is_none()) {
        match result.status {
            Status::Pass => {
                // We multiply everything by 2 so half points stay integers.
                earned += result.weight * 2;
                possible += result.weight * 2;
            }
            Status::Warn => {
                earned += result.weight;
                possible += result.weight * 2;
            }
            Status::Fail => possible += result.weight * 2,
            Status::Unknown => {}
        }
    }

    // If `possible` is zero, `earned` is zero too; max(1) prevents division by zero.
    earned * 100 / possible.max(1)
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
        let results = [
            result("a", Status::Pass, 10),
            result("b", Status::Unknown, 90),
            exempt,
        ];
        assert_eq!(calculate_score(&results), 100);
    }

    #[test]
    fn empty_list_does_not_divide_by_zero() {
        assert_eq!(calculate_score(&[]), 0);
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
