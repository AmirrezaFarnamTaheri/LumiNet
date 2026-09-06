//! Deterministic, explainable candidate scoring.
//!
//! package, semantics preserved): rank candidates with a stable weighted score,
//! never mutate caller state, and break ties by ascending identifier so the
//! same inputs always produce the same decision.
//!
//! Weights: priority×100 + weight + success_rate×100 + active bonus(15)
//!          − latency/100 penalty − consecutive_failures×25 penalty.
//! Unknown latency defaults to 500 ms (the upstream neutral assumption) and an
//! empty observation history yields a neutral 0.5 success rate.

/// One scored candidate as produced by [`evaluate`].
#[derive(Debug, Clone, PartialEq)]
pub struct ScoreBreakdown {
    pub priority_score: f64,
    pub weight_score: f64,
    pub reliability_score: f64,
    pub active_bonus: f64,
    pub latency_penalty: f64,
    pub failure_penalty: f64,
    pub total: f64,
}

/// Input describing one candidate. Callers translate their domain state into
/// these plain numbers; the scorer stays domain-agnostic.
#[derive(Debug, Clone, Default)]
pub struct Candidate {
    pub id: String,
    pub priority: i64,
    pub weight: f64,
    pub active: bool,
    pub success_count: u64,
    pub failure_count: u64,
    /// Average observed latency in milliseconds; `None` means unknown.
    pub average_latency_ms: Option<i64>,
    pub consecutive_failures: i64,
}

/// Why a candidate was excluded from selection.
#[derive(Debug, Clone, PartialEq)]
pub struct Exclusion {
    pub reason: String,
}

/// Result of scoring one candidate.
#[derive(Debug, Clone)]
pub struct Evaluation {
    pub id: String,
    pub eligible: bool,
    pub exclusion: Option<Exclusion>,
    pub success_rate: f64,
    pub breakdown: Option<ScoreBreakdown>,
}

/// The full deterministic decision.
#[derive(Debug, Clone)]
pub struct Decision {
    pub evaluations: Vec<Evaluation>,
    /// Index into `evaluations` of the highest-scoring eligible candidate.
    pub selected: Option<usize>,
}

const ACTIVE_BONUS: f64 = 15.0;
const NEUTRAL_SUCCESS_RATE: f64 = 0.5;
const DEFAULT_LATENCY_MS: i64 = 500;
const FAILURE_PENALTY_PER: f64 = 25.0;
const LATENCY_PENALTY_DIVISOR: f64 = 100.0;

fn success_rate(successes: u64, failures: u64) -> f64 {
    let total = successes.saturating_add(failures);
    if total == 0 {
        NEUTRAL_SUCCESS_RATE
    } else {
        successes as f64 / total as f64
    }
}

/// Scores and ranks candidates. Ineligible candidates keep their exclusion
/// reason and sort after eligible ones; equal scores tie-break by id.
pub fn decide(candidates: &[Candidate]) -> Decision {
    let mut evaluations: Vec<Evaluation> = candidates
        .iter()
        .map(|c| {
            let rate = success_rate(c.success_count, c.failure_count);
            if !c.active {
                return Evaluation {
                    id: c.id.clone(),
                    eligible: false,
                    exclusion: Some(Exclusion { reason: "candidate is disabled".into() }),
                    success_rate: rate,
                    breakdown: None,
                };
            }
            if c.consecutive_failures < 0 {
                return Evaluation {
                    id: c.id.clone(),
                    eligible: false,
                    exclusion: Some(Exclusion { reason: "invalid negative failure count".into() }),
                    success_rate: rate,
                    breakdown: None,
                };
            }
            let priority_score = c.priority as f64 * 100.0;
            let weight_score = c.weight;
            let reliability_score = rate * 100.0;
            let active_bonus = ACTIVE_BONUS;
            let latency_penalty =
                c.average_latency_ms.unwrap_or(DEFAULT_LATENCY_MS).max(0) as f64 / LATENCY_PENALTY_DIVISOR;
            let failure_penalty = c.consecutive_failures as f64 * FAILURE_PENALTY_PER;
            let total = priority_score
                + weight_score
                + reliability_score
                + active_bonus
                - latency_penalty
                - failure_penalty;
            Evaluation {
                id: c.id.clone(),
                eligible: true,
                exclusion: None,
                success_rate: rate,
                breakdown: Some(ScoreBreakdown {
                    priority_score,
                    weight_score,
                    reliability_score,
                    active_bonus,
                    latency_penalty,
                    failure_penalty,
                    total,
                }),
            }
        })
        .collect();

    evaluations.sort_by(|left, right| {
        let ls = left.breakdown.as_ref().map(|b| b.total);
        let rs = right.breakdown.as_ref().map(|b| b.total);
        rs.partial_cmp(&ls)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| left.id.cmp(&right.id))
    });

    let selected = evaluations.iter().position(|e| e.eligible);
    Decision { evaluations, selected }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(id: &str, priority: i64) -> Candidate {
        Candidate { id: id.into(), priority, active: true, ..Default::default() }
    }

    #[test]
    fn ranks_by_total_and_ties_break_by_id() {
        let mut a = candidate("a", 1);
        a.weight = 10.0;
        let mut b = candidate("b", 1);
        b.weight = 10.0;
        let d = decide(&[a, b]);
        // identical scores → ascending id wins
        assert_eq!(d.selected, Some(0));
        assert_eq!(d.evaluations[0].id, "a");
        assert_eq!(d.evaluations[1].id, "b");
    }

    #[test]
    fn higher_priority_wins() {
        let d = decide(&[candidate("low", 1), candidate("high", 5)]);
        assert_eq!(d.evaluations[d.selected.unwrap()].id, "high");
    }

    #[test]
    fn disabled_candidates_are_excluded_but_kept_in_report() {
        let mut off = candidate("off", 9);
        off.active = false;
        let d = decide(&[off, candidate("on", 1)]);
        // eligible candidate wins selection; the excluded one stays visible
        assert_eq!(d.selected, Some(0));
        assert_eq!(d.evaluations[d.selected.unwrap()].id, "on");
        assert!(!d.evaluations[1].eligible);
        assert_eq!(
            d.evaluations[1].exclusion.as_ref().unwrap().reason,
            "candidate is disabled"
        );
    }

    #[test]
    fn neutral_success_rate_without_history() {
        let d = decide(&[candidate("solo", 1)]);
        assert!((d.evaluations[0].success_rate - 0.5).abs() < 1e-9);
    }

    #[test]
    fn failure_penalty_drops_candidate_below_fresh_peer() {
        let mut failing = candidate("failing", 1);
        failing.consecutive_failures = 2;
        let fresh = candidate("fresh", 1);
        let d = decide(&[failing, fresh]);
        assert_eq!(d.evaluations[d.selected.unwrap()].id, "fresh");
    }

    #[test]
    fn all_disabled_yields_no_selection() {
        let mut off = candidate("only", 1);
        off.active = false;
        let d = decide(&[off]);
        assert!(d.selected.is_none());
    }
}
