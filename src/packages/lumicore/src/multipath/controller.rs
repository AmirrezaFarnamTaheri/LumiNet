//! Multipath Adaptive Path Controller
//!
//! Ported and unified from `XPlex-main` (`internal/mpadapt`).
//! Dynamically classifies parallel proxy tunnel paths into Active or Shadow
//! roles using win-rate hysteresis, demoting lagging tunnels and promoting responsive ones.

use std::collections::HashMap;

/// Path operational classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathState {
    Active,
    Shadow,
}

pub type PathClassification = PathState;

/// Dynamic path score and telemetry counters.
#[derive(Debug, Clone)]
pub struct PathStats {
    pub path_id: String,
    pub state: PathState,
    pub wins: u64,
    pub total_frames: u64,
}

impl PathStats {
    pub fn new(path_id: impl Into<String>, initial_state: PathState) -> Self {
        Self {
            path_id: path_id.into(),
            state: initial_state,
            wins: 0,
            total_frames: 0,
        }
    }

    /// Calculates the win rate as a fraction between 0.0 and 1.0.
    pub fn win_rate(&self) -> f64 {
        if self.total_frames == 0 {
            0.0
        } else {
            self.wins as f64 / self.total_frames as f64
        }
    }
}

/// Transition event emitted during an evaluation tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControllerTransition {
    Promoted { path_id: String },
    Demoted { path_id: String },
}

/// Tuning parameters for the adaptive multipath controller.
#[derive(Debug, Clone)]
pub struct AdaptiveConfig {
    pub min_active: usize,
    pub max_active: usize,
    pub demote_threshold: f64,
    pub promote_margin: f64,
    pub min_frames: u64,
}

impl Default for AdaptiveConfig {
    fn default() -> Self {
        Self {
            min_active: 2,
            max_active: 4,
            demote_threshold: 0.05,
            promote_margin: 0.10,
            min_frames: 20,
        }
    }
}

/// Hysteresis-aware controller managing multiple concurrent tunnel paths.
pub struct AdaptiveController {
    config: AdaptiveConfig,
    paths: HashMap<String, PathStats>,
}

impl AdaptiveController {
    pub fn new(config: AdaptiveConfig) -> Self {
        Self {
            config,
            paths: HashMap::new(),
        }
    }

    /// Registers a new tunnel path. New tunnels start in Active state.
    pub fn register_path(&mut self, path_id: impl Into<String>) {
        let id = path_id.into();
        self.paths
            .insert(id.clone(), PathStats::new(id, PathState::Active));
    }

    /// Records that this path was the first to deliver a given sequence frame (a win).
    pub fn record_win(&mut self, path_id: &str) {
        if let Some(stats) = self.paths.get_mut(path_id) {
            stats.wins += 1;
            stats.total_frames += 1;
        }
    }

    /// Records that a frame arrived via this path (without being first).
    pub fn record_frame(&mut self, path_id: &str) {
        if let Some(stats) = self.paths.get_mut(path_id) {
            stats.total_frames += 1;
        }
    }

    /// Evaluates paths and returns at most one transition per tick to avoid thrashing.
    pub fn evaluate_tick(&mut self) -> Option<ControllerTransition> {
        let active_count = self
            .paths
            .values()
            .filter(|p| p.state == PathState::Active)
            .count();

        // 1. Check if we need to promote a shadow path because active count is below min_active
        if active_count < self.config.min_active {
            if let Some(shadow) = self
                .paths
                .values_mut()
                .filter(|p| p.state == PathState::Shadow)
                .max_by(|a, b| {
                    a.win_rate()
                        .partial_cmp(&b.win_rate())
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
            {
                shadow.state = PathState::Active;
                return Some(ControllerTransition::Promoted {
                    path_id: shadow.path_id.clone(),
                });
            }
        }

        // 2. Check for demotions: if active_count > min_active and an active has win_rate < demote_threshold
        if active_count > self.config.min_active {
            let mut demote_candidate: Option<String> = None;
            for stats in self.paths.values() {
                if stats.state == PathState::Active
                    && stats.total_frames >= self.config.min_frames
                    && stats.win_rate() < self.config.demote_threshold
                {
                    demote_candidate = Some(stats.path_id.clone());
                    break;
                }
            }

            if let Some(path_id) = demote_candidate {
                if let Some(stats) = self.paths.get_mut(&path_id) {
                    stats.state = PathState::Shadow;
                    return Some(ControllerTransition::Demoted { path_id });
                }
            }
        }

        // 3. Check for promotions: shadow outperforms worst active by promote_margin
        let worst_active = self
            .paths
            .values()
            .filter(|p| p.state == PathState::Active && p.total_frames >= self.config.min_frames)
            .min_by(|a, b| {
                a.win_rate()
                    .partial_cmp(&b.win_rate())
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|p| (p.path_id.clone(), p.win_rate()));

        let best_shadow = self
            .paths
            .values()
            .filter(|p| p.state == PathState::Shadow && p.total_frames >= self.config.min_frames)
            .max_by(|a, b| {
                a.win_rate()
                    .partial_cmp(&b.win_rate())
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|p| (p.path_id.clone(), p.win_rate()));

        if let (Some((_worst_id, worst_rate)), Some((best_id, best_rate))) =
            (worst_active, best_shadow)
        {
            if best_rate > worst_rate + self.config.promote_margin
                && active_count < self.config.max_active
            {
                if let Some(stats) = self.paths.get_mut(&best_id) {
                    stats.state = PathState::Active;
                    return Some(ControllerTransition::Promoted {
                        path_id: stats.path_id.clone(),
                    });
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_controller_demote_lagging_active() {
        let mut ctrl = AdaptiveController::new(AdaptiveConfig {
            min_active: 1,
            max_active: 3,
            demote_threshold: 0.05,
            promote_margin: 0.10,
            min_frames: 20,
        });

        ctrl.register_path("path_fast");
        ctrl.register_path("path_slow");

        // Simulate 25 frames
        for _ in 0..25 {
            ctrl.record_win("path_fast");
            ctrl.record_frame("path_slow");
        }

        let transition = ctrl.evaluate_tick();
        assert_eq!(
            transition,
            Some(ControllerTransition::Demoted {
                path_id: "path_slow".to_string()
            })
        );
    }
}
