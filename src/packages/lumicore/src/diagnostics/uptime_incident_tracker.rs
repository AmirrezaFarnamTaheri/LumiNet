//! SLA Health Check and Uptime Incident Tracker
//!
//! Tracks service endpoint heartbeat availability, records downtime incidents,
//! and computes operational uptime percentage across rolling intervals.

use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct IncidentRecord {
    pub endpoint: String,
    pub started_at_unix: u64,
    pub resolved_at_unix: Option<u64>,
    pub reason: String,
}

#[derive(Debug, Default)]
pub struct UptimeIncidentTracker {
    checks: HashMap<String, (u64, u64)>, // endpoint -> (total_checks, successful_checks)
    active_incidents: HashMap<String, IncidentRecord>,
    incident_history: Vec<IncidentRecord>,
}

impl UptimeIncidentTracker {
    pub fn new() -> Self {
        Self {
            checks: HashMap::new(),
            active_incidents: HashMap::new(),
            incident_history: Vec::new(),
        }
    }

    pub fn record_heartbeat(&mut self, endpoint: &str, success: bool, now_unix: u64, reason: &str) {
        let entry = self.checks.entry(endpoint.to_string()).or_insert((0, 0));
        entry.0 += 1;
        if success {
            entry.1 += 1;
            if let Some(mut incident) = self.active_incidents.remove(endpoint) {
                incident.resolved_at_unix = Some(now_unix);
                self.incident_history.push(incident);
            }
        } else {
            if !self.active_incidents.contains_key(endpoint) {
                self.active_incidents.insert(
                    endpoint.to_string(),
                    IncidentRecord {
                        endpoint: endpoint.to_string(),
                        started_at_unix: now_unix,
                        resolved_at_unix: None,
                        reason: reason.to_string(),
                    },
                );
            }
        }
    }

    pub fn uptime_percentage(&self, endpoint: &str) -> f64 {
        if let Some(&(total, succ)) = self.checks.get(endpoint) {
            if total > 0 {
                (succ as f64 / total as f64) * 100.0
            } else {
                100.0
            }
        } else {
            100.0
        }
    }

    pub fn is_operational(&self, endpoint: &str) -> bool {
        !self.active_incidents.contains_key(endpoint)
    }

    pub fn active_incident_count(&self) -> usize {
        self.active_incidents.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uptime_incident_tracking() {
        let mut tracker = UptimeIncidentTracker::new();
        tracker.record_heartbeat("edge-relay-1", true, 100, "");
        tracker.record_heartbeat("edge-relay-1", true, 110, "");
        tracker.record_heartbeat("edge-relay-1", false, 120, "Connection timeout");

        assert!(!tracker.is_operational("edge-relay-1"));
        assert_eq!(tracker.active_incident_count(), 1);

        tracker.record_heartbeat("edge-relay-1", true, 130, "");
        assert!(tracker.is_operational("edge-relay-1"));
        assert_eq!(tracker.active_incident_count(), 0);

        let pct = tracker.uptime_percentage("edge-relay-1");
        assert!((pct - 75.0).abs() < 0.01);
    }
}
