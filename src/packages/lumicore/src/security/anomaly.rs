//! # Security Anomaly Detection Engine
//!
//! Evaluates login attempts for suspicious behaviors:
//! - R1: New IP address not seen in history
//! - R2: New device type
//! - R3: New browser family
//! - R4: New operating-system family
//! - R5: Login during unusual hours (e.g., 00:00–04:59 UTC)
//! - R6: Rapid multiple logins in short window
//! - R7: Impossible travel (geographic velocity > threshold km/h)
//! - R8: VPN / Proxy detection
//! - R9: Automated/Bot user-agent signature matching
//!
//! Also handles brute-force source tracking and account lockouts.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

/// Geological coordinates
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct GeoLocation {
    pub latitude: f64,
    pub longitude: f64,
}

/// Login historical entry details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRecord {
    pub ip_address: String,
    pub device_type: String,
    pub browser: String,
    pub os: String,
    pub user_agent: String,
    pub timestamp_sec: u64,
    pub location: Option<GeoLocation>,
    pub is_vpn: bool,
}

/// Anomaly scoring result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyScore {
    pub risk_score: u32,
    pub reasons: Vec<String>,
    pub is_suspicious: bool,
}

/// Detection rules configurations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionConfig {
    pub max_failed_attempts: u32,
    pub failed_attempt_window_sec: u64,
    pub rapid_login_count: u32,
    pub rapid_login_window_sec: u64,
    pub unusual_hour_start: u32,
    pub unusual_hour_end: u32,
    pub history_lookup_limit: usize,
    pub lockout_duration_sec: u64,
    pub impossible_travel_speed_kph: f64, // km/h threshold (default 900)
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            max_failed_attempts: 3,
            failed_attempt_window_sec: 1800, // 30 mins
            rapid_login_count: 3,
            rapid_login_window_sec: 600, // 10 mins
            unusual_hour_start: 0,       // 00:00 UTC
            unusual_hour_end: 5,         // 05:00 UTC
            history_lookup_limit: 50,
            lockout_duration_sec: 1800, // 30 mins
            impossible_travel_speed_kph: 900.0,
        }
    }
}

/// State storage for brute-force source tracking
#[derive(Debug, Default)]
pub struct LockoutTracker {
    failed_attempts: HashMap<String, Vec<u64>>, // maps username/IP -> timestamps
    locked_until: HashMap<String, u64>,         // maps username/IP -> lockout expiry
}

impl LockoutTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Logs a failed login attempt. Returns true if it triggers a new lockout.
    pub fn register_fail(&mut self, key: &str, now: u64, config: &DetectionConfig) -> bool {
        if self.is_locked(key, now) {
            return false;
        }

        let attempts = self.failed_attempts.entry(key.to_string()).or_default();
        attempts.push(now);

        // Filter old attempts outside the window
        let window_start = now.saturating_sub(config.failed_attempt_window_sec);
        attempts.retain(|&ts| ts >= window_start);

        if attempts.len() >= config.max_failed_attempts as usize {
            let unlock_time = now + config.lockout_duration_sec;
            self.locked_until.insert(key.to_string(), unlock_time);
            return true;
        }
        false
    }

    /// Checks if a key is currently locked out
    pub fn is_locked(&self, key: &str, now: u64) -> bool {
        if let Some(&locked_until) = self.locked_until.get(key) {
            if now < locked_until {
                return true;
            }
        }
        false
    }

    /// Resets failed attempt history upon successful sign-in
    pub fn clear(&mut self, key: &str) {
        self.failed_attempts.remove(key);
        self.locked_until.remove(key);
    }
}

/// The anomaly detection engine
pub struct AnomalyDetector<'a> {
    config: &'a DetectionConfig,
}

impl<'a> AnomalyDetector<'a> {
    pub fn new(config: &'a DetectionConfig) -> Self {
        Self { config }
    }

    /// Evaluates current login record against user history
    pub fn analyze(&self, current: &LoginRecord, history: &[LoginRecord]) -> AnomalyScore {
        let mut reasons = Vec::new();
        let mut risk_score = 0;

        if !history.is_empty() {
            // R1: New IP Address
            let known_ips: HashSet<&str> = history.iter().map(|r| r.ip_address.as_str()).collect();
            if !known_ips.contains(current.ip_address.as_str()) {
                reasons.push(format!("New IP address: {}", current.ip_address));
                risk_score += 20;
            }

            // R2: New Device Type
            let known_devices: HashSet<&str> =
                history.iter().map(|r| r.device_type.as_str()).collect();
            if !current.device_type.is_empty()
                && !known_devices.contains(current.device_type.as_str())
            {
                reasons.push(format!("New device type: {}", current.device_type));
                risk_score += 15;
            }

            // R3: New Browser
            let known_browsers: HashSet<String> = history
                .iter()
                .map(|r| self.get_family(&r.browser))
                .collect();
            let current_browser_fam = self.get_family(&current.browser);
            if !current_browser_fam.is_empty() && !known_browsers.contains(&current_browser_fam) {
                reasons.push(format!("New browser family: {}", current.browser));
                risk_score += 10;
            }

            // R4: New OS
            let known_os: HashSet<String> =
                history.iter().map(|r| self.get_family(&r.os)).collect();
            let current_os_fam = self.get_family(&current.os);
            if !current_os_fam.is_empty() && !known_os.contains(&current_os_fam) {
                reasons.push(format!("New operating system: {}", current.os));
                risk_score += 10;
            }

            // R6: Rapid Multiple Logins
            let since = current
                .timestamp_sec
                .saturating_sub(self.config.rapid_login_window_sec);
            let rapid_logins = history.iter().filter(|r| r.timestamp_sec >= since).count();
            if rapid_logins >= self.config.rapid_login_count as usize {
                reasons.push(format!(
                    "Multiple logins in short period: {} successful logins in the last {} minutes",
                    rapid_logins,
                    self.config.rapid_login_window_sec / 60
                ));
                risk_score += 25;
            }

            // R7: Impossible Travel Velocity
            if let Some(current_loc) = current.location {
                // Compare only with the most recent geolocation-enabled record
                let last_geo = history
                    .iter()
                    .filter_map(|r| r.location.map(|loc| (loc, r.timestamp_sec)))
                    .next();

                if let Some((prev_loc, prev_time)) = last_geo {
                    if current.timestamp_sec > prev_time {
                        let diff_sec = current.timestamp_sec - prev_time;
                        let hours = diff_sec as f64 / 3600.0;
                        if hours > 0.25 {
                            // Skip small fluctuations (15 mins threshold)
                            let dist_km = self.haversine(prev_loc, current_loc);
                            let velocity = dist_km / hours;
                            if velocity > self.config.impossible_travel_speed_kph {
                                reasons.push(format!(
                                    "Impossible travel: {:.0} km in {:.1} h ({:.0} km/h) from previous login location",
                                    dist_km, hours, velocity
                                ));
                                risk_score += 45;
                            }
                        }
                    }
                }
            }
        }

        // R5: Unusual Hour (always run)
        let utc_hour = self.get_utc_hour(current.timestamp_sec);
        if utc_hour >= self.config.unusual_hour_start && utc_hour < self.config.unusual_hour_end {
            reasons.push(format!(
                "Login during unusual hours: {:02}:00 UTC (between {:02}:00 and {:02}:00)",
                utc_hour, self.config.unusual_hour_start, self.config.unusual_hour_end
            ));
            risk_score += 15;
        }

        // R8: VPN / Proxy Connection
        if current.is_vpn {
            reasons.push(
                "VPN / proxy / TOR exit node detected: login may be masking true location"
                    .to_string(),
            );
            risk_score += 30;
        }

        // R9: Automated/Bot User Agent Signature
        if self.is_bot(&current.user_agent) {
            reasons.push(
                "Automated client detected: user agent matches bot/script signature pattern"
                    .to_string(),
            );
            risk_score += 35;
        }

        let is_suspicious = risk_score > 30;

        AnomalyScore {
            risk_score: risk_score.min(100),
            reasons,
            is_suspicious,
        }
    }

    /// Extract the primary software family name
    fn get_family(&self, val: &str) -> String {
        val.split_whitespace().next().unwrap_or("").to_lowercase()
    }

    /// Calculate the great-circle distance between coordinates via the Haversine formula
    fn haversine(&self, loc1: GeoLocation, loc2: GeoLocation) -> f64 {
        let r = 6371.0; // Earth mean radius in km
        let d_lat = (loc2.latitude - loc1.latitude).to_radians();
        let d_lon = (loc2.longitude - loc1.longitude).to_radians();

        let a = (d_lat / 2.0).sin().powi(2)
            + loc1.latitude.to_radians().cos()
                * loc2.latitude.to_radians().cos()
                * (d_lon / 2.0).sin().powi(2);

        let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());
        r * c
    }

    /// Extract the hour field from an epoch timestamp
    fn get_utc_hour(&self, timestamp_sec: u64) -> u32 {
        let seconds_in_day = timestamp_sec % 86400;
        let hour = seconds_in_day / 3600;
        hour as u32
    }

    /// Inspect User Agent patterns matching scripting languages or browsers automation frameworks
    fn is_bot(&self, ua: &str) -> bool {
        let ua_lower = ua.to_lowercase();
        let bot_signatures = [
            "headlesschrome",
            "phantomjs",
            "selenium",
            "webdriver",
            "python-requests",
            "python-urllib",
            "curl/",
            "wget/",
            "scrapy",
            "httpx",
            "aiohttp",
            "go-http-client",
            "libwww-perl",
            "lwp-trivial",
            "java/1.",
        ];

        for sig in bot_signatures.iter() {
            if ua_lower.contains(sig) {
                return true;
            }
        }
        false
    }
}

/// Helper: returns the current system time in seconds
pub fn current_time_sec() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_haversine() {
        let config = DetectionConfig::default();
        let detector = AnomalyDetector::new(&config);
        // Paris coordinates
        let paris = GeoLocation {
            latitude: 48.8566,
            longitude: 2.3522,
        };
        // London coordinates
        let london = GeoLocation {
            latitude: 51.5074,
            longitude: -0.1278,
        };

        let distance = detector.haversine(paris, london);
        // Approximately 344 km
        assert!((distance - 344.0).abs() < 5.0);
    }

    #[test]
    fn test_lockout_tracker() {
        let config = DetectionConfig::default();
        let mut tracker = LockoutTracker::new();
        let key = "admin_user";

        assert!(!tracker.is_locked(key, 1000));
        // Register three failed attempts
        assert!(!tracker.register_fail(key, 1000, &config));
        assert!(!tracker.register_fail(key, 1010, &config));
        // The third attempt triggers lockout
        assert!(tracker.register_fail(key, 1020, &config));

        assert!(tracker.is_locked(key, 1025));
        // Lockout expired after 30 minutes (1800s)
        assert!(!tracker.is_locked(key, 1020 + 1801));
    }

    #[test]
    fn test_anomaly_check() {
        let config = DetectionConfig::default();
        let detector = AnomalyDetector::new(&config);

        let history = vec![LoginRecord {
            ip_address: "192.168.1.50".to_string(),
            device_type: "PC".to_string(),
            browser: "Chrome 120".to_string(),
            os: "Windows 11".to_string(),
            user_agent: "Mozilla/5.0 Chrome/120".to_string(),
            timestamp_sec: 1700000000,
            location: Some(GeoLocation {
                latitude: 40.7128,
                longitude: -74.0060,
            }), // New York
            is_vpn: false,
        }];

        // Normal login attempt matching history
        let normal = LoginRecord {
            ip_address: "192.168.1.50".to_string(),
            device_type: "PC".to_string(),
            browser: "Chrome 120".to_string(),
            os: "Windows 11".to_string(),
            user_agent: "Mozilla/5.0 Chrome/120".to_string(),
            timestamp_sec: 1700036000, // 10 hours later, 08:13 UTC (normal hour)
            location: Some(GeoLocation {
                latitude: 40.7128,
                longitude: -74.0060,
            }),
            is_vpn: false,
        };

        let res = detector.analyze(&normal, &history);
        assert!(!res.is_suspicious);
        assert_eq!(res.risk_score, 0);

        // Anomaly: Impossible travel velocity (sign-in from Tokyo 1 hour later)
        let anomaly = LoginRecord {
            ip_address: "10.0.0.1".to_string(), // New IP (+20)
            device_type: "PC".to_string(),
            browser: "Chrome 120".to_string(),
            os: "Windows 11".to_string(),
            user_agent: "Mozilla/5.0 Chrome/120".to_string(),
            timestamp_sec: 1700003600, // 1 hour later
            location: Some(GeoLocation {
                latitude: 35.6762,
                longitude: 139.6503,
            }), // Tokyo
            is_vpn: false,
        };

        let res = detector.analyze(&anomaly, &history);
        assert!(res.is_suspicious);
        assert!(res.reasons.iter().any(|r| r.contains("Impossible travel")));
        assert!(res.reasons.iter().any(|r| r.contains("New IP")));
    }
}
