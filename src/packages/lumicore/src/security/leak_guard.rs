//! Multi-layered WebRTC, IPv6 fail-closed, and firewall leak protection.
//!
//! Provides triple-layer defense against IP leaks on Windows and desktop environments:
//! 1. Browser policy layer: Configures Chromium `WebRtcIPHandlingPolicy` and Firefox
//!    `media.peerconnection.ice.proxy_only` with managed sentinels.
//! 2. System firewall layer: Blocks outbound UDP for detected browsers, blocks STUN/TURN
//!    standard ports system-wide, and enforces IPv6 fail-closed for global unicast traffic.
//! 3. Kill-switch management: Independent kill-switch rule that persists through automatic
//!    reconnection handovers and disarms safely on explicit disconnect.

use std::path::PathBuf;
use std::process::Command;
use std::sync::{Mutex, OnceLock};

#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Shared firewall rule name for session leak-guard.
pub const FW_RULE: &str = "LumiNet Leak Guard";
/// Dedicated kill-switch rule name surviving automatic reconnects.
pub const KILL_RULE: &str = "LumiNet Kill Switch";

/// Standard STUN/TURN ports and Google STUN IP ranges.
pub const STUN_TURN_PORTS: &str = "3478,3479,5349,5350,19302-19309";

/// Managed sentinel marking registry policies created by LumiNet.
pub const SENTINEL_NAME: &str = "LumiLeakGuardManaged";

/// Known browser executable filenames.
pub const BROWSER_EXES: [&str; 8] = [
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "brave.exe",
    "opera.exe",
    "vivaldi.exe",
    "chromium.exe",
    "browser.exe",
];

/// Standard relative installation paths for browsers on Windows.
pub const BROWSER_PATHS: [&str; 11] = [
    r"Google\Chrome\Application\chrome.exe",
    r"Microsoft\Edge\Application\msedge.exe",
    r"Mozilla Firefox\firefox.exe",
    r"BraveSoftware\Brave-Browser\Application\brave.exe",
    r"Vivaldi\Application\vivaldi.exe",
    r"Chromium\Application\chrome.exe",
    r"Yandex\YandexBrowser\Application\browser.exe",
    r"Opera\opera.exe",
    r"Opera GX\opera.exe",
    r"Programs\Opera\opera.exe",
    r"Programs\Opera GX\opera.exe",
];

/// Registry policy keys for Chromium-based browsers.
pub const CHROMIUM_POLICY_KEYS: [&str; 7] = [
    r"HKCU\Software\Policies\Google\Chrome",
    r"HKCU\Software\Policies\Microsoft\Edge",
    r"HKCU\Software\Policies\BraveSoftware\Brave",
    r"HKCU\Software\Policies\Vivaldi",
    r"HKCU\Software\Policies\Chromium",
    r"HKCU\Software\Policies\Opera Software\Opera",
    r"HKCU\Software\Policies\Yandex\YandexBrowser",
];
pub const CHROMIUM_POLICY_NAME: &str = "WebRtcIPHandlingPolicy";
pub const CHROMIUM_POLICY_VALUE: &str = "disable_non_proxied_udp";

pub const FIREFOX_PREFS_KEY: &str = r"HKCU\Software\Policies\Mozilla\Firefox\Preferences";
pub const FIREFOX_PREF_NAME: &str = "media.peerconnection.ice.proxy_only";

/// Live status of the leak guard system.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GuardStatus {
    pub engaged: bool,
    pub firewall_rules: u32,
    pub browser_policies: u32,
    pub kill_switch_active: bool,
}

fn status_cell() -> &'static Mutex<GuardStatus> {
    static CELL: OnceLock<Mutex<GuardStatus>> = OnceLock::new();
    CELL.get_or_init(|| Mutex::new(GuardStatus::default()))
}

/// Retrieves current global leak guard status.
pub fn status() -> GuardStatus {
    *status_cell().lock().unwrap()
}

/// Reversible registry modification tracker.
#[derive(Debug, Clone)]
pub struct PolicyEdit {
    pub key: String,
    pub name: String,
    pub kind: &'static str,
    pub previous: Option<String>,
}

/// Active LeakGuard session instance.
#[derive(Debug, Default)]
pub struct LeakGuard {
    pub rules: u32,
    pub kill_rules: u32,
    pub policies: u32,
    pub edits: Vec<PolicyEdit>,
}

impl LeakGuard {
    /// Creates a disabled leak guard that touches nothing.
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Engages full triple-layer leak protection.
    pub fn engage(ipv6_protection: bool, kill_switch: bool) -> Self {
        delete_firewall_rules();
        delete_kill_switch_rules();

        let mut guard = Self::default();
        guard.apply_browser_policies();
        guard.apply_firewall(ipv6_protection);
        if kill_switch {
            guard.apply_kill_switch(ipv6_protection);
        }

        let total_fw = guard.rules + guard.kill_rules;
        *status_cell().lock().unwrap() = GuardStatus {
            engaged: true,
            firewall_rules: total_fw,
            browser_policies: guard.policies,
            kill_switch_active: guard.kill_rules > 0,
        };

        guard
    }

    /// Applies browser policy registry entries for WebRTC protection.
    pub fn apply_browser_policies(&mut self) {
        for key in CHROMIUM_POLICY_KEYS {
            let previous = reg_read(key, CHROMIUM_POLICY_NAME);
            if previous.as_deref() == Some(CHROMIUM_POLICY_VALUE) {
                self.policies += 1;
                continue;
            }
            if reg_write(key, CHROMIUM_POLICY_NAME, "REG_SZ", CHROMIUM_POLICY_VALUE) {
                reg_write(key, SENTINEL_NAME, "REG_DWORD", "1");
                self.policies += 1;
                self.edits.push(PolicyEdit {
                    key: key.to_string(),
                    name: CHROMIUM_POLICY_NAME.to_string(),
                    kind: "REG_SZ",
                    previous,
                });
            }
        }

        let previous = reg_read(FIREFOX_PREFS_KEY, FIREFOX_PREF_NAME);
        if previous.as_deref() == Some("0x1") {
            self.policies += 1;
        } else if reg_write(FIREFOX_PREFS_KEY, FIREFOX_PREF_NAME, "REG_DWORD", "1") {
            reg_write(FIREFOX_PREFS_KEY, SENTINEL_NAME, "REG_DWORD", "1");
            self.policies += 1;
            self.edits.push(PolicyEdit {
                key: FIREFOX_PREFS_KEY.to_string(),
                name: FIREFOX_PREF_NAME.to_string(),
                kind: "REG_DWORD",
                previous,
            });
        }
    }

    /// Applies outbound UDP blocks for browsers and system-wide STUN/TURN blocks.
    pub fn apply_firewall(&mut self, ipv6_protection: bool) {
        for exe in discover_browsers() {
            let program = exe.to_string_lossy().to_string();
            let ok = fw_add(
                &["dir=out", "action=block", "protocol=udp", "profile=any", "enable=yes"],
                Some(&program),
            );
            if ok {
                self.rules += 1;
            }
        }

        let ports = format!("remoteport={STUN_TURN_PORTS}");
        for proto in ["protocol=udp", "protocol=tcp"] {
            if fw_add(&["dir=out", "action=block", proto, &ports, "profile=any", "enable=yes"], None) {
                self.rules += 1;
            }
        }

        if ipv6_protection {
            let ok = fw_add(
                &["dir=out", "action=block", "protocol=any", "remoteip=2000::/3", "profile=any", "enable=yes"],
                None,
            );
            if ok {
                self.rules += 1;
            }
        }
    }

    /// Applies browser-scoped kill switch preventing direct egress outside localhost.
    pub fn apply_kill_switch(&mut self, ipv6_protection: bool) {
        for exe in discover_browsers() {
            let program = exe.to_string_lossy().to_string();
            if fw_add_named(
                KILL_RULE,
                &["dir=out", "action=block", "protocol=any", "remoteip=any", "profile=any", "enable=yes"],
                Some(&program),
            ) {
                self.kill_rules += 1;
            }
        }

        if ipv6_protection
            && fw_add_named(
                KILL_RULE,
                &["dir=out", "action=block", "protocol=any", "remoteip=2000::/3", "profile=any", "enable=yes"],
                None,
            )
        {
            self.kill_rules += 1;
        }
    }

    /// Disarms guard without releasing system rules (transfers ownership to replacement guard).
    pub fn disarm_without_cleanup(&mut self) {
        self.rules = 0;
        self.kill_rules = 0;
        self.policies = 0;
        self.edits.clear();
    }

    /// Releases session-level leak rules while keeping kill-switch active across reconnects.
    pub fn release_for_reconnect(&mut self) {
        if self.rules > 0 {
            delete_firewall_rules();
        }
        self.rules = 0;
        let edits = std::mem::take(&mut self.edits);
        for edit in edits {
            match &edit.previous {
                Some(v) => {
                    reg_write(&edit.key, &edit.name, edit.kind, v);
                }
                None => {
                    reg_delete_value(&edit.key, &edit.name);
                }
            }
            reg_delete_value(&edit.key, SENTINEL_NAME);
        }

        *status_cell().lock().unwrap() = GuardStatus {
            engaged: self.kill_rules > 0,
            firewall_rules: self.kill_rules,
            browser_policies: 0,
            kill_switch_active: self.kill_rules > 0,
        };
    }

    /// Completely releases all firewall rules and reverts browser policies.
    pub fn release(&mut self) {
        if self.rules > 0 {
            delete_firewall_rules();
        }
        if self.kill_rules > 0 {
            delete_kill_switch_rules();
        }
        self.rules = 0;
        self.kill_rules = 0;

        for edit in std::mem::take(&mut self.edits) {
            match &edit.previous {
                Some(v) => {
                    reg_write(&edit.key, &edit.name, edit.kind, v);
                }
                None => {
                    reg_delete_value(&edit.key, &edit.name);
                }
            }
            reg_delete_value(&edit.key, SENTINEL_NAME);
        }
        *status_cell().lock().unwrap() = GuardStatus::default();
    }
}

impl Drop for LeakGuard {
    fn drop(&mut self) {
        self.release();
    }
}

/// Purges stale rules and policies from prior abnormal terminations.
pub fn purge_stale() {
    delete_firewall_rules();
    delete_kill_switch_rules();

    for key in CHROMIUM_POLICY_KEYS {
        if reg_read(key, SENTINEL_NAME).is_some() {
            reg_delete_value(key, CHROMIUM_POLICY_NAME);
            reg_delete_value(key, SENTINEL_NAME);
        }
    }
    if reg_read(FIREFOX_PREFS_KEY, SENTINEL_NAME).is_some() {
        reg_delete_value(FIREFOX_PREFS_KEY, FIREFOX_PREF_NAME);
        reg_delete_value(FIREFOX_PREFS_KEY, SENTINEL_NAME);
    }
    *status_cell().lock().unwrap() = GuardStatus::default();
}

// ---------------------------------------------------------------------------
// Helpers & Windows Command Wrappers
// ---------------------------------------------------------------------------

pub fn fw_add(args: &[&str], program: Option<&str>) -> bool {
    fw_add_named(FW_RULE, args, program)
}

pub fn fw_add_named(rule_name: &str, args: &[&str], program: Option<&str>) -> bool {
    let mut argv: Vec<String> = vec![
        "advfirewall".into(),
        "firewall".into(),
        "add".into(),
        "rule".into(),
        format!("name={rule_name}"),
    ];
    argv.extend(args.iter().map(|a| (*a).to_string()));
    if let Some(p) = program {
        argv.push(format!("program={p}"));
    }
    netsh(&argv)
}

pub fn delete_firewall_rules() {
    let argv: Vec<String> = vec![
        "advfirewall".into(),
        "firewall".into(),
        "delete".into(),
        "rule".into(),
        format!("name={FW_RULE}"),
    ];
    let _ = netsh(&argv);
}

pub fn delete_kill_switch_rules() {
    let argv: Vec<String> = vec![
        "advfirewall".into(),
        "firewall".into(),
        "delete".into(),
        "rule".into(),
        format!("name={KILL_RULE}"),
    ];
    let _ = netsh(&argv);
}

fn netsh(args: &[String]) -> bool {
    #[cfg(windows)]
    {
        let mut cmd = Command::new("netsh");
        cmd.args(args);
        cmd.creation_flags(CREATE_NO_WINDOW);
        cmd.output().map(|o| o.status.success()).unwrap_or(false)
    }
    #[cfg(not(windows))]
    {
        let _ = args;
        true
    }
}

pub fn reg_write(key: &str, name: &str, kind: &str, data: &str) -> bool {
    reg(&["add", key, "/v", name, "/t", kind, "/d", data, "/f"]).is_some()
}

pub fn reg_delete_value(key: &str, name: &str) -> bool {
    reg(&["delete", key, "/v", name, "/f"]).is_some()
}

pub fn reg_read(key: &str, name: &str) -> Option<String> {
    let out = reg(&["query", key, "/v", name])?;
    parse_reg_value(&out, name)
}

pub fn parse_reg_value(output: &str, name: &str) -> Option<String> {
    for line in output.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with(name) {
            continue;
        }
        let rest = trimmed[name.len()..].trim_start();
        let mut it = rest.splitn(2, "REG_");
        let _ = it.next()?;
        let typed = it.next()?;
        let value = typed.split_whitespace().skip(1).collect::<Vec<_>>().join(" ");
        return Some(value);
    }
    None
}

fn reg(args: &[&str]) -> Option<String> {
    #[cfg(windows)]
    {
        let mut cmd = Command::new("reg");
        cmd.args(args);
        cmd.creation_flags(CREATE_NO_WINDOW);
        let out = cmd.output().ok()?;
        if !out.status.success() {
            return None;
        }
        Some(String::from_utf8_lossy(&out.stdout).to_string())
    }
    #[cfg(not(windows))]
    {
        let _ = args;
        None
    }
}

pub fn discover_browsers() -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = Vec::new();

    for exe in BROWSER_EXES {
        let key = format!(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{exe}");
        if let Some(out) = reg(&["query", &key, "/ve"]) {
            if let Some(v) = parse_default_value(&out) {
                push_unique(&mut found, PathBuf::from(v.trim_matches('"')));
            }
        }
    }

    for root in ["ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"] {
        let base = match std::env::var(root) {
            Ok(v) => v,
            Err(_) => continue,
        };
        for rel in BROWSER_PATHS {
            push_unique(&mut found, PathBuf::from(&base).join(rel));
        }
    }

    found
}

fn push_unique(list: &mut Vec<PathBuf>, path: PathBuf) {
    if path.exists() && !list.iter().any(|x| x == &path) {
        list.push(path);
    }
}

pub fn parse_default_value(output: &str) -> Option<String> {
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("(Default)") {
            let mut it = trimmed.splitn(2, "REG_");
            let _ = it.next()?;
            let typed = it.next()?;
            let value = typed.split_whitespace().skip(1).collect::<Vec<_>>().join(" ");
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_string_registry_value() {
        let out = "\r\nHKEY_CURRENT_USER\\Software\\Policies\\Google\\Chrome\r\n    WebRtcIPHandlingPolicy    REG_SZ    disable_non_proxied_udp\r\n";
        assert_eq!(
            parse_reg_value(out, CHROMIUM_POLICY_NAME).as_deref(),
            Some(CHROMIUM_POLICY_VALUE)
        );
    }

    #[test]
    fn parses_a_dword_registry_value() {
        let out = "    media.peerconnection.ice.proxy_only    REG_DWORD    0x1\r\n";
        assert_eq!(parse_reg_value(out, FIREFOX_PREF_NAME).as_deref(), Some("0x1"));
    }

    #[test]
    fn missing_value_is_none() {
        assert!(parse_reg_value("ERROR: The system was unable to find", CHROMIUM_POLICY_NAME).is_none());
    }

    #[test]
    fn parses_app_paths_default_value() {
        let out = "    (Default)    REG_SZ    C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\r\n";
        assert_eq!(
            parse_default_value(out).as_deref(),
            Some("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe")
        );
    }

    #[test]
    fn stun_port_list_covers_standard_ports() {
        for p in ["3478", "5349", "19302-19309"] {
            assert!(STUN_TURN_PORTS.contains(p), "missing {p}");
        }
    }

    #[test]
    fn disabled_guard_touches_nothing() {
        let g = LeakGuard::disabled();
        assert_eq!(g.rules, 0);
        assert_eq!(g.kill_rules, 0);
        assert_eq!(g.policies, 0);
        assert!(g.edits.is_empty());
    }
}
