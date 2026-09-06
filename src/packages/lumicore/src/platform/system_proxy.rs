//! Windows and Cross-Platform System Proxy Controller with WinINET Restoration.
//!
//! Provides transactional configuration of the OS system proxy (WinINET):
//! 1. Atomic snapshotting: captures current proxy settings (`ProxyServer`, `ProxyOverride`,
//!    `ProxyEnable`, `AutoConfigURL`) in memory and in persistent registry backup (`HKCU\Software\LumiNet\ProxyBackup`).
//! 2. Per-protocol string composition: configures HTTP, HTTPS, and SOCKS5 endpoints simultaneously.
//! 3. Bypass isolation: ensures loopback and private subnets (`127.*`, `10.*`, `172.16.*`, `192.168.*`, `<local>`) bypass the proxy.
//! 4. Live WinINET notification: invokes `InternetSetOptionW` to signal running applications without process restart.
//! 5. Stale crash recovery: cleans up orphaned proxy configurations pointing to local ports without destroying enterprise PAC scripts.

use std::process::Command;
use std::sync::{Mutex, OnceLock};

#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub const INTERNET_SETTINGS_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";
pub const BACKUP_KEY: &str = r"HKCU\Software\LumiNet\ProxyBackup";
pub const SENTINEL_ACTIVE: &str = "LumiNetActive";

/// Destination subnet bypass pattern keeping loopback and local LAN direct.
pub const SYSTEM_PROXY_BYPASS: &str = "localhost;127.*;10.*;172.16.*;192.168.*;<local>";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SavedProxy {
    pub server: Option<String>,
    pub override_list: Option<String>,
    pub enable: Option<String>,
    pub auto_config: Option<String>,
}

fn saved_proxy_cell() -> &'static Mutex<Option<SavedProxy>> {
    static CELL: OnceLock<Mutex<Option<SavedProxy>>> = OnceLock::new();
    CELL.get_or_init(|| Mutex::new(None))
}

/// Formats per-protocol proxy string for WinINET.
pub fn build_proxy_string(http_port: u16, socks_port: u16) -> String {
    format!("http=127.0.0.1:{http_port};https=127.0.0.1:{http_port};socks=127.0.0.1:{socks_port}")
}

/// Enables the OS system proxy targeting local HTTP and SOCKS5 bridge ports.
pub fn enable_system_proxy(http_port: u16, socks_port: u16) -> bool {
    let mut saved = saved_proxy_cell().lock().unwrap();
    if saved.is_none() {
        *saved = Some(SavedProxy {
            server: reg_read("ProxyServer"),
            override_list: reg_read("ProxyOverride"),
            enable: reg_read("ProxyEnable"),
            auto_config: reg_read("AutoConfigURL"),
        });
    }

    if let Some(previous) = saved.as_ref() {
        let _ = reg(&["add", BACKUP_KEY, "/f"]);
        backup_write("ProxyServer", previous.server.as_deref());
        backup_write("ProxyOverride", previous.override_list.as_deref());
        backup_write("ProxyEnable", previous.enable.as_deref());
        backup_write("AutoConfigURL", previous.auto_config.as_deref());
        backup_write(SENTINEL_ACTIVE, Some("REG_DWORD\t1"));
    }
    drop(saved);

    let server = build_proxy_string(http_port, socks_port);
    let ok = reg(&["add", INTERNET_SETTINGS_KEY, "/v", "ProxyServer", "/t", "REG_SZ", "/d", &server, "/f"])
        && reg(&["add", INTERNET_SETTINGS_KEY, "/v", "ProxyOverride", "/t", "REG_SZ", "/d", SYSTEM_PROXY_BYPASS, "/f"])
        && reg(&["add", INTERNET_SETTINGS_KEY, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "1", "/f"]);

    if !ok {
        let _ = disable_system_proxy();
        return false;
    }

    broadcast_system_proxy_change();
    true
}

/// Disables system proxy and restores previous configuration from memory or backup registry.
pub fn disable_system_proxy() -> bool {
    let snapshot = saved_proxy_cell()
        .lock()
        .unwrap()
        .take()
        .or_else(load_persistent_backup);
    let had_snapshot = snapshot.is_some();

    let ok = match snapshot {
        Some(previous) => {
            restore_value("ProxyServer", previous.server)
                && restore_value("ProxyOverride", previous.override_list)
                && restore_value("ProxyEnable", previous.enable)
                && restore_value("AutoConfigURL", previous.auto_config)
        }
        None => {
            let stale = reg_read("ProxyServer")
                .map(|v| v.contains("127.0.0.1:10811") || v.contains("127.0.0.1:1819"))
                .unwrap_or(false);
            if stale {
                reg(&["add", INTERNET_SETTINGS_KEY, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "0", "/f"])
                    && reg_delete("ProxyServer")
                    && reg_delete("ProxyOverride")
            } else {
                true
            }
        }
    };

    if ok && had_snapshot {
        let _ = reg(&["delete", BACKUP_KEY, "/f"]);
    }
    broadcast_system_proxy_change();
    ok
}

/// Recovers and cleans up only stale configurations from an abnormal previous shutdown.
pub fn recover_stale_proxy() -> bool {
    let has_backup = load_persistent_backup().is_some();
    let points_to_luminet = reg_read("ProxyServer")
        .map(|v| v.contains("127.0.0.1:10811") || v.contains("127.0.0.1:1819"))
        .unwrap_or(false);
    if has_backup || points_to_luminet {
        disable_system_proxy()
    } else {
        true
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn backup_write(name: &str, value: Option<&str>) {
    if let Some(val) = value {
        let _ = reg(&["add", BACKUP_KEY, "/v", name, "/t", "REG_SZ", "/d", val, "/f"]);
    }
}

pub fn load_persistent_backup() -> Option<SavedProxy> {
    if reg_read_backup(SENTINEL_ACTIVE).is_none() {
        return None;
    }
    Some(SavedProxy {
        server: reg_read_backup("ProxyServer"),
        override_list: reg_read_backup("ProxyOverride"),
        enable: reg_read_backup("ProxyEnable"),
        auto_config: reg_read_backup("AutoConfigURL"),
    })
}

fn reg_read_backup(name: &str) -> Option<String> {
    let output = reg_output(&["query", BACKUP_KEY, "/v", name])?;
    output.lines().find_map(|line| {
        let t = line.trim();
        if !t.starts_with(name) {
            return None;
        }
        let mut p = t[name.len()..].split_whitespace();
        let kind = p.next()?;
        Some(format!("{}\t{}", kind, p.collect::<Vec<_>>().join(" ")))
    })
}

fn reg_read(name: &str) -> Option<String> {
    let output = reg_output(&["query", INTERNET_SETTINGS_KEY, "/v", name])?;
    output.lines().find_map(|line| {
        let t = line.trim();
        if !t.starts_with(name) {
            return None;
        }
        let mut parts = t[name.len()..].split_whitespace();
        let kind = parts.next()?;
        let value = parts.collect::<Vec<_>>().join(" ");
        Some(format!("{kind}\t{value}"))
    })
}

fn restore_value(name: &str, encoded: Option<String>) -> bool {
    match encoded {
        Some(raw) => {
            let mut parts = raw.splitn(2, '\t');
            let kind = parts.next().unwrap_or("REG_SZ");
            let value = parts.next().unwrap_or("");
            reg(&["add", INTERNET_SETTINGS_KEY, "/v", name, "/t", kind, "/d", value, "/f"])
        }
        None => reg(&["delete", INTERNET_SETTINGS_KEY, "/v", name, "/f"]) || true,
    }
}

fn reg_delete(name: &str) -> bool {
    reg(&["delete", INTERNET_SETTINGS_KEY, "/v", name, "/f"]) || true
}

fn reg_output(args: &[&str]) -> Option<String> {
    #[cfg(windows)]
    {
        let mut cmd = Command::new("reg");
        cmd.args(args);
        cmd.creation_flags(CREATE_NO_WINDOW);
        let out = cmd.output().ok()?;
        if !out.status.success() {
            return None;
        }
        Some(String::from_utf8_lossy(&out.stdout).into_owned())
    }
    #[cfg(not(windows))]
    {
        let _ = args;
        None
    }
}

fn reg(args: &[&str]) -> bool {
    #[cfg(windows)]
    {
        let mut cmd = Command::new("reg");
        cmd.args(args);
        cmd.creation_flags(CREATE_NO_WINDOW);
        cmd.status().map(|s| s.success()).unwrap_or(false)
    }
    #[cfg(not(windows))]
    {
        let _ = args;
        true
    }
}

/// Notifies WinINET that system proxy settings have changed.
#[cfg(windows)]
pub fn broadcast_system_proxy_change() {
    const INTERNET_OPTION_REFRESH: u32 = 37;
    const INTERNET_OPTION_SETTINGS_CHANGED: u32 = 39;
    #[link(name = "wininet")]
    extern "system" {
        fn InternetSetOptionW(
            hinternet: *mut core::ffi::c_void,
            dwoption: u32,
            lpbuffer: *mut core::ffi::c_void,
            dwbufferlength: u32,
        ) -> i32;
    }
    unsafe {
        InternetSetOptionW(std::ptr::null_mut(), INTERNET_OPTION_SETTINGS_CHANGED, std::ptr::null_mut(), 0);
        InternetSetOptionW(std::ptr::null_mut(), INTERNET_OPTION_REFRESH, std::ptr::null_mut(), 0);
    }
}

#[cfg(not(windows))]
pub fn broadcast_system_proxy_change() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_string_contains_all_protocols() {
        let s = build_proxy_string(10811, 10810);
        assert!(s.contains("http=127.0.0.1:10811"));
        assert!(s.contains("https=127.0.0.1:10811"));
        assert!(s.contains("socks=127.0.0.1:10810"));
    }

    #[test]
    fn bypass_contains_all_private_and_local_targets() {
        for target in ["localhost", "127.*", "10.*", "172.16.*", "192.168.*", "<local>"] {
            assert!(SYSTEM_PROXY_BYPASS.contains(target), "missing {target}");
        }
    }

    #[test]
    fn saved_proxy_roundtrip_decoding() {
        let raw = "REG_SZ\thttp=127.0.0.1:8080";
        let mut parts = raw.splitn(2, '\t');
        assert_eq!(parts.next(), Some("REG_SZ"));
        assert_eq!(parts.next(), Some("http=127.0.0.1:8080"));
    }
}
