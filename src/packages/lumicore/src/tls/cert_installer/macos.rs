//! macOS certificate installation.

use crate::tls::mitm::CERT_NAME;
use std::path::Path;
use std::process::Command;

pub fn install_macos(cert_path: &str) -> bool {
    let home = std::env::var("HOME").unwrap_or_default();
    let login_kc_db = format!("{}/Library/Keychains/login.keychain-db", home);
    let login_kc = format!("{}/Library/Keychains/login.keychain", home);
    let login_keychain = if Path::new(&login_kc_db).exists() {
        login_kc_db
    } else {
        login_kc
    };

    // Try login keychain first (no sudo).
    let res = Command::new("security")
        .args([
            "add-trusted-cert",
            "-d",
            "-r",
            "trustRoot",
            "-k",
            &login_keychain,
            cert_path,
        ])
        .status();
    if let Ok(s) = res {
        if s.success() {
            tracing::info!("CA installed into login keychain.");
            return true;
        }
    }

    // Fall back to system keychain (needs sudo).
    tracing::warn!("login keychain install failed — trying system keychain (needs sudo).");
    let res = Command::new("sudo")
        .args([
            "security",
            "add-trusted-cert",
            "-d",
            "-r",
            "trustRoot",
            "-k",
            "/Library/Keychains/System.keychain",
            cert_path,
        ])
        .status();
    if let Ok(s) = res {
        if s.success() {
            tracing::info!("CA installed into System keychain.");
            return true;
        }
    }
    tracing::error!("macOS install failed — run with sudo or install manually.");
    false
}

/// Delete the CA from the login keychain (no sudo) and, only when a
/// probe confirms the cert actually lives there, the system keychain
/// (sudo). Probing first avoids prompting the user — or hanging the
/// UI's GUI-spawned `sudo` — for a password they don't need when the
/// cert was only ever installed in the login keychain (the default
/// path). Exit status is best-effort: `security delete-certificate`
/// exits non-zero for "not found", which is indistinguishable from
/// real failures, so the final trust state is verified by the caller
/// via `is_ca_trusted_by_name`.
pub fn remove_macos() {
    let home = std::env::var("HOME").unwrap_or_default();
    let login_kc_db = format!("{}/Library/Keychains/login.keychain-db", home);
    let login_kc = format!("{}/Library/Keychains/login.keychain", home);
    let login_keychain = if Path::new(&login_kc_db).exists() {
        login_kc_db
    } else {
        login_kc
    };

    let res = Command::new("security")
        .args(["delete-certificate", "-c", CERT_NAME, &login_keychain])
        .status();
    if matches!(res, Ok(s) if s.success()) {
        tracing::info!("Removed CA from login keychain.");
    }

    if macos_system_keychain_has() {
        let res = Command::new("sudo")
            .args([
                "security",
                "delete-certificate",
                "-c",
                CERT_NAME,
                "/Library/Keychains/System.keychain",
            ])
            .status();
        if matches!(res, Ok(s) if s.success()) {
            tracing::info!("Removed CA from System keychain.");
        } else {
            tracing::warn!(
                "System keychain still has the CA and the sudo delete did not \
                 succeed — re-run with an admin password available."
            );
        }
    }
}

/// Probe-without-sudo: does the System keychain currently contain our
/// cert? `security find-certificate` against the system keychain path
/// does not require admin; only `delete-certificate` does. Used to
/// decide whether to escalate at all.
pub fn macos_system_keychain_has() -> bool {
    let out = Command::new("security")
        .args([
            "find-certificate",
            "-a",
            "-c",
            CERT_NAME,
            "/Library/Keychains/System.keychain",
        ])
        .output();
    match out {
        Ok(o) => o.status.success() && !o.stdout.is_empty(),
        Err(_) => false,
    }
}

pub fn is_trusted_macos() -> bool {
    let out = Command::new("security")
        .args(["find-certificate", "-a", "-c", CERT_NAME])
        .output();
    match out {
        Ok(o) => !o.stdout.is_empty() && o.status.success(),
        Err(_) => false,
    }
}
