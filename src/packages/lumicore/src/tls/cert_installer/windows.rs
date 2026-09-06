//! Windows certificate installation.

use crate::tls::mitm::CERT_NAME;
use std::process::Command;

/// Check whether our CA is present in the Windows Trusted Root store.
/// Looks in both the user store (no admin required to install) and the
/// machine store. Returns true if `certutil -store ... MasterHttpRelayVPN`
/// finds a match. Issue #13 follow-up: previously this always returned
/// false on Windows, so the Check-CA button was misleading users into
/// reinstalling a cert that was already trusted.
pub fn is_trusted_windows() -> bool {
    windows_store_has(true) || windows_store_has(false)
}

/// Query a single Windows Trusted Root store for our CA.
/// `user = true` hits the current-user store (no admin needed);
/// `user = false` hits the machine store. `certutil -store Root <name>`
/// prints the matching cert entries on success and exits non-zero with
/// "Not found" if nothing matches — we also check stdout for the cert
/// name because certutil in some locales returns 0 on no-match with
/// empty output.
pub fn windows_store_has(user: bool) -> bool {
    let mut args: Vec<&str> = Vec::new();
    if user {
        args.push("-user");
    }
    args.extend(["-store", "Root", CERT_NAME]);
    let out = Command::new("certutil").args(&args).output();
    match out {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            o.status.success()
                && stdout
                    .to_ascii_lowercase()
                    .contains(&CERT_NAME.to_ascii_lowercase())
        }
        Err(_) => false,
    }
}

pub fn install_windows(cert_path: &str) -> bool {
    // Per-user Root store (no admin required).
    let res = Command::new("certutil")
        .args(["-addstore", "-user", "Root", cert_path])
        .status();
    if let Ok(s) = res {
        if s.success() {
            tracing::info!("CA installed in Windows user Trusted Root store.");
            return true;
        }
    }
    // System store (admin).
    let res = Command::new("certutil")
        .args(["-addstore", "Root", cert_path])
        .status();
    if let Ok(s) = res {
        if s.success() {
            tracing::info!("CA installed in Windows system Trusted Root store.");
            return true;
        }
    }
    tracing::error!("Windows install failed — run as administrator or install manually.");
    false
}

/// Delete from user and/or machine Trusted Root stores. We probe each
/// store first with `certutil -store` and only attempt the delete where
/// the cert actually lives — this avoids the confusing "needs elevation"
/// error that `-delstore Root` would print when the cert was only ever
/// installed in the per-user store (the default path for non-admin
/// runs). Final state is verified by the caller via `is_ca_trusted`.
pub fn remove_windows() {
    let mut any = false;

    if windows_store_has(true) {
        let res = Command::new("certutil")
            .args(["-delstore", "-user", "Root", CERT_NAME])
            .status();
        if matches!(res, Ok(s) if s.success()) {
            tracing::info!("Removed CA from Windows user Trusted Root store.");
            any = true;
        } else {
            tracing::warn!("failed to remove CA from Windows user Trusted Root store");
        }
    }

    if windows_store_has(false) {
        let res = Command::new("certutil")
            .args(["-delstore", "Root", CERT_NAME])
            .status();
        if matches!(res, Ok(s) if s.success()) {
            tracing::info!("Removed CA from Windows machine Trusted Root store.");
            any = true;
        } else {
            tracing::warn!(
                "failed to remove CA from Windows machine Trusted Root store \
                 (run as administrator to complete)"
            );
        }
    }

    if !any {
        tracing::info!("No MITM CA found in Windows Trusted Root stores.");
    }
}
