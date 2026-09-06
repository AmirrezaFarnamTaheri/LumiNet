//! Linux certificate installation.

use crate::tls::mitm::CERT_NAME;
use std::path::Path;
use std::process::Command;

pub fn install_linux(cert_path: &str) -> bool {
    let distro = detect_linux_distro();
    tracing::info!("Detected Linux distro family: {}", distro);
    let safe_name = CERT_NAME.replace(' ', "_");

    match distro.as_str() {
        "debian" => {
            let dest = format!("/usr/local/share/ca-certificates/{}.crt", safe_name);
            try_copy_and_run(cert_path, &dest, &[&["update-ca-certificates"]])
        }
        "rhel" => {
            let dest = format!("/etc/pki/ca-trust/source/anchors/{}.crt", safe_name);
            try_copy_and_run(cert_path, &dest, &[&["update-ca-trust", "extract"]])
        }
        "arch" => {
            let dest = format!(
                "/etc/ca-certificates/trust-source/anchors/{}.crt",
                safe_name
            );
            try_copy_and_run(cert_path, &dest, &[&["trust", "extract-compat"]])
        }
        "openwrt" => {
            // OpenWRT itself doesn't open HTTPS connections through the proxy —
            // LAN clients do. The CA needs to be trusted on the CLIENTS, not on
            // the router. So this is a no-op success with guidance rather than
            // an error.
            tracing::info!(
                "OpenWRT detected: the router doesn't need to trust the MITM CA. \
                 Copy {} to each LAN client (browser / OS trust store) instead. \
                 Example: scp root@<router>:{} ./ and import from there.",
                cert_path,
                cert_path
            );
            true
        }
        _ => {
            tracing::warn!(
                "Unknown Linux distro — CA file is at {}. Copy it into your system's \
                 trust anchors dir (e.g. /usr/local/share/ca-certificates/ for \
                 Debian-like, /etc/pki/ca-trust/source/anchors/ for RHEL-like) and \
                 run the corresponding refresh command.",
                cert_path
            );
            false
        }
    }
}

fn try_copy_and_run(src: &str, dest: &str, cmds: &[&[&str]]) -> bool {
    // First try without sudo.
    let mut ok = true;
    if let Some(parent) = Path::new(dest).parent() {
        if std::fs::create_dir_all(parent).is_err() {
            ok = false;
        }
    }
    if ok && std::fs::copy(src, dest).is_err() {
        ok = false;
    }
    if ok {
        for cmd in cmds {
            if !run_cmd(cmd) {
                ok = false;
                break;
            }
        }
    }
    if ok {
        tracing::info!("CA installed via {}.", cmds[0].join(" "));
        return true;
    }

    // Retry with sudo.
    tracing::warn!("direct install failed — retrying with sudo.");
    if !run_cmd(&["sudo", "cp", src, dest]) {
        return false;
    }
    for cmd in cmds {
        let mut full: Vec<&str> = vec!["sudo"];
        full.extend_from_slice(cmd);
        if !run_cmd(&full) {
            return false;
        }
    }
    tracing::info!("CA installed via sudo.");
    true
}

fn run_cmd(args: &[&str]) -> bool {
    if args.is_empty() {
        return false;
    }
    let out = Command::new(args[0]).args(&args[1..]).status();
    matches!(out, Ok(s) if s.success())
}

fn detect_linux_distro() -> String {
    // Marker-file shortcuts (most reliable).
    if Path::new("/etc/openwrt_release").exists() {
        return "openwrt".into();
    }
    if Path::new("/etc/debian_version").exists() {
        return "debian".into();
    }
    if Path::new("/etc/redhat-release").exists() || Path::new("/etc/fedora-release").exists() {
        return "rhel".into();
    }
    if Path::new("/etc/arch-release").exists() {
        return "arch".into();
    }
    if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
        return classify_os_release(&content);
    }
    "unknown".into()
}

/// Parse /etc/os-release content and return a distro family.
///
/// We specifically look at the `ID` and `ID_LIKE` fields (not a substring
/// search over the whole file) because random other fields like
/// `OPENWRT_DEVICE_ARCH=x86_64` contain substrings that false-positive on
/// "arch". Exposed for unit testing.
fn classify_os_release(content: &str) -> String {
    let mut id = String::new();
    let mut id_like = String::new();
    for line in content.lines() {
        let (k, v) = match line.split_once('=') {
            Some(x) => x,
            None => continue,
        };
        let v = v
            .trim()
            .trim_matches('"')
            .trim_matches('\'')
            .to_ascii_lowercase();
        match k.trim() {
            "ID" => id = v,
            "ID_LIKE" => id_like = v,
            _ => {}
        }
    }
    let tokens: Vec<&str> = id
        .split(|c: char| c.is_whitespace() || c == ',')
        .chain(id_like.split(|c: char| c.is_whitespace() || c == ','))
        .filter(|t| !t.is_empty())
        .collect();
    let has = |needle: &str| tokens.contains(&needle);
    if has("openwrt") {
        return "openwrt".into();
    }
    if has("debian") || has("ubuntu") || has("mint") || has("raspbian") {
        return "debian".into();
    }
    if has("fedora") || has("rhel") || has("centos") || has("rocky") || has("almalinux") {
        return "rhel".into();
    }
    if has("arch") || has("manjaro") || has("endeavouros") {
        return "arch".into();
    }
    "unknown".into()
}

/// Mirror of `install_linux`: for each known anchor dir, delete our cert
/// file and run the corresponding refresh command. Tries without sudo
/// first, falls back to sudo. Missing files are silently skipped —
/// removal is idempotent.
///
/// Key safety behavior: we refresh the trust bundle **regardless of
/// whether we found an anchor file to delete**. The concern is a retry
/// after a prior run that deleted the anchor but failed to refresh —
/// leaving the merged bundle still containing our PEM. On the next
/// invocation the anchor dir is empty, so a "delete file, then refresh"
/// contract would skip the refresh entirely and `remove_ca` would see
/// no anchor file left, declare success, and delete `ca/` while the
/// stale root is still trusted. Running the refresh unconditionally
/// catches this.
///
/// Returns `false` if any refresh command failed — callers must then
/// abort file deletion so a regenerated CA with a fresh keypair can't
/// mismatch the stale root.
pub fn remove_linux() -> bool {
    let safe_name = CERT_NAME.replace(' ', "_");
    let anchors: &[(&str, &[&str])] = &[
        (
            "/usr/local/share/ca-certificates",
            &["update-ca-certificates"],
        ),
        (
            "/etc/pki/ca-trust/source/anchors",
            &["update-ca-trust", "extract"],
        ),
        (
            "/etc/ca-certificates/trust-source/anchors",
            &["trust", "extract-compat"],
        ),
    ];

    let mut all_ok = true;
    for (dir, refresh) in anchors {
        // Skip distros whose anchor dir doesn't exist — running their
        // refresh tool (e.g. `trust extract-compat` on a Debian host)
        // would just error out and falsely mark the removal as failed.
        if !Path::new(dir).exists() {
            continue;
        }

        let path = format!("{}/{}.crt", dir, safe_name);
        let anchor_present = Path::new(&path).exists();
        if anchor_present {
            let deleted =
                std::fs::remove_file(&path).is_ok() || run_cmd(&["sudo", "rm", "-f", &path]);
            if !deleted {
                tracing::warn!("failed to remove {}", path);
                all_ok = false;
                continue;
            }
        }

        // Always refresh — see doc comment for the retry-safety rationale.
        let refreshed = run_cmd(refresh) || {
            let mut full: Vec<&str> = vec!["sudo"];
            full.extend_from_slice(refresh);
            run_cmd(&full)
        };
        if !refreshed {
            tracing::error!(
                "refresh {:?} failed for {} — CA may still be trusted via the merged bundle",
                refresh,
                dir
            );
            all_ok = false;
        } else if anchor_present {
            tracing::info!("Removed CA from {} (bundle refreshed).", dir);
        } else {
            tracing::debug!("Refreshed {} bundle (nothing to delete here).", dir);
        }
    }
    all_ok
}

pub fn is_trusted_linux() -> bool {
    // Check both the anchor dirs (what we write into on install) and
    // the post-extract dirs (where update-ca-certificates / `trust
    // extract-compat` etc. copy or symlink our PEM after refresh).
    // Checking the post-extract side catches the "anchor file already
    // removed but bundle not regenerated" case on a retry — if we only
    // looked at anchor dirs, a `remove_ca` retry after a prior refresh
    // failure could declare success while the merged bundle still
    // contains our stale root.
    let dirs = [
        "/usr/local/share/ca-certificates",
        "/etc/pki/ca-trust/source/anchors",
        "/etc/ca-certificates/trust-source/anchors",
        // Post-extract locations:
        "/etc/ssl/certs",
        "/etc/pki/ca-trust/extracted/pem/directory-hash",
        "/etc/ca-certificates/extracted/cadir",
    ];
    for d in dirs {
        if let Ok(entries) = std::fs::read_dir(d) {
            for e in entries.flatten() {
                let name = e.file_name();
                let s = name.to_string_lossy().to_lowercase();
                if s.contains("masterhttprelayvpn") || s.contains("mhrv") {
                    return true;
                }
            }
        }
    }
    false
}
