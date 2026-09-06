//! NSS (Firefox/LibreWolf/Chrome) certificate database management.

use crate::tls::mitm::CERT_NAME;
use std::path::{Path, PathBuf};
use std::process::Command;
// ---------- NSS (Firefox + LibreWolf + Chrome/Chromium on Linux) ----------

/// Best-effort install of the CA into all discovered NSS stores:
///   1. Every Firefox/LibreWolf profile (each has its own cert9.db).
///   2. On Linux, the shared Chrome/Chromium NSS DB at ~/.pki/nssdb —
///      this is the one update-ca-certificates does NOT populate, and
///      missing it was the real blocker for Chrome users who'd installed
///      the OS-level CA and still got cert errors (part of issue #11).
///
/// Silently no-ops if `certutil` isn't on PATH.
/// Browsers must be closed during install for changes to take effect.
pub fn install_nss_stores(cert_path: &str) {
    // First, try to make Firefox/LibreWolf pick up the OS-level CA
    // automatically by flipping the `security.enterprise_roots.enabled`
    // pref in user.js of every Mozilla-family profile we find. This is
    // the cleanest cross-platform fix because it doesn't depend on
    // whether NSS certutil is installed — the browser just starts
    // trusting whatever the OS trusts. Especially important on Windows
    // where NSS certutil isn't on PATH.
    enable_mozilla_enterprise_roots();

    if !has_nss_certutil() {
        tracing::debug!(
            "NSS certutil not found — Firefox/LibreWolf will still trust the CA via \
             the `security.enterprise_roots.enabled` user.js pref (flipped above). \
             For Chrome/Chromium on Linux, install `libnss3-tools` (Debian/Ubuntu) \
             or `nss-tools` (Fedora/RHEL), or import ca.crt manually via \
             chrome://settings/certificates → Authorities."
        );
        return;
    }

    let mut ok = 0;
    let mut tried = 0;

    // 1. Firefox/LibreWolf profiles.
    for p in mozilla_family_profile_dirs() {
        tried += 1;
        if install_nss_in_profile(&p, cert_path) {
            ok += 1;
        }
    }

    // 2. Chrome/Chromium shared NSS DB (Linux only).
    #[cfg(target_os = "linux")]
    {
        if let Some(nssdb) = chrome_nssdb_path() {
            // Ensure the DB exists. certutil -N creates an empty cert9.db in
            // the directory if none is there. An empty passphrase is fine
            // for a user-local DB.
            let dir_arg = format!("sql:{}", nssdb.display());
            if !nssdb.join("cert9.db").exists() && !nssdb.join("cert8.db").exists() {
                let _ = std::fs::create_dir_all(&nssdb);
                let _ = Command::new("certutil")
                    .args(["-N", "-d", &dir_arg, "--empty-password"])
                    .output();
            }
            tried += 1;
            if install_nss_in_dir(&dir_arg, cert_path) {
                ok += 1;
                tracing::info!(
                    "CA installed in Chrome/Chromium NSS DB: {}",
                    nssdb.display()
                );
            }
        }
    }

    if ok > 0 {
        tracing::info!("CA installed in {}/{} NSS store(s).", ok, tried);
    } else if tried > 0 {
        tracing::warn!(
            "NSS install: 0/{} stores updated. If Firefox/LibreWolf/Chrome was running, \
             close them and retry. Otherwise, import ca.crt manually via browser settings.",
            tried
        );
    }
}

/// Write `user_pref("security.enterprise_roots.enabled", true);` to every
/// discovered Firefox/LibreWolf profile's user.js. This makes the browser
/// trust the OS trust store on next startup — so our already-successful
/// system-level CA install automatically propagates. Critical on Windows
/// where the browser keeps its own NSS DB independent of the Windows
/// cert store, and NSS certutil isn't typically installed so the
/// certutil-based path doesn't fire there.
///
/// We tag the block we write with a sentinel marker comment on the line
/// above the pref, so uninstall can prove ownership before removing it —
/// the user may have had `security.enterprise_roots.enabled = true`
/// before this app existed, and we must not silently revoke their
/// setting. Idempotent.
fn enable_mozilla_enterprise_roots() {
    let mut touched = 0;
    for profile in mozilla_family_profile_dirs() {
        let user_js = profile.join("user.js");
        let existing = std::fs::read_to_string(&user_js).unwrap_or_default();
        match add_enterprise_roots_block(&existing) {
            EnterpriseRootsEdit::AddedBlock(new) => {
                if let Err(e) = std::fs::write(&user_js, new) {
                    tracing::debug!(
                        "mozilla profile {}: user.js write failed: {}",
                        profile.display(),
                        e
                    );
                    continue;
                }
                touched += 1;
            }
            EnterpriseRootsEdit::AlreadyOurs => {}
            EnterpriseRootsEdit::UserOwned => {
                tracing::debug!(
                    "mozilla profile {} already has a user-owned enterprise_roots pref; leaving alone",
                    profile.display()
                );
            }
        }
    }
    if touched > 0 {
        tracing::info!(
            "enabled enterprise_roots in {} Firefox/LibreWolf profile(s) — restart the browser for it to take effect",
            touched
        );
    }
}

// ── Firefox enterprise_roots marker-block helpers (pure, testable) ──
//
// We write a two-line block into user.js — a sentinel comment followed
// by the pref itself. The marker proves we wrote it, so uninstall can
// distinguish our own line from a user-authored one with the same
// value. Any user-authored `security.enterprise_roots.enabled` line
// (with or without our marker above it) means "hands off".
const FX_MARKER: &str = "// mhrv-rs: auto-added, safe to strip with --remove-cert";
const FX_PREF: &str = r#"user_pref("security.enterprise_roots.enabled", true);"#;

#[derive(Debug, PartialEq, Eq)]
enum EnterpriseRootsEdit {
    AddedBlock(String),
    AlreadyOurs,
    UserOwned,
}

/// Append our marker+pref block to `existing` unless (a) it's already
/// there verbatim (idempotent no-op), or (b) the user has their own
/// `enterprise_roots` pref that we didn't write — in which case we
/// leave everything alone.
fn add_enterprise_roots_block(existing: &str) -> EnterpriseRootsEdit {
    if contains_our_block(existing) {
        return EnterpriseRootsEdit::AlreadyOurs;
    }
    if existing.contains("security.enterprise_roots.enabled") {
        return EnterpriseRootsEdit::UserOwned;
    }
    let mut out = existing.to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(FX_MARKER);
    out.push('\n');
    out.push_str(FX_PREF);
    out.push('\n');
    EnterpriseRootsEdit::AddedBlock(out)
}

/// Strip our marker+pref block from `existing` if present. If the pref
/// exists without our marker directly above it, the user owns it — we
/// cannot prove otherwise and leave user.js untouched.
///
/// Consequence for upgrades from pre-marker versions of this app: the
/// legacy bare pref line stays orphaned in user.js after uninstall.
/// That's cosmetic only (Firefox falls back to its built-in root store
/// the moment the CA leaves the OS trust store), and it's the
/// conservative tradeoff — a bare `enterprise_roots = true` line is
/// indistinguishable from a user- or enterprise-policy-authored one,
/// and silently revoking that would break unrelated Firefox trust
/// behavior. README documents the orphan.
fn strip_enterprise_roots_block(existing: &str) -> Option<String> {
    if !contains_our_block(existing) {
        return None;
    }
    let lines: Vec<&str> = existing.lines().collect();
    let mut out: Vec<&str> = Vec::with_capacity(lines.len());
    let mut i = 0;
    while i < lines.len() {
        let is_marker = lines[i].trim() == FX_MARKER;
        let next_is_our_pref = lines.get(i + 1).is_some_and(|l| l.trim() == FX_PREF);
        if is_marker && next_is_our_pref {
            i += 2;
            continue;
        }
        out.push(lines[i]);
        i += 1;
    }
    let mut joined = out.join("\n");
    if existing.ends_with('\n') && !joined.is_empty() {
        joined.push('\n');
    }
    Some(joined)
}

/// True iff `existing` contains our sentinel directly above our pref.
fn contains_our_block(existing: &str) -> bool {
    let mut prev: Option<&str> = None;
    for line in existing.lines() {
        if prev.map(|p| p.trim()) == Some(FX_MARKER) && line.trim() == FX_PREF {
            return true;
        }
        prev = Some(line);
    }
    false
}

/// True iff `existing` has our exact pref line but NOT inside our
/// marker+pref block — i.e. an orphan `security.enterprise_roots.enabled
/// = true` whose provenance we can't prove. Used by
/// `disable_mozilla_enterprise_roots` to surface a one-line hint on
/// uninstall so users upgrading from pre-v1.2.13 installs know their
/// Firefox user.js still has a cosmetic orphan pref from the old app
/// (not broken, just left in place because we can't distinguish it
/// from a user-authored line).
fn has_bare_enterprise_roots(existing: &str) -> bool {
    if contains_our_block(existing) {
        return false;
    }
    existing.lines().any(|l| l.trim() == FX_PREF)
}

fn has_nss_certutil() -> bool {
    // We want NSS's `certutil`, not Windows's
    // built-in `certutil.exe` which shares the binary name but has
    // completely different semantics. The previous heuristic looked
    // for "-d" in help output, which false-positived on Windows
    // because `-dump` / `-dumpPFX` are in the Windows help text.
    //
    // "nickname" is an NSS-specific concept (single-letter batch verbs
    // like `-A`/`-D`/`-n nickname`); the Windows and macOS built-in
    // certutils don't use that term. Matching on it reliably
    // discriminates.
    Command::new("certutil")
        .arg("--help")
        .output()
        .ok()
        .map(|o| {
            let combined = format!(
                "{}{}",
                String::from_utf8_lossy(&o.stderr),
                String::from_utf8_lossy(&o.stdout)
            );
            combined.to_ascii_lowercase().contains("nickname")
        })
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn chrome_nssdb_path() -> Option<std::path::PathBuf> {
    let home = std::env::var("HOME").ok()?;
    Some(std::path::PathBuf::from(format!("{}/.pki/nssdb", home)))
}

/// Install into a given sql: or legacy NSS DB path. Factored out so both
/// Firefox-per-profile and Chrome-shared paths share one code path.
fn install_nss_in_dir(dir_arg: &str, cert_path: &str) -> bool {
    // Delete any stale entry first (ignore errors).
    let _ = Command::new("certutil")
        .args(["-D", "-n", CERT_NAME, "-d", dir_arg])
        .output();

    let res = Command::new("certutil")
        .args([
            "-A", "-n", CERT_NAME, "-t", "C,,", "-d", dir_arg, "-i", cert_path,
        ])
        .output();
    match res {
        Ok(o) if o.status.success() => {
            tracing::debug!("NSS install ok: {}", dir_arg);
            true
        }
        Ok(o) => {
            tracing::debug!(
                "NSS install failed for {}: {}",
                dir_arg,
                String::from_utf8_lossy(&o.stderr).trim()
            );
            false
        }
        Err(e) => {
            tracing::debug!("NSS certutil exec failed for {}: {}", dir_arg, e);
            false
        }
    }
}

fn install_nss_in_profile(profile: &Path, cert_path: &str) -> bool {
    let prefix = if profile.join("cert9.db").exists() {
        "sql:"
    } else if profile.join("cert8.db").exists() {
        ""
    } else {
        return false;
    };
    let dir_arg = format!("{}{}", prefix, profile.display());
    install_nss_in_dir(&dir_arg, cert_path)
}

/// Best-effort reverse of `install_nss_stores`: delete our cert from
/// every Firefox profile NSS DB we can find, plus the shared Chrome/
/// Chromium NSS DB on Linux, and remove the user.js pref we added.
///
/// NSS cleanup is explicitly best-effort — `certutil` from libnss3-tools
/// may be missing, a DB may be locked by a running Firefox/Chrome, or
/// the delete may fail for reasons we can't distinguish. When that
/// happens we log a manual-cleanup hint but don't fail the whole
/// revocation. Callers of `remove_ca` should convey this to users so
/// the `--remove-cert` promise is "OS trust store + best-effort NSS",
/// not "guaranteed NSS".
/// Outcome of an NSS cleanup pass. `tried` / `ok` let callers render
/// accurate messages like "NSS cleanup partial: 1/3 stores updated".
/// `tool_missing_with_stores_present` flags the case where we found
/// Firefox/Chrome NSS DBs but NSS `certutil` isn't on PATH — surfaced
/// so the UI/CLI can tell the user why the cleanup is incomplete.
#[derive(Debug, Clone, Copy, Default)]
pub struct NssReport {
    pub tried: usize,
    pub ok: usize,
    pub tool_missing_with_stores_present: bool,
}

impl NssReport {
    pub fn is_clean(&self) -> bool {
        !self.tool_missing_with_stores_present && self.tried == self.ok
    }
}

pub fn remove_nss_stores() -> NssReport {
    disable_mozilla_enterprise_roots();

    if !has_nss_certutil() {
        // Only warn if there's actually an NSS store we can see — if the
        // user never ran Firefox/Chrome on this machine there's nothing
        // to clean up either way.
        let profiles = mozilla_family_profile_dirs();
        let chrome_present: bool;
        #[cfg(target_os = "linux")]
        {
            chrome_present = chrome_nssdb_path()
                .map(|p| p.join("cert9.db").exists() || p.join("cert8.db").exists())
                .unwrap_or(false);
        }
        #[cfg(not(target_os = "linux"))]
        {
            chrome_present = false;
        }
        let stores_present = !profiles.is_empty() || chrome_present;
        if stores_present {
            tracing::warn!(
                "NSS certutil not found — cannot automatically remove CA from \
                 Firefox/LibreWolf/Chrome NSS stores. Remove `MasterHttpRelayVPN` \
                 manually via each browser's certificate settings, or install NSS \
                 tools (`libnss3-tools` on Debian/Ubuntu, `nss-tools` on Fedora/RHEL) \
                 and re-run --remove-cert."
            );
        }
        return NssReport {
            tried: 0,
            ok: 0,
            tool_missing_with_stores_present: stores_present,
        };
    }

    let mut report = NssReport::default();

    for p in mozilla_family_profile_dirs() {
        report.tried += 1;
        if remove_nss_in_profile(&p) {
            report.ok += 1;
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Some(nssdb) = chrome_nssdb_path() {
            if nssdb.join("cert9.db").exists() || nssdb.join("cert8.db").exists() {
                report.tried += 1;
                let dir_arg = format!("sql:{}", nssdb.display());
                if remove_nss_in_dir(&dir_arg) {
                    report.ok += 1;
                    tracing::info!(
                        "Removed CA from Chrome/Chromium NSS DB: {}",
                        nssdb.display()
                    );
                }
            }
        }
    }

    if report.tried > 0 {
        if report.ok == report.tried {
            tracing::info!("Removed CA from {} NSS store(s).", report.ok);
        } else {
            tracing::warn!(
                "NSS cleanup partial: {}/{} stores updated. If Firefox/LibreWolf/Chrome \
                 was running, close it and re-run --remove-cert. Otherwise \
                 remove `MasterHttpRelayVPN` manually via each browser's cert \
                 settings.",
                report.ok,
                report.tried
            );
        }
    }
    report
}

/// Best-effort remove our cert from one NSS DB.
///
/// Idempotent contract: "cert was never in this DB" is success.
/// Critical distinction from probe *failure*: if `certutil -L` fails
/// because the DB is locked by a running Firefox/Chrome, corrupt, or
/// inaccessible, we must NOT return `true` — that would silently mask
/// an incomplete revocation the user can't see, and NSS would keep
/// trusting the stale root. We parse stderr: only the specific
/// "could not find cert" message means absent.
fn remove_nss_in_dir(dir_arg: &str) -> bool {
    let list = Command::new("certutil")
        .args(["-L", "-n", CERT_NAME, "-d", dir_arg])
        .output();
    match list {
        Ok(o) if o.status.success() => {
            // Cert is present — fall through to delete.
        }
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            if is_nss_not_found(&stderr) {
                tracing::debug!("NSS {}: no `{}` entry — already clean", dir_arg, CERT_NAME);
                return true;
            }
            tracing::warn!(
                "NSS {}: probe failed (DB locked / inaccessible / other error): {}",
                dir_arg,
                stderr.trim()
            );
            return false;
        }
        Err(e) => {
            tracing::warn!("NSS {}: probe exec failed: {}", dir_arg, e);
            return false;
        }
    }

    let res = Command::new("certutil")
        .args(["-D", "-n", CERT_NAME, "-d", dir_arg])
        .output();
    match res {
        Ok(o) if o.status.success() => true,
        Ok(o) => {
            tracing::warn!(
                "NSS {}: delete failed: {}",
                dir_arg,
                String::from_utf8_lossy(&o.stderr).trim()
            );
            false
        }
        Err(e) => {
            tracing::warn!("NSS {}: delete exec failed: {}", dir_arg, e);
            false
        }
    }
}

/// Classify NSS `certutil` stderr as "nickname not present" (idempotent
/// success signal) vs any other failure mode (DB locked, DB corrupt,
/// permission, etc.). Exposed for unit testing. Matches only the
/// specific not-found messages NSS emits — anything else is treated as
/// a real failure so silent bugs can't hide behind false positives.
fn is_nss_not_found(stderr: &str) -> bool {
    let s = stderr.to_ascii_lowercase();
    s.contains("could not find cert") || s.contains("could not find a certificate")
}

fn remove_nss_in_profile(profile: &Path) -> bool {
    let prefix = if profile.join("cert9.db").exists() {
        "sql:"
    } else if profile.join("cert8.db").exists() {
        ""
    } else {
        return false;
    };
    let dir_arg = format!("{}{}", prefix, profile.display());
    remove_nss_in_dir(&dir_arg)
}

/// Undo `enable_mozilla_enterprise_roots`: for each profile, strip the
/// marker+pref block if (and only if) we wrote it. If the user owns
/// their own `enterprise_roots` pref — indicated by the absence of our
/// marker line — leave user.js alone entirely.
fn disable_mozilla_enterprise_roots() {
    for profile in mozilla_family_profile_dirs() {
        let user_js = profile.join("user.js");
        let Ok(existing) = std::fs::read_to_string(&user_js) else {
            continue;
        };
        if let Some(new) = strip_enterprise_roots_block(&existing) {
            let _ = std::fs::write(&user_js, new);
            continue;
        }
        // No marker block to strip, but an orphan pref is present.
        // Surface it so the user isn't left wondering why user.js
        // still has an enterprise_roots line after --remove-cert.
        // The orphan is harmless (Firefox falls back to its built-in
        // root store once the CA leaves the OS store), but silent
        // leftovers feel like half-done removals.
        if has_bare_enterprise_roots(&existing) {
            tracing::info!(
                "Mozilla profile {}: `security.enterprise_roots.enabled` pref \
                 present without our marker — left in place. If it was written \
                 by a pre-v1.2.13 install it's a cosmetic orphan (harmless, the \
                 browser falls back to its built-in root store); remove it \
                 manually from user.js if it bothers you. If you set it \
                 yourself, leave it.",
                profile.display()
            );
        }
    }
}

/// Candidate root directories under which Mozilla-family browser profile
/// directories (each containing cert9.db / cert8.db) live. Pure helper —
/// OS / HOME / APPDATA / XDG_CONFIG_HOME come in as args so the
/// per-platform layout can be asserted in unit tests without touching
/// env or the filesystem.
///
/// LibreWolf (issue #1145) is a Firefox fork with strict privacy
/// defaults that shares Firefox's NSS DB layout and respects the same
/// `security.enterprise_roots.enabled` pref, but stores its profile tree
/// under its own app dir — so the original Firefox-only scan missed it
/// and the MITM CA never reached LibreWolf's trust store. HSTS-protected
/// sites (bing.com, youtube.com, …) then failed with
/// MOZILLA_PKIX_ERROR_MITM_DETECTED with no add-exception path the user
/// could take.
///
/// On Linux we have to scan five candidate Mozilla-fork layouts:
///   * `~/.librewolf` — LibreWolf legacy Firefox-style layout (still
///     present on pre-migration installs).
///   * `${XDG_CONFIG_HOME:-~/.config}/librewolf/librewolf` — LibreWolf
///     current XDG layout.
///   * Both LibreWolf paths again under
///     `~/.var/app/io.gitlab.librewolf-community/` for the Flatpak
///     sandbox, which redirects HOME inside the container.
///   * `~/.mozilla/icecat` — GNU IceCat (Firefox fork shipped by
///     Trisquel / Parabola / Guix / Debian). Same NSS DB format and
///     `security.enterprise_roots.enabled` semantics as Firefox; only
///     the binary's branded profile dir differs. Windows/macOS builds
///     are not officially distributed, so we don't list paths there.
///
/// Non-existent roots silently no-op via `read_dir` failure, so listing
/// all of them costs nothing on installs that only have one.
fn mozilla_family_profile_roots(
    os: &str,
    home: &str,
    appdata: Option<&str>,
    xdg_config_home: Option<&str>,
) -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();
    match os {
        "macos" => {
            roots.push(PathBuf::from(format!(
                "{}/Library/Application Support/Firefox/Profiles",
                home
            )));
            roots.push(PathBuf::from(format!(
                "{}/Library/Application Support/LibreWolf/Profiles",
                home
            )));
        }
        "linux" => {
            roots.push(PathBuf::from(format!("{}/.mozilla/firefox", home)));
            roots.push(PathBuf::from(format!(
                "{}/snap/firefox/common/.mozilla/firefox",
                home
            )));
            // Legacy LibreWolf layout (still present on older installs).
            roots.push(PathBuf::from(format!("{}/.librewolf", home)));
            // Current XDG layout. Empty XDG_CONFIG_HOME is treated as
            // unset per XDG Base Directory spec.
            let xdg = xdg_config_home
                .filter(|v| !v.is_empty())
                .map(String::from)
                .unwrap_or_else(|| format!("{}/.config", home));
            roots.push(PathBuf::from(format!("{}/librewolf/librewolf", xdg)));
            // Flatpak sandbox: $HOME inside the container is
            // ~/.var/app/<flatpak-id>/. Cover both legacy and XDG layouts
            // since LibreWolf's migration mirrors the host inside the
            // sandbox.
            let flatpak_home = format!("{}/.var/app/io.gitlab.librewolf-community", home);
            roots.push(PathBuf::from(format!("{}/.librewolf", flatpak_home)));
            roots.push(PathBuf::from(format!(
                "{}/.config/librewolf/librewolf",
                flatpak_home
            )));
            // GNU IceCat: Firefox fork shipped by Trisquel / Parabola /
            // Guix / Debian, primarily a GNU/Linux distribution target.
            // Mirrors Firefox's `~/.mozilla/firefox` layout under
            // `~/.mozilla/icecat`.
            roots.push(PathBuf::from(format!("{}/.mozilla/icecat", home)));
        }
        "windows" => {
            if let Some(appdata) = appdata {
                roots.push(PathBuf::from(format!(
                    "{}\\Mozilla\\Firefox\\Profiles",
                    appdata
                )));
                roots.push(PathBuf::from(format!("{}\\LibreWolf\\Profiles", appdata)));
            }
        }
        _ => {}
    }
    roots
}

/// Walk each candidate root and return every immediate child that looks
/// like a Mozilla NSS profile (has cert9.db or cert8.db). Pure given the
/// roots — no env access — so tempdir tests can pin the filter without
/// stubbing HOME/APPDATA. Missing roots silently skip.
fn discover_profile_dirs(roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for root in roots {
        let Ok(entries) = std::fs::read_dir(root) else {
            continue;
        };
        for ent in entries.flatten() {
            let p = ent.path();
            if !p.is_dir() {
                continue;
            }
            // A profile has cert9.db (NSS sql:) or cert8.db (legacy dbm:).
            if p.join("cert9.db").exists() || p.join("cert8.db").exists() {
                out.push(p);
            }
        }
    }
    out
}

fn mozilla_family_profile_dirs() -> Vec<std::path::PathBuf> {
    let home = std::env::var("HOME").unwrap_or_default();
    let appdata = std::env::var("APPDATA").ok();
    let xdg = std::env::var("XDG_CONFIG_HOME").ok();
    let roots = mozilla_family_profile_roots(
        std::env::consts::OS,
        &home,
        appdata.as_deref(),
        xdg.as_deref(),
    );
    discover_profile_dirs(&roots)
}
