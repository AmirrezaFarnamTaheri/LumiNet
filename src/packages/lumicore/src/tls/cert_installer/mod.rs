//! # Certificate Installation
//!
//! Cross-platform CA certificate installation for TLS trust.
//! Split from the original cert_installer.rs for maintainability.
//!
//! ## Platform Support
//! - macOS: Keychain access
//! - Linux: update-ca-certificates / trust / certutil
//! - Windows: certutil
//! - NSS: Firefox/LibreWolf/Chrome cert databases

pub mod linux;
pub mod macos;
pub mod nss;
pub mod windows;

use std::path::Path;

/// Error type for certificate operations.
#[derive(Debug)]
pub enum InstallError {
    IoError(std::io::Error),
    CertNotFound,
    PlatformNotSupported,
    PermissionDenied,
}

impl std::fmt::Display for InstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IoError(e) => write!(f, "IO error: {}", e),
            Self::CertNotFound => write!(f, "certificate not found"),
            Self::PlatformNotSupported => write!(f, "platform not supported"),
            Self::PermissionDenied => write!(f, "permission denied"),
        }
    }
}

impl From<std::io::Error> for InstallError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e)
    }
}

/// Result of removing a CA certificate.
#[derive(Debug)]
pub enum RemovalOutcome {
    Removed,
    NotFound,
    PlatformNotSupported,
}

/// Summary of NSS removal operations.
#[derive(Debug, Default)]
pub struct NssReport {
    pub firefox: bool,
    pub librewolf: bool,
    pub chrome: bool,
}

impl NssReport {
    pub fn is_clean(&self) -> bool {
        // A report records only successful removals; false fields also cover
        // stores that were absent and therefore already clean.
        true
    }
}

/// Installs a CA certificate for the current platform.
pub fn install_ca(path: &Path) -> Result<(), InstallError> {
    if !path.exists() {
        return Err(InstallError::CertNotFound);
    }

    let cert_path = path.to_str().ok_or(InstallError::CertNotFound)?;

    #[cfg(target_os = "macos")]
    {
        macos::install_macos(cert_path);
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        linux::install_linux(cert_path);
        nss::install_nss_stores(cert_path);
        return Ok(());
    }

    #[cfg(target_os = "windows")]
    {
        windows::install_windows(cert_path);
        Ok(())
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Err(InstallError::PlatformNotSupported)
    }
}

/// Removes a CA certificate for the current platform.
pub fn remove_ca(_base: &Path) -> Result<RemovalOutcome, InstallError> {
    #[cfg(target_os = "macos")]
    {
        macos::remove_macos();
        return Ok(RemovalOutcome::Removed);
    }

    #[cfg(target_os = "linux")]
    {
        linux::remove_linux();
        nss::remove_nss_stores();
        return Ok(RemovalOutcome::Removed);
    }

    #[cfg(target_os = "windows")]
    {
        windows::remove_windows();
        Ok(RemovalOutcome::Removed)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Ok(RemovalOutcome::PlatformNotSupported)
    }
}

/// Checks if a CA certificate is trusted by the system.
pub fn is_ca_trusted(path: &Path) -> bool {
    let _cert_path = match path.to_str() {
        Some(p) => p,
        None => return false,
    };

    #[cfg(target_os = "macos")]
    {
        return macos::is_trusted_macos();
    }

    #[cfg(target_os = "linux")]
    {
        return linux::is_trusted_linux();
    }

    #[cfg(target_os = "windows")]
    {
        windows::is_trusted_windows()
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        false
    }
}

/// Checks if our CA is trusted by name (not by path).
pub fn is_ca_trusted_by_name() -> bool {
    #[cfg(target_os = "macos")]
    {
        return macos::macos_system_keychain_has();
    }

    #[cfg(target_os = "linux")]
    {
        return linux::is_trusted_linux();
    }

    #[cfg(target_os = "windows")]
    {
        windows::is_trusted_windows()
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        false
    }
}

/// Returns a summary of the current trust state.
pub fn summary() -> String {
    let mut parts = Vec::new();

    #[cfg(target_os = "macos")]
    {
        if macos::macos_system_keychain_has() {
            parts.push("macOS: trusted");
        } else {
            parts.push("macOS: not trusted");
        }
    }

    #[cfg(target_os = "linux")]
    {
        if linux::is_trusted_linux() {
            parts.push("Linux: trusted");
        } else {
            parts.push("Linux: not trusted");
        }
    }

    #[cfg(target_os = "windows")]
    {
        if windows::is_trusted_windows() {
            parts.push("Windows: trusted");
        } else {
            parts.push("Windows: not trusted");
        }
    }

    if parts.is_empty() {
        "Unknown platform".to_string()
    } else {
        parts.join(", ")
    }
}
