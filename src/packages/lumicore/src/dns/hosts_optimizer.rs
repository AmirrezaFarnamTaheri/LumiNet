//! # DNS-over-HTTPS (DoH) Hosts Optimizer
//!
//! Resolves clean IP addresses for key domains using DoH, tests their TCP connection latencies
//! on port 443, and updates either the system hosts file (Windows/Linux) or registers them in
//! an in-memory bypass cache.
//!
//! Extracted from GitHub520-main.

use dashmap::DashMap;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Error, ErrorKind, Read};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::dns::resolve_doh;

/// Target domains to optimize.
pub const OPTIMIZE_DOMAINS: &[&str] = &[
    "alive.github.com",
    "api.github.com",
    "avatars.githubusercontent.com",
    "camo.githubusercontent.com",
    "codeload.github.com",
    "desktop.githubusercontent.com",
    "favicons.githubusercontent.com",
    "gist.github.com",
    "github-cloud.s3.amazonaws.com",
    "github-com.s3.amazonaws.com",
    "github.blog",
    "github.com",
    "github.io",
    "githubstatus.com",
    "media.githubusercontent.com",
    "objects.githubusercontent.com",
    "pipelines.actions.githubusercontent.com",
    "raw.githubusercontent.com",
    "user-images.githubusercontent.com",
];

/// In-memory host bypass mapping fallback (used when running without admin rights).
pub static IN_MEMORY_HOSTS: Lazy<DashMap<String, String>> = Lazy::new(DashMap::new);

/// Measure TCP connection latency on port 443 in milliseconds.
pub fn measure_tcp_latency(ip: &str, timeout: Duration) -> Option<u32> {
    let addr = format!("{}:443", ip).parse::<SocketAddr>().ok()?;
    let mut latencies = Vec::new();

    for _ in 0..3 {
        let start = Instant::now();
        if let Ok(_stream) = TcpStream::connect_timeout(&addr, timeout) {
            latencies.push(start.elapsed().as_millis() as u32);
        } else {
            latencies.push(timeout.as_millis() as u32);
        }
    }
    latencies.sort();
    // Return median value
    Some(latencies[1])
}

/// Query DoH endpoints to resolve IP lists for a domain, testing and returning the lowest latency IP.
pub async fn resolve_best_ip(domain: &str) -> Option<String> {
    let doh_server = "https://cloudflare-dns.com/dns-query";
    let mut ip_candidates = Vec::new();

    // Query DoH
    if let Ok(records) = resolve_doh(doh_server, domain, "A").await {
        for record in records {
            // Check if record is type A (IPv4 address)
            if record.record_type.to_uppercase() == "A" {
                ip_candidates.push(record.value.clone());
            }
        }
    }

    if ip_candidates.is_empty() {
        return None;
    }

    let mut best_ip = None;
    let mut min_latency = u32::MAX;

    for ip in ip_candidates {
        if let Some(latency) = measure_tcp_latency(&ip, Duration::from_secs(1)) {
            if latency < min_latency {
                min_latency = latency;
                best_ip = Some(ip);
            }
        }
    }

    best_ip
}

/// Retrieve the platform-specific hosts file path.
pub fn get_hosts_path() -> PathBuf {
    #[cfg(windows)]
    {
        PathBuf::from(r"C:\Windows\System32\drivers\etc\hosts")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/etc/hosts")
    }
}

/// Format hosts mappings into a structured block.
pub fn generate_hosts_block(mappings: &HashMap<String, String>) -> String {
    let mut block = String::new();
    block.push_str("# GitHub520 Host Start\n");
    for (domain, ip) in mappings {
        block.push_str(&format!("{:<30} {}\n", ip, domain));
    }
    block.push_str(&format!(
        "# Update time: {}\n",
        crate::security::current_time_sec()
    ));
    block.push_str("# GitHub520 Host End\n");
    block
}

fn restore_hosts_preimage(path: &std::path::Path, preimage: Option<&[u8]>) -> std::io::Result<()> {
    match preimage {
        Some(bytes) => fs::write(path, bytes),
        None => match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err),
        },
    }
}

fn write_hosts_transaction<F>(
    path: &std::path::Path,
    new_content: &[u8],
    write_candidate: F,
) -> std::io::Result<()>
where
    F: FnOnce(&std::path::Path, &[u8]) -> std::io::Result<()>,
{
    let preimage = if path.exists() {
        Some(fs::read(path)?)
    } else {
        None
    };

    if let Err(write_err) = write_candidate(path, new_content) {
        if let Err(restore_err) = restore_hosts_preimage(path, preimage.as_deref()) {
            return Err(Error::new(
                write_err.kind(),
                format!("hosts write failed: {write_err}; rollback failed: {restore_err}"),
            ));
        }
        return Err(write_err);
    }

    match fs::read(path) {
        Ok(actual) if actual == new_content => Ok(()),
        verification => {
            let verify_err = match verification {
                Ok(_) => Error::new(ErrorKind::InvalidData, "hosts verification mismatch"),
                Err(err) => err,
            };
            if let Err(restore_err) = restore_hosts_preimage(path, preimage.as_deref()) {
                return Err(Error::new(
                    verify_err.kind(),
                    format!("hosts verification failed: {verify_err}; rollback failed: {restore_err}"),
                ));
            }
            Err(verify_err)
        }
    }
}

/// Overwrites the system hosts file section block with the clean IPs mapping.
/// Returns true if updated successfully, or false if permission is denied.
pub fn update_system_hosts_file(mappings: &HashMap<String, String>) -> std::io::Result<()> {
    let path = get_hosts_path();
    let mut content = String::new();

    if path.exists() {
        let mut file = File::open(&path)?;
        file.read_to_string(&mut content)?;
    }

    let hosts_block = generate_hosts_block(mappings);
    let start_tag = "# GitHub520 Host Start";
    let end_tag = "# GitHub520 Host End";

    let new_content = if let Some(start_idx) = content.find(start_tag) {
        if let Some(end_idx) = content[start_idx..].find(end_tag) {
            let actual_end = start_idx + end_idx + end_tag.len();
            let mut prefix = content[..start_idx].to_string();
            let suffix = &content[actual_end..];
            prefix.push_str(&hosts_block);
            prefix.push_str(suffix);
            prefix
        } else {
            let mut prefix = content[..start_idx].to_string();
            prefix.push_str(&hosts_block);
            prefix
        }
    } else {
        let mut prefix = content.clone();
        if !prefix.ends_with('\n') && !prefix.is_empty() {
            prefix.push('\n');
        }
        prefix.push_str(&hosts_block);
        prefix
    };

    write_hosts_transaction(&path, new_content.as_bytes(), |target, bytes| {
        fs::write(target, bytes)
    })
}

/// Optimize hosts mappings for a custom domains list via DoH.
pub async fn optimize_hosts(domains: &[String]) -> HashMap<String, String> {
    let mut mappings = HashMap::new();

    for domain in domains {
        if let Some(best_ip) = resolve_best_ip(domain).await {
            mappings.insert(domain.clone(), best_ip.clone());
            // Sync to in-memory fallback cache
            IN_MEMORY_HOSTS.insert(domain.clone(), best_ip);
        }
    }

    // Try system hosts file update
    if let Err(err) = update_system_hosts_file(&mappings) {
        log::warn!(
            "Failed to update system-wide hosts file: {}. Fallback to in-memory proxy resolution.",
            err
        );
    } else {
        log::info!("System-wide hosts file updated successfully.");
    }

    mappings
}

/// Resolves target domains and updates the system hosts file OR falls back to the in-memory bypass cache.
pub async fn run_hosts_optimization() -> HashMap<String, String> {
    let mut mappings = HashMap::new();

    for &domain in OPTIMIZE_DOMAINS {
        if let Some(best_ip) = resolve_best_ip(domain).await {
            mappings.insert(domain.to_string(), best_ip.clone());
            // Sync to in-memory fallback cache
            IN_MEMORY_HOSTS.insert(domain.to_string(), best_ip);
        }
    }

    // Try system hosts file update
    if let Err(err) = update_system_hosts_file(&mappings) {
        log::warn!(
            "Failed to update system-wide hosts file: {}. Fallback to in-memory proxy resolution.",
            err
        );
    } else {
        log::info!("System-wide hosts file updated successfully.");
    }

    mappings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hosts_block_generation() {
        let mut mappings = HashMap::new();
        mappings.insert("github.com".to_string(), "140.82.113.3".to_string());
        let block = generate_hosts_block(&mappings);
        assert!(block.contains("# GitHub520 Host Start"));
        assert!(block.contains("140.82.113.3"));
        assert!(block.contains("github.com"));
        assert!(block.contains("# GitHub520 Host End"));
    }

    #[test]
    fn test_hosts_transaction_rolls_back_exact_preimage_on_verification_failure() {
        let path = std::env::temp_dir().join(format!(
            "luminet-hosts-rollback-{}-{}",
            std::process::id(),
            crate::security::current_time_sec()
        ));
        let original = b"127.0.0.1 localhost\n# exact preimage\n";
        fs::write(&path, original).unwrap();

        let result = write_hosts_transaction(&path, b"new contents\n", |target, _| {
            fs::write(target, b"corrupted contents\n")
        });

        assert!(result.is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_hosts_transaction_removes_failed_new_file() {
        let path = std::env::temp_dir().join(format!(
            "luminet-hosts-new-{}-{}",
            std::process::id(),
            crate::security::current_time_sec()
        ));
        let _ = fs::remove_file(&path);

        let result = write_hosts_transaction(&path, b"new contents\n", |target, _| {
            fs::write(target, b"wrong contents\n")
        });

        assert!(result.is_err());
        assert!(!path.exists());
    }

    #[test]
    fn test_hosts_path() {
        let path = get_hosts_path();
        assert!(path.to_str().unwrap().contains("hosts"));
    }
}
