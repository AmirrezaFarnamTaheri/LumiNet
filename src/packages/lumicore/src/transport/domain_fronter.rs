
use dashmap::DashMap;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, Stream};
use std::error::Error;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Per-script blacklist entry to avoid slow container instances
pub struct BlacklistEntry {
    pub blacklisted_until: Instant,
}

/// DomainFronter wraps connection handshakes and HTTP payloads inside domain-fronted TLS tunnels.
/// Supports SNI pool rotation, multi-script round-robin, fan-out parallel relays, and container blacklisting.
pub struct DomainFronter {
    pub front_domains: Vec<String>,
    pub target_host: String,
    pub script_ids: Vec<String>,
    pub parallel_relay: usize,
    pub config: Arc<ClientConfig>,
    pub front_index: AtomicUsize,
    pub script_index: AtomicUsize,
    pub blacklist: Arc<DashMap<String, BlacklistEntry>>,
}

impl DomainFronter {
    /// Creates a new DomainFronter instance.
    pub fn new(
        front_domains: Vec<String>,
        target_host: &str,
        script_ids: Vec<String>,
        parallel_relay: usize,
    ) -> Self {
        // Prepare rustls client config with system roots
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(root_store)
                .with_no_client_auth();

        Self {
            front_domains,
            target_host: target_host.to_string(),
            script_ids,
            parallel_relay: parallel_relay.max(1),
            config: Arc::new(config),
            front_index: AtomicUsize::new(0),
            script_index: AtomicUsize::new(0),
            blacklist: Arc::new(DashMap::new()),
        }
    }

    /// Get next available fronting domain using round-robin rotation
    fn next_front_domain(&self) -> String {
        if self.front_domains.is_empty() {
            return "www.google.com".to_string();
        }
        let idx = self.front_index.fetch_add(1, Ordering::SeqCst) % self.front_domains.len();
        self.front_domains[idx].clone()
    }

    /// Get next available script ID (filtering out blacklisted ones if possible)
    fn next_script_id(&self) -> String {
        if self.script_ids.is_empty() {
            return String::new();
        }

        let now = Instant::now();
        // Try up to self.script_ids.len() times to find a non-blacklisted script
        for _ in 0..self.script_ids.len() {
            let idx = self.script_index.fetch_add(1, Ordering::SeqCst) % self.script_ids.len();
            let sid = &self.script_ids[idx];

            if let Some(entry) = self.blacklist.get(sid) {
                if entry.blacklisted_until > now {
                    continue;
                }
            }
            return sid.clone();
        }

        // Fallback to absolute round robin if all are blacklisted
        let idx = self.script_index.load(Ordering::SeqCst) % self.script_ids.len();
        self.script_ids[idx].clone()
    }

    /// Blacklists a slow or failing script container
    fn blacklist_script(&self, script_id: String, duration: Duration) {
        let until = Instant::now() + duration;
        self.blacklist.insert(
            script_id,
            BlacklistEntry {
                blacklisted_until: until,
            },
        );
    }

    /// Connects to a single target and performs domain-fronted TLS payload POST
    fn execute_single_relay(
        config: Arc<ClientConfig>,
        front_domain: String,
        target_host: String,
        script_id: String,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        let addr = format!("{}:443", front_domain);
        let mut tcp = TcpStream::connect_timeout(
            &addr
                .parse()
                .unwrap_or("216.239.38.120:443".parse().unwrap()),
            Duration::from_secs(5),
        )?;

        let server_name = ServerName::try_from(front_domain.as_str())
            .map_err(|e| format!("Invalid server name: {}", e))?
            .to_owned();

        let mut conn = ClientConnection::new(config, server_name)?;
        let mut stream = Stream::new(&mut conn, &mut tcp);

        let req_path = format!("/macros/s/{}/exec", script_id);
        let body = base64::Engine::encode(&base64::prelude::BASE64_STANDARD, &payload);

        let http_request = format!(
            "POST {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Content-Type: application/octet-stream\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n\
             {}",
            req_path,
            target_host,
            body.len(),
            body
        );

        stream.write_all(http_request.as_bytes())?;
        stream.flush()?;

        let mut response = Vec::new();
        let mut temp_buf = [0u8; 4096];
        loop {
            match stream.read(&mut temp_buf) {
                Ok(0) => break,
                Ok(n) => response.extend_from_slice(&temp_buf[..n]),
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(Box::new(e)),
            }
        }

        let response_str = String::from_utf8_lossy(&response);
        let body_parts: Vec<&str> = response_str.split("\r\n\r\n").collect();
        if body_parts.len() < 2 {
            return Err("Malformed HTTP response".into());
        }

        let body_content = body_parts[1].trim();
        let decoded = base64::Engine::decode(&base64::prelude::BASE64_STANDARD, body_content)?;
        Ok(decoded)
    }

    /// Performs the domain-fronted TLS payload POST with parallel fan-out options
    pub async fn relay_payload(&self, payload: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let parallel_count = self.parallel_relay;

        if parallel_count <= 1 {
            let front_domain = self.next_front_domain();
            let script_id = self.next_script_id();
            let config_clone = Arc::clone(&self.config);
            let target_host = self.target_host.clone();
            let payload_vec = payload.to_vec();

            let res = tokio::task::spawn_blocking(move || {
                Self::execute_single_relay(
                    config_clone,
                    front_domain,
                    target_host,
                    script_id.clone(),
                    payload_vec,
                )
                .map_err(|e| (e.to_string(), script_id))
            })
            .await?;

            return match res {
                Ok(data) => Ok(data),
                Err((e, sid)) => {
                    self.blacklist_script(sid, Duration::from_secs(60));
                    Err(e.into())
                }
            };
        }

        // Fan-out parallel relay: fire multiple Apps Script instances concurrently
        let mut tasks = Vec::new();
        for _ in 0..parallel_count {
            let front_domain = self.next_front_domain();
            let script_id = self.next_script_id();
            let config_clone = Arc::clone(&self.config);
            let target_host = self.target_host.clone();
            let payload_vec = payload.to_vec();

            let task = tokio::spawn(async move {
                tokio::task::spawn_blocking(move || {
                    Self::execute_single_relay(
                        config_clone,
                        front_domain,
                        target_host,
                        script_id.clone(),
                        payload_vec,
                    )
                    .map_err(|e| (e.to_string(), script_id))
                })
                .await
            });
            tasks.push(task);
        }

        // Wait for the first successful response
        let mut last_error = None;
        for task in tasks {
            match task.await {
                Ok(Ok(Ok(data))) => {
                    // Return first success
                    return Ok(data);
                }
                Ok(Ok(Err((e, sid)))) => {
                    // Single instance failure, blacklist the script
                    self.blacklist_script(sid, Duration::from_secs(60));
                    last_error = Some(e);
                }
                Ok(Err(e)) => {
                    last_error = Some(e.to_string());
                }
                Err(e) => {
                    last_error = Some(e.to_string());
                }
            }
        }

        Err(last_error
            .unwrap_or_else(|| "All parallel relay connections failed".to_string())
            .into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_fronter_init() {
        let fronter = DomainFronter::new(
            vec!["www.google.com".to_string()],
            "script.google.com",
            vec!["AKfycbx12345".to_string()],
            2,
        );
        assert_eq!(fronter.target_host, "script.google.com");
    }
}
