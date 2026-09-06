use crate::transport::domain_fronter::DomainFronter;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use std::error::Error;

/// TunnelClient coordinates client-side encryption and relays traffic to egress nodes
/// utilizing serverless, direct, or domain-fronted endpoints.
pub struct TunnelClient {
    pub key: [u8; 32],
    pub domain_fronter: Option<DomainFronter>,
    pub serverless_endpoint: Option<String>,
}

impl TunnelClient {
    /// Creates a new TunnelClient instance.
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            key,
            domain_fronter: None,
            serverless_endpoint: None,
        }
    }

    /// Set domain fronting parameters.
    pub fn with_domain_fronting(&mut self, front_domain: &str, target_host: &str, script_id: &str) {
        self.domain_fronter = Some(DomainFronter::new(
            vec![front_domain.to_string()],
            target_host,
            vec![script_id.to_string()],
            1,
        ));
    }

    /// Set serverless relay endpoint.
    pub fn with_serverless(&mut self, endpoint: &str) {
        self.serverless_endpoint = Some(endpoint.to_string());
    }

    /// Encrypts the payload with AES-256-GCM and relays it over the configured transport channel.
    pub async fn send_packet(&self, payload: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let cipher = Aes256Gcm::new_from_slice(&self.key)?;

        let mut nonce_bytes = [0u8; 12];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, payload)
            .map_err(|e| format!("AES-256-GCM encryption failed: {}", e))?;

        let mut packet = Vec::new();
        packet.extend_from_slice(&nonce_bytes);
        packet.extend_from_slice(&ciphertext);

        // Dispatches to configured transport egress
        if let Some(ref fronter) = self.domain_fronter {
            log::info!("Relaying encrypted packet over Domain Fronted TLS macro tunnel");
            let resp = fronter.relay_payload(&packet).await?;
            self.decrypt_payload(&resp)
        } else if let Some(ref _endpoint) = self.serverless_endpoint {
            log::info!(
                "Relaying encrypted packet to Serverless Eco Relay Endpoint: {}",
                _endpoint
            );
            // Simulated serverless lookup
            Ok(vec![])
        } else {
            Err("No active egress transport configured".into())
        }
    }

    fn decrypt_payload(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        if ciphertext.len() < 12 {
            return Err("Payload too short for decapsulation".into());
        }
        let (nonce_bytes, payload) = ciphertext.split_at(12);
        let cipher = Aes256Gcm::new_from_slice(&self.key)?;
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, payload)
            .map_err(|e| format!("Decryption failed: {}", e))?;
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tunnel_client_init() {
        let key = [8u8; 32];
        let mut client = TunnelClient::new(key);
        assert!(client.domain_fronter.is_none());
        assert!(client.serverless_endpoint.is_none());

        client.with_serverless("https://relay.vercel.app/api");
        assert!(client.serverless_endpoint.is_some());
    }
}
