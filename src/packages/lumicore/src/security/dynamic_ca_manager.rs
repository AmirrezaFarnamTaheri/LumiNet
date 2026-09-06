use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct GeneratedCert {
    pub common_name: String,
    pub serial_number: u64,
    pub not_before_epoch: u64,
    pub not_after_epoch: u64,
    pub cert_der: Vec<u8>,
}

#[derive(Debug)]
pub struct DynamicCaManager {
    ca_name: String,
    serial_counter: u64,
    cert_cache: HashMap<String, GeneratedCert>,
}

impl DynamicCaManager {
    pub fn new(ca_name: &str) -> Self {
        Self {
            ca_name: ca_name.to_string(),
            serial_counter: 1000,
            cert_cache: HashMap::new(),
        }
    }

    pub fn issue_or_get_cert(&mut self, common_name: &str, valid_duration_secs: u64, now_epoch: u64) -> GeneratedCert {
        if let Some(cached) = self.cert_cache.get(common_name) {
            if now_epoch < cached.not_after_epoch {
                return cached.clone();
            }
        }

        self.serial_counter += 1;
        let mut der_mock = Vec::new();
        der_mock.extend_from_slice(b"LUMI-MOCK-CERT:");
        der_mock.extend_from_slice(common_name.as_bytes());
        der_mock.extend_from_slice(&self.serial_counter.to_be_bytes());

        let cert = GeneratedCert {
            common_name: common_name.to_string(),
            serial_number: self.serial_counter,
            not_before_epoch: now_epoch,
            not_after_epoch: now_epoch + valid_duration_secs,
            cert_der: der_mock,
        };

        self.cert_cache.insert(common_name.to_string(), cert.clone());
        cert
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dynamic_ca_certificate_issuance() {
        let mut ca = DynamicCaManager::new("LumiNet Root CA");
        let cert1 = ca.issue_or_get_cert("api.example.com", 3600, 1000);

        assert_eq!(cert1.common_name, "api.example.com");
        assert_eq!(cert1.not_after_epoch, 4600);

        // Cache hit
        let cert2 = ca.issue_or_get_cert("api.example.com", 3600, 2000);
        assert_eq!(cert1.serial_number, cert2.serial_number);

        // New domain
        let cert3 = ca.issue_or_get_cert("login.example.com", 3600, 2000);
        assert_ne!(cert1.serial_number, cert3.serial_number);
    }
}
