//! Client TLS fingerprint emulation (uTLS/browser-impersonation).

#[derive(Clone, Debug)]
pub struct FingerprintParams {
    pub cipher_list: String,
    pub curves_list: String,
    pub grease: bool,
    pub permute_extensions: bool,
    pub sigalgs_list: String,
}

impl FingerprintParams {
    pub fn get_cipher_list(&self) -> &str {
        &self.cipher_list
    }

    pub fn set_cipher_list(&mut self, val: String) {
        self.cipher_list = val;
    }

    pub fn get_curves_list(&self) -> &str {
        &self.curves_list
    }

    pub fn set_curves_list(&mut self, val: String) {
        self.curves_list = val;
    }

    pub fn get_grease(&self) -> bool {
        self.grease
    }

    pub fn set_grease(&mut self, val: bool) {
        self.grease = val;
    }

    pub fn get_permute_extensions(&self) -> bool {
        self.permute_extensions
    }

    pub fn set_permute_extensions(&mut self, val: bool) {
        self.permute_extensions = val;
    }

    pub fn get_sigalgs_list(&self) -> &str {
        &self.sigalgs_list
    }

    pub fn set_sigalgs_list(&mut self, val: String) {
        self.sigalgs_list = val;
    }
}

pub struct FingerprintBuilder {
    cipher_list: String,
    curves_list: String,
    grease: bool,
    permute_extensions: bool,
    sigalgs_list: String,
    alpn_protocols: Vec<String>,
    min_version: Option<u16>,
    max_version: Option<u16>,
    cert_verification: bool,
    sni_override: Option<String>,
    session_tickets: bool,
    early_data: bool,
    ech_config: Option<Vec<u8>>,
    key_shares: Vec<u16>,
    signature_algorithms: Vec<u16>,
}

impl Default for FingerprintBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl FingerprintBuilder {
    pub fn new() -> Self {
        Self {
            cipher_list: String::new(),
            curves_list: String::new(),
            grease: false,
            permute_extensions: false,
            sigalgs_list: String::new(),
            alpn_protocols: Vec::new(),
            min_version: None,
            max_version: None,
            cert_verification: true,
            sni_override: None,
            session_tickets: true,
            early_data: false,
            ech_config: None,
            key_shares: Vec::new(),
            signature_algorithms: Vec::new(),
        }
    }

    // Getters
    pub fn get_cipher_list(&self) -> &str {
        &self.cipher_list
    }
    pub fn get_curves_list(&self) -> &str {
        &self.curves_list
    }
    pub fn get_grease(&self) -> bool {
        self.grease
    }
    pub fn get_permute_extensions(&self) -> bool {
        self.permute_extensions
    }
    pub fn get_sigalgs_list(&self) -> &str {
        &self.sigalgs_list
    }
    pub fn get_alpn_protocols(&self) -> &[String] {
        &self.alpn_protocols
    }
    pub fn get_min_version(&self) -> Option<u16> {
        self.min_version
    }
    pub fn get_max_version(&self) -> Option<u16> {
        self.max_version
    }
    pub fn get_cert_verification(&self) -> bool {
        self.cert_verification
    }
    pub fn get_sni_override(&self) -> Option<&str> {
        self.sni_override.as_deref()
    }
    pub fn get_session_tickets(&self) -> bool {
        self.session_tickets
    }
    pub fn get_early_data(&self) -> bool {
        self.early_data
    }
    pub fn get_ech_config(&self) -> Option<&[u8]> {
        self.ech_config.as_deref()
    }
    pub fn get_key_shares(&self) -> &[u16] {
        &self.key_shares
    }
    pub fn get_signature_algorithms(&self) -> &[u16] {
        &self.signature_algorithms
    }

    // Setters
    pub fn set_cipher_list(&mut self, val: String) {
        self.cipher_list = val;
    }
    pub fn set_curves_list(&mut self, val: String) {
        self.curves_list = val;
    }
    pub fn set_grease(&mut self, val: bool) {
        self.grease = val;
    }
    pub fn set_permute_extensions(&mut self, val: bool) {
        self.permute_extensions = val;
    }
    pub fn set_sigalgs_list(&mut self, val: String) {
        self.sigalgs_list = val;
    }
    pub fn set_alpn_protocols(&mut self, val: Vec<String>) {
        self.alpn_protocols = val;
    }
    pub fn set_min_version(&mut self, val: Option<u16>) {
        self.min_version = val;
    }
    pub fn set_max_version(&mut self, val: Option<u16>) {
        self.max_version = val;
    }
    pub fn set_cert_verification(&mut self, val: bool) {
        self.cert_verification = val;
    }
    pub fn set_sni_override(&mut self, val: Option<String>) {
        self.sni_override = val;
    }
    pub fn set_session_tickets(&mut self, val: bool) {
        self.session_tickets = val;
    }
    pub fn set_early_data(&mut self, val: bool) {
        self.early_data = val;
    }
    pub fn set_ech_config(&mut self, val: Option<Vec<u8>>) {
        self.ech_config = val;
    }
    pub fn set_key_shares(&mut self, val: Vec<u16>) {
        self.key_shares = val;
    }
    pub fn set_signature_algorithms(&mut self, val: Vec<u16>) {
        self.signature_algorithms = val;
    }

    // Builders (Fluent Interface)
    pub fn with_cipher_list(mut self, val: String) -> Self {
        self.cipher_list = val;
        self
    }
    pub fn with_curves_list(mut self, val: String) -> Self {
        self.curves_list = val;
        self
    }
    pub fn with_grease(mut self, val: bool) -> Self {
        self.grease = val;
        self
    }
    pub fn with_permute_extensions(mut self, val: bool) -> Self {
        self.permute_extensions = val;
        self
    }
    pub fn with_sigalgs_list(mut self, val: String) -> Self {
        self.sigalgs_list = val;
        self
    }
    pub fn with_alpn_protocols(mut self, val: Vec<String>) -> Self {
        self.alpn_protocols = val;
        self
    }
    pub fn with_min_version(mut self, val: Option<u16>) -> Self {
        self.min_version = val;
        self
    }
    pub fn with_max_version(mut self, val: Option<u16>) -> Self {
        self.max_version = val;
        self
    }
    pub fn with_cert_verification(mut self, val: bool) -> Self {
        self.cert_verification = val;
        self
    }
    pub fn with_sni_override(mut self, val: Option<String>) -> Self {
        self.sni_override = val;
        self
    }
    pub fn with_session_tickets(mut self, val: bool) -> Self {
        self.session_tickets = val;
        self
    }
    pub fn with_early_data(mut self, val: bool) -> Self {
        self.early_data = val;
        self
    }
    pub fn with_ech_config(mut self, val: Option<Vec<u8>>) -> Self {
        self.ech_config = val;
        self
    }
    pub fn with_key_shares(mut self, val: Vec<u16>) -> Self {
        self.key_shares = val;
        self
    }
    pub fn with_signature_algorithms(mut self, val: Vec<u16>) -> Self {
        self.signature_algorithms = val;
        self
    }

    // Array / List Modifiers
    pub fn add_alpn_protocol(&mut self, proto: String) {
        self.alpn_protocols.push(proto);
    }
    pub fn remove_alpn_protocol(&mut self, proto: &str) -> bool {
        if let Some(pos) = self.alpn_protocols.iter().position(|x| x == proto) {
            self.alpn_protocols.remove(pos);
            true
        } else {
            false
        }
    }
    pub fn add_key_share(&mut self, val: u16) {
        self.key_shares.push(val);
    }
    pub fn remove_key_share(&mut self, val: u16) -> bool {
        if let Some(pos) = self.key_shares.iter().position(|&x| x == val) {
            self.key_shares.remove(pos);
            true
        } else {
            false
        }
    }
    pub fn add_signature_algorithm(&mut self, val: u16) {
        self.signature_algorithms.push(val);
    }
    pub fn remove_signature_algorithm(&mut self, val: u16) -> bool {
        if let Some(pos) = self.signature_algorithms.iter().position(|&x| x == val) {
            self.signature_algorithms.remove(pos);
            true
        } else {
            false
        }
    }

    // Cleanups
    pub fn clear_alpn_protocols(&mut self) {
        self.alpn_protocols.clear();
    }
    pub fn clear_key_shares(&mut self) {
        self.key_shares.clear();
    }
    pub fn clear_signature_algorithms(&mut self) {
        self.signature_algorithms.clear();
    }

    // Helpers
    pub fn build(self) -> FingerprintParams {
        FingerprintParams {
            cipher_list: self.cipher_list,
            curves_list: self.curves_list,
            grease: self.grease,
            permute_extensions: self.permute_extensions,
            sigalgs_list: self.sigalgs_list,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ClientHelloFingerprint {
    pub ja3_fingerprint: String,
    pub ja4_fingerprint: String,
    pub negotiated_cipher: u16,
    pub negotiated_version: u16,
    pub extensions_count: usize,
    pub supported_groups: Vec<u16>,
    pub supported_points: Vec<u8>,
    pub alpns: Vec<String>,
    pub signature_schemes: Vec<u16>,
    pub key_share_curves: Vec<u16>,
    pub sni_hostname: Option<String>,
    pub session_id: Vec<u8>,
    pub ticket_lifetime: u32,
    pub grease_present: bool,
    pub ech_extension_present: bool,
}

impl ClientHelloFingerprint {
    pub fn new() -> Self {
        Self::default()
    }

    // Getters
    pub fn get_ja3_fingerprint(&self) -> &str {
        &self.ja3_fingerprint
    }
    pub fn get_ja4_fingerprint(&self) -> &str {
        &self.ja4_fingerprint
    }
    pub fn get_negotiated_cipher(&self) -> u16 {
        self.negotiated_cipher
    }
    pub fn get_negotiated_version(&self) -> u16 {
        self.negotiated_version
    }
    pub fn get_extensions_count(&self) -> usize {
        self.extensions_count
    }
    pub fn get_supported_groups(&self) -> &[u16] {
        &self.supported_groups
    }
    pub fn get_supported_points(&self) -> &[u8] {
        &self.supported_points
    }
    pub fn get_alpns(&self) -> &[String] {
        &self.alpns
    }
    pub fn get_signature_schemes(&self) -> &[u16] {
        &self.signature_schemes
    }
    pub fn get_key_share_curves(&self) -> &[u16] {
        &self.key_share_curves
    }
    pub fn get_sni_hostname(&self) -> Option<&str> {
        self.sni_hostname.as_deref()
    }
    pub fn get_session_id(&self) -> &[u8] {
        &self.session_id
    }
    pub fn get_ticket_lifetime(&self) -> u32 {
        self.ticket_lifetime
    }
    pub fn get_grease_present(&self) -> bool {
        self.grease_present
    }
    pub fn get_ech_extension_present(&self) -> bool {
        self.ech_extension_present
    }

    // Setters
    pub fn set_ja3_fingerprint(&mut self, val: String) {
        self.ja3_fingerprint = val;
    }
    pub fn set_ja4_fingerprint(&mut self, val: String) {
        self.ja4_fingerprint = val;
    }
    pub fn set_negotiated_cipher(&mut self, val: u16) {
        self.negotiated_cipher = val;
    }
    pub fn set_negotiated_version(&mut self, val: u16) {
        self.negotiated_version = val;
    }
    pub fn set_extensions_count(&mut self, val: usize) {
        self.extensions_count = val;
    }
    pub fn set_supported_groups(&mut self, val: Vec<u16>) {
        self.supported_groups = val;
    }
    pub fn set_supported_points(&mut self, val: Vec<u8>) {
        self.supported_points = val;
    }
    pub fn set_alpns(&mut self, val: Vec<String>) {
        self.alpns = val;
    }
    pub fn set_signature_schemes(&mut self, val: Vec<u16>) {
        self.signature_schemes = val;
    }
    pub fn set_key_share_curves(&mut self, val: Vec<u16>) {
        self.key_share_curves = val;
    }
    pub fn set_sni_hostname(&mut self, val: Option<String>) {
        self.sni_hostname = val;
    }
    pub fn set_session_id(&mut self, val: Vec<u8>) {
        self.session_id = val;
    }
    pub fn set_ticket_lifetime(&mut self, val: u32) {
        self.ticket_lifetime = val;
    }
    pub fn set_grease_present(&mut self, val: bool) {
        self.grease_present = val;
    }
    pub fn set_ech_extension_present(&mut self, val: bool) {
        self.ech_extension_present = val;
    }

    // Builders
    pub fn with_ja3_fingerprint(mut self, val: String) -> Self {
        self.ja3_fingerprint = val;
        self
    }
    pub fn with_ja4_fingerprint(mut self, val: String) -> Self {
        self.ja4_fingerprint = val;
        self
    }
    pub fn with_negotiated_cipher(mut self, val: u16) -> Self {
        self.negotiated_cipher = val;
        self
    }
    pub fn with_negotiated_version(mut self, val: u16) -> Self {
        self.negotiated_version = val;
        self
    }
    pub fn with_extensions_count(mut self, val: usize) -> Self {
        self.extensions_count = val;
        self
    }
    pub fn with_supported_groups(mut self, val: Vec<u16>) -> Self {
        self.supported_groups = val;
        self
    }
    pub fn with_supported_points(mut self, val: Vec<u8>) -> Self {
        self.supported_points = val;
        self
    }
    pub fn with_alpns(mut self, val: Vec<String>) -> Self {
        self.alpns = val;
        self
    }
    pub fn with_signature_schemes(mut self, val: Vec<u16>) -> Self {
        self.signature_schemes = val;
        self
    }
    pub fn with_key_share_curves(mut self, val: Vec<u16>) -> Self {
        self.key_share_curves = val;
        self
    }
    pub fn with_sni_hostname(mut self, val: Option<String>) -> Self {
        self.sni_hostname = val;
        self
    }
    pub fn with_session_id(mut self, val: Vec<u8>) -> Self {
        self.session_id = val;
        self
    }
    pub fn with_ticket_lifetime(mut self, val: u32) -> Self {
        self.ticket_lifetime = val;
        self
    }
    pub fn with_grease_present(mut self, val: bool) -> Self {
        self.grease_present = val;
        self
    }
    pub fn with_ech_extension_present(mut self, val: bool) -> Self {
        self.ech_extension_present = val;
        self
    }
}
