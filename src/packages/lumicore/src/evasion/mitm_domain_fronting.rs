//! # MITM Domain Fronting (MMDF) Router & TLS Repacker
//!
//! Provides local TLS interception with custom CA and upstream domain-fronted TLS repack.
//! Enables direct access to CDN-fronted services by decoupling client SNI from CDN edge SNI
//! while enforcing strict multi-SAN peer certificate validation.
//! Conforms to §8 structural cleanroom rules.

use std::collections::HashSet;

/// Supported ALPN negotiation modes for decrypted inbounds and repacked outbounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MitmAlpn {
    Http11,
    Http2,
    Http2And11,
}

impl MitmAlpn {
    pub fn as_slice(&self) -> &'static [&'static str] {
        match self {
            MitmAlpn::Http11 => &["http/1.1"],
            MitmAlpn::Http2 => &["h2"],
            MitmAlpn::Http2And11 => &["h2", "http/1.1"],
        }
    }
}

/// Outbound action decided by the fronting router.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrontingAction {
    /// Forward traffic directly without fronting or decryption.
    Direct,
    /// Block connection immediately.
    Block,
    /// Redirect to local MITM decryption port (11666 for H1.1, 11777 for H2/H1.1).
    RedirectToMitm { port: u16 },
    /// Repack decrypted stream into domain-fronted outbound TLS session.
    RepackFronted {
        fronted_sni: String,
        allowed_sans: Vec<String>,
        redirect_endpoint: Option<String>,
        alpn: MitmAlpn,
    },
}

/// A target fronting profile specifying safe SNI and valid SAN pool.
#[derive(Debug, Clone)]
pub struct FrontingTargetProfile {
    pub name: String,
    pub fronted_sni: String,
    pub allowed_sans: Vec<String>,
    pub redirect_endpoint: Option<String>,
    pub alpn: MitmAlpn,
}

impl FrontingTargetProfile {
    /// Creates the standard Google fronting profile (fronted via google.com edge).
    pub fn google_default() -> Self {
        Self {
            name: "google".to_string(),
            fronted_sni: "www.google.com".to_string(),
            allowed_sans: vec![
                "www.google.com".to_string(),
                "*.google.com".to_string(),
                "dns.google".to_string(),
                "www.googlevideo.com".to_string(),
                "*.googlevideo.com".to_string(),
                "www.youtube.com".to_string(),
                "*.youtube.com".to_string(),
            ],
            redirect_endpoint: None,
            alpn: MitmAlpn::Http2And11,
        }
    }

    /// Creates Google Video profile strictly enforcing HTTP/1.1 to prevent H2 stall.
    pub fn google_video() -> Self {
        let mut prof = Self::google_default();
        prof.name = "google-video".to_string();
        prof.alpn = MitmAlpn::Http11;
        prof
    }

    /// Creates the Fastly edge fronting profile (fronted via githubassets.com).
    pub fn fastly_default() -> Self {
        Self {
            name: "fastly".to_string(),
            fronted_sni: "github.githubassets.com".to_string(),
            allowed_sans: vec![
                "github.githubassets.com".to_string(),
                "githubassets.com".to_string(),
                "*.githubassets.com".to_string(),
                "github.com".to_string(),
                "*.github.com".to_string(),
                "fastly.com".to_string(),
                "*.fastly.com".to_string(),
                "reddit.com".to_string(),
                "*.reddit.com".to_string(),
                "pypi.org".to_string(),
                "*.python.org".to_string(),
            ],
            redirect_endpoint: Some("github.githubassets.com:443".to_string()),
            alpn: MitmAlpn::Http2And11,
        }
    }

    /// Creates the Meta / WhatsApp / Instagram fronting profile.
    pub fn meta_default() -> Self {
        Self {
            name: "meta".to_string(),
            fronted_sni: "www.microsoft.com".to_string(),
            allowed_sans: vec![
                "www.whatsapp.com".to_string(),
                "*.whatsapp.com".to_string(),
                "*.whatsapp.net".to_string(),
                "www.facebook.com".to_string(),
                "*.facebook.com".to_string(),
                "*.fbcdn.net".to_string(),
                "www.instagram.com".to_string(),
                "*.instagram.com".to_string(),
                "*.cdninstagram.com".to_string(),
                "*.meta.com".to_string(),
            ],
            redirect_endpoint: None,
            alpn: MitmAlpn::Http2And11,
        }
    }

    /// Validates whether any presented server certificate SAN satisfies the allowed SANs.
    pub fn verify_peer_sans(&self, presented_sans: &[String]) -> bool {
        for presented in presented_sans {
            for allowed in &self.allowed_sans {
                if match_san_pattern(presented, allowed) {
                    return true;
                }
            }
        }
        false
    }
}

/// Evaluates wildcard and exact SAN matches according to RFC 6125.
pub fn match_san_pattern(presented: &str, pattern: &str) -> bool {
    let pres = presented.to_ascii_lowercase();
    let pat = pattern.to_ascii_lowercase();

    if pres == pat {
        return true;
    }

    if let Some(suffix) = pat.strip_prefix("*.") {
        if pres.ends_with(suffix) && pres.len() > suffix.len() {
            let prefix = &pres[..pres.len() - suffix.len()];
            if prefix.ends_with('.') && !prefix[..prefix.len() - 1].contains('.') {
                return true;
            }
        }
    }
    false
}

/// MITM Domain Fronting Router managing redirection and repacking rules.
#[derive(Debug, Clone)]
pub struct MitmFrontingRouter {
    pub h11_port: u16,
    pub h211_port: u16,
    blocked_categories: HashSet<String>,
    direct_domains: HashSet<String>,
    profiles: Vec<FrontingTargetProfile>,
}

impl Default for MitmFrontingRouter {
    fn default() -> Self {
        Self::new(11666, 11777)
    }
}

impl MitmFrontingRouter {
    pub fn new(h11_port: u16, h211_port: u16) -> Self {
        let mut blocked = HashSet::new();
        blocked.insert("geosite:category-ads-all".to_string());

        let mut direct = HashSet::new();
        direct.insert("domain:ir".to_string());
        direct.insert("geosite:private".to_string());
        direct.insert("geosite:category-ir".to_string());

        Self {
            h11_port,
            h211_port,
            blocked_categories: blocked,
            direct_domains: direct,
            profiles: vec![
                FrontingTargetProfile::google_video(),
                FrontingTargetProfile::google_default(),
                FrontingTargetProfile::fastly_default(),
                FrontingTargetProfile::meta_default(),
            ],
        }
    }

    /// Evaluates initial ingress routing for client connections.
    pub fn route_client_ingress(&self, domain: &str, is_streaming_video: bool) -> FrontingAction {
        let d = domain.to_ascii_lowercase();

        // 1. Direct bypass rules
        for direct in &self.direct_domains {
            if direct.starts_with("domain:") && d.ends_with(&direct[7..]) {
                return FrontingAction::Direct;
            }
        }

        // 2. Video streaming domains use H1.1 decryption inbound
        if is_streaming_video || d.contains("googlevideo.com") {
            return FrontingAction::RedirectToMitm { port: self.h11_port };
        }

        // 3. Supported frontable domains route to H2/H1.1 decryption inbound
        if self.is_frontable_domain(&d) {
            return FrontingAction::RedirectToMitm { port: self.h211_port };
        }

        // 4. Default to direct
        FrontingAction::Direct
    }

    /// Evaluates egress routing for streams arriving on decrypted MITM inbounds.
    pub fn route_decrypted_egress(&self, domain: &str, inbound_port: u16) -> FrontingAction {
        let d = domain.to_ascii_lowercase();

        // Check if stream is on H1.1 inbound
        if inbound_port == self.h11_port {
            if d.contains("googlevideo.com") {
                let prof = FrontingTargetProfile::google_video();
                return FrontingAction::RepackFronted {
                    fronted_sni: prof.fronted_sni,
                    allowed_sans: prof.allowed_sans,
                    redirect_endpoint: prof.redirect_endpoint,
                    alpn: prof.alpn,
                };
            }
            // Strict block on non-video traffic hitting H1.1 inbound
            return FrontingAction::Block;
        }

        // Stream is on H2/H1.1 inbound
        if inbound_port == self.h211_port {
            if d.contains("google") || d.contains("youtube") {
                let prof = FrontingTargetProfile::google_default();
                return FrontingAction::RepackFronted {
                    fronted_sni: prof.fronted_sni,
                    allowed_sans: prof.allowed_sans,
                    redirect_endpoint: prof.redirect_endpoint,
                    alpn: prof.alpn,
                };
            }

            if d.contains("fastly") || d.contains("reddit") || d.contains("github") || d.contains("pypi") {
                let prof = FrontingTargetProfile::fastly_default();
                return FrontingAction::RepackFronted {
                    fronted_sni: prof.fronted_sni,
                    allowed_sans: prof.allowed_sans,
                    redirect_endpoint: prof.redirect_endpoint,
                    alpn: prof.alpn,
                };
            }

            if d.contains("meta") || d.contains("facebook") || d.contains("instagram") || d.contains("whatsapp") {
                let prof = FrontingTargetProfile::meta_default();
                return FrontingAction::RepackFronted {
                    fronted_sni: prof.fronted_sni,
                    allowed_sans: prof.allowed_sans,
                    redirect_endpoint: prof.redirect_endpoint,
                    alpn: prof.alpn,
                };
            }

            // Unmatched domain on decrypted port is blocked to prevent open proxy relaying
            return FrontingAction::Block;
        }

        FrontingAction::Direct
    }

    fn is_frontable_domain(&self, domain: &str) -> bool {
        for prof in &self.profiles {
            for allowed in &prof.allowed_sans {
                if match_san_pattern(domain, allowed) {
                    return true;
                }
            }
        }
        false
    }
}
