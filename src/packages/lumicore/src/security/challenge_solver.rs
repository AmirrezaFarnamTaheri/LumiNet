//! # CDN Challenge Solver
//!
//! Unified CDN challenge detection and bypass for various CDNs (e.g. Cloudflare + ArvanCloud).
//! Merges: cdn_bypass.rs (ArvanCloud) + cf_solver.rs (Cloudflare).
//!

use std::collections::HashMap;

// ─── Unified CDN Challenge Types ─────────────────────────────────────────────

/// Unified CDN challenge type covering all supported CDNs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CdnChallengeType {
    ArvanCloud,
    Cloudflare,
    CloudflareManaged,
    CloudflareTurnstile,
    CloudflareJavaScript,
    Blocked,
    Unknown(String),
}

// ─── ArvanCloud Detection ───────────────────────────────────────────────────

/// ArvanCloud challenge detection markers.
const ARVAN_MARKERS: &[&str] = &["__arcsjs", "__arcsjsc", "Transferring to the website"];

/// ArvanCloud cookie names.
const ARVAN_COOKIE_ARCSJS: &str = "__arcsjs";
const ARVAN_COOKIE_ARCSJSC: &str = "__arcsjsc";

/// Detects ArvanCloud challenge page.
pub fn detect_arvan_challenge(body: &str) -> bool {
    ARVAN_MARKERS.iter().all(|m| body.contains(m))
}

/// Extracts embedded JavaScript from ArvanCloud challenge page.
pub fn extract_arvan_challenge_script(body: &str) -> Option<String> {
    if let Some(start) = body.find("<script") {
        if let Some(script_start) = body[start..].find('>') {
            let script_content = &body[start + script_start + 1..];
            if let Some(end) = script_content.find("</script>") {
                return Some(script_content[..end].to_string());
            }
        }
    }
    None
}

/// Patches ArvanCloud challenge script for synchronous execution.
pub fn patch_challenge_script(script: &str) -> String {
    let mut patched = script.to_string();
    patched = patched.replace(
        "document.addEventListener('DOMContentLoaded', function() {",
        "(function() {",
    );
    patched = patched.replace("setTimeout(function() {", "(function() {");
    if let Some(pos) = patched.rfind("}, getRandomInt(") {
        if let Some(end) = patched[pos..].find("))") {
            patched.replace_range(pos..pos + end + 2, "})()");
        }
    }
    if patched.ends_with("});") {
        patched.truncate(patched.len() - 3);
        patched.push_str("})();");
    }
    patched
}

/// Verifies ArvanCloud challenge cookies were captured.
pub fn verify_arvan_cookies(cookies: &HashMap<String, String>) -> Result<(), String> {
    if !cookies.contains_key(ARVAN_COOKIE_ARCSJS) {
        return Err(format!("Missing {} cookie", ARVAN_COOKIE_ARCSJS));
    }
    if !cookies.contains_key(ARVAN_COOKIE_ARCSJSC) {
        return Err(format!("Missing {} cookie", ARVAN_COOKIE_ARCSJSC));
    }
    Ok(())
}

// ─── Cloudflare Detection ────────────────────────────────────────────────────

/// CSS selectors for Cloudflare challenge elements.
pub const CF_CHALLENGE_SELECTORS: &[&str] = &[
    "div.cf-browser-verification",
    "iframe[src*='challenges.cloudflare.com']",
    "div.cf-turnstile",
    "div#challenge-running",
    "div#challenge-stage",
    "div.cf-please-wait",
    "div#cf-spinner-please-wait",
    "div.cf-spinner",
];

const CHALLENGE_TEXT_PATTERNS: &[&str] = &[
    "Checking if the site connection is secure",
    "Enable JavaScript and cookies to continue",
    "Please wait while we verify your browser",
    "Verifying you are human",
    "Just a moment",
    "Please turn JavaScript on and reload the page",
    "Attention Required!",
    "Access denied",
    "You have been blocked",
];

const BLOCKED_TEXT_PATTERNS: &[&str] = &[
    "Access denied",
    "You have been blocked",
    "Error 1020",
    "Error 1009",
    "Your IP address has been blocked",
];

const CLOUDFLARE_MARKERS: &[&str] = &[
    "cf-browser-verification",
    "challenge-platform",
    "cf_chl_opt",
    "cf-chl-widget-manage",
];

// ─── Unified Detection ───────────────────────────────────────────────────────

/// Challenge detection result.
#[derive(Debug, Clone)]
pub struct ChallengeDetection {
    pub challenge_type: CdnChallengeType,
    pub confidence: f32,
    pub evidence: Vec<String>,
}

/// Detects ALL CDN challenges (ArvanCloud + Cloudflare) from HTML content.
pub fn detect_cdn_challenge(body: &str) -> ChallengeDetection {
    let mut evidence = Vec::new();

    // Check ArvanCloud first
    if detect_arvan_challenge(body) {
        evidence.push("ArvanCloud challenge markers found".to_string());
        return ChallengeDetection {
            challenge_type: CdnChallengeType::ArvanCloud,
            confidence: 1.0,
            evidence,
        };
    }

    // Check blocked state
    let mut blocked_score = 0.0f32;
    for pattern in BLOCKED_TEXT_PATTERNS {
        if body.contains(pattern) {
            blocked_score += 1.0;
            evidence.push(format!("blocked: {}", pattern));
        }
    }
    if blocked_score > 0.5 {
        return ChallengeDetection {
            challenge_type: CdnChallengeType::Blocked,
            confidence: blocked_score.min(1.0),
            evidence,
        };
    }

    // Check Turnstile
    if body.contains("cf-turnstile") || body.contains("challenges.cloudflare.com") {
        evidence.push("Turnstile iframe detected".to_string());
        return ChallengeDetection {
            challenge_type: CdnChallengeType::CloudflareTurnstile,
            confidence: 0.9,
            evidence,
        };
    }

    // Check managed challenge
    if body.contains("challenge-running") || body.contains("challenge-stage") {
        evidence.push("Managed challenge detected".to_string());
        return ChallengeDetection {
            challenge_type: CdnChallengeType::CloudflareManaged,
            confidence: 0.8,
            evidence,
        };
    }

    // Check general Cloudflare markers
    let mut cf_score = 0.0f32;
    for marker in CLOUDFLARE_MARKERS {
        if body.contains(marker) {
            cf_score += 0.3;
            evidence.push(format!("CF marker: {}", marker));
        }
    }
    for pattern in CHALLENGE_TEXT_PATTERNS {
        if body.contains(pattern) {
            cf_score += 0.2;
            evidence.push(format!("challenge text: {}", pattern));
        }
    }

    if cf_score > 0.3 {
        return ChallengeDetection {
            challenge_type: CdnChallengeType::CloudflareJavaScript,
            confidence: cf_score.min(1.0),
            evidence,
        };
    }

    ChallengeDetection {
        challenge_type: CdnChallengeType::Cloudflare,
        confidence: 0.0,
        evidence,
    }
}

/// Detects Cloudflare challenge from HTTP headers.
pub fn detect_cdn_challenge_from_headers(headers: &HashMap<String, String>) -> bool {
    if let Some(cf_mitigated) = headers.get("cf-mitigated") {
        if cf_mitigated == "challenge" {
            return true;
        }
    }
    if let Some(cookies) = headers.get("set-cookie") {
        if cookies.contains("cf_chl") || cookies.contains("__cf_bm") {
            return true;
        }
    }
    if let Some(server) = headers.get("server") {
        if server == "cloudflare" {
            if let Some(status) = headers.get("status") {
                if status == "403" || status == "503" {
                    return true;
                }
            }
        }
    }
    false
}

// ─── Session Management ──────────────────────────────────────────────────────

/// Cookie management.
pub fn parse_cookie_string(cookie_str: &str) -> HashMap<String, String> {
    let mut cookies = HashMap::new();
    for pair in cookie_str.split(';') {
        let pair = pair.trim();
        if let Some(eq_pos) = pair.find('=') {
            let name = pair[..eq_pos].trim().to_string();
            let value = pair[eq_pos + 1..].trim().to_string();
            if !name.is_empty() {
                cookies.insert(name, value);
            }
        }
    }
    cookies
}

pub fn build_cookie_header(cookies: &HashMap<String, String>) -> String {
    cookies
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Unified session state for CDN bypass.
#[derive(Debug, Clone, Default)]
pub struct CdnSessionState {
    pub cookies: HashMap<String, String>,
    pub attempts: u32,
    pub domain: String,
    pub success_count: u32,
    pub is_trusted: bool,
}

impl CdnSessionState {
    pub fn new(domain: &str) -> Self {
        Self {
            domain: domain.to_string(),
            ..Default::default()
        }
    }

    pub fn merge_cookies(&mut self, new_cookies: HashMap<String, String>) {
        self.cookies.extend(new_cookies);
    }

    pub fn cookie_header(&self) -> String {
        build_cookie_header(&self.cookies)
    }

    pub fn has_arvan_cookies(&self) -> bool {
        self.cookies.contains_key(ARVAN_COOKIE_ARCSJS)
            && self.cookies.contains_key(ARVAN_COOKIE_ARCSJSC)
    }

    pub fn mark_success(&mut self) {
        self.success_count += 1;
        if self.success_count >= 3 {
            self.is_trusted = true;
        }
    }

    pub fn mark_failure(&mut self) {
        self.is_trusted = false;
        self.success_count = 0;
    }

    pub fn reset(&mut self) {
        self.cookies.clear();
        self.attempts += 1;
    }
}

/// Session store for multiple domains.
pub struct SessionStore {
    states: HashMap<String, CdnSessionState>,
    max_age_secs: u64,
}

impl SessionStore {
    pub fn new(max_age_secs: u64) -> Self {
        Self {
            states: HashMap::new(),
            max_age_secs,
        }
    }

    pub fn get_or_create(&mut self, domain: &str) -> &mut CdnSessionState {
        self.states
            .entry(domain.to_string())
            .or_insert_with(|| CdnSessionState::new(domain))
    }

    pub fn is_trusted(&self, domain: &str) -> bool {
        self.states
            .get(domain)
            .map(|s| s.is_trusted)
            .unwrap_or(false)
    }

    /// Maximum configured session age in seconds.
    pub fn max_age_secs(&self) -> u64 {
        self.max_age_secs
    }
}

// ─── Curl Parser ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct CurlRequest {
    pub url: String,
    pub method: String,
    pub headers: HashMap<String, String>,
    pub data: Option<String>,
    pub cookies: Option<String>,
    pub auth: Option<String>,
    pub proxy: Option<String>,
    pub follow_redirects: bool,
    pub insecure: bool,
    pub timeout: Option<std::time::Duration>,
}

pub fn parse_curl_command(cmd: &str) -> Result<CurlRequest, String> {
    let parts = shell_split(cmd)?;
    let mut request = CurlRequest::default();
    let mut i = 0;
    while i < parts.len() {
        match parts[i].as_str() {
            "-X" => {
                i += 1;
                if i < parts.len() {
                    request.method = parts[i].clone();
                }
            }
            "-H" => {
                i += 1;
                if i < parts.len() {
                    if let Some((k, v)) = parts[i].split_once(':') {
                        request
                            .headers
                            .insert(k.trim().to_string(), v.trim().to_string());
                    }
                }
            }
            "-d" | "--data" | "--data-raw" => {
                i += 1;
                if i < parts.len() {
                    request.data = Some(parts[i].clone());
                    if request.method == "GET" {
                        request.method = "POST".to_string();
                    }
                }
            }
            "-b" => {
                i += 1;
                if i < parts.len() {
                    request.cookies = Some(parts[i].clone());
                }
            }
            "-u" => {
                i += 1;
                if i < parts.len() {
                    request.auth = Some(parts[i].clone());
                }
            }
            "-x" => {
                i += 1;
                if i < parts.len() {
                    request.proxy = Some(parts[i].clone());
                }
            }
            "-L" => {
                request.follow_redirects = true;
            }
            "-k" => {
                request.insecure = true;
            }
            "--max-time" => {
                i += 1;
                if i < parts.len() {
                    if let Ok(secs) = parts[i].parse::<f64>() {
                        request.timeout = Some(std::time::Duration::from_secs_f64(secs));
                    }
                }
            }
            "-I" => {
                request.method = "HEAD".to_string();
            }
            arg if !arg.starts_with('-') && request.url.is_empty() => {
                request.url = arg.to_string();
            }
            _ => {}
        }
        i += 1;
    }
    if request.url.is_empty() {
        return Err("No URL specified".to_string());
    }
    Ok(request)
}

fn shell_split(s: &str) -> Result<Vec<String>, String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut escape = false;
    for ch in s.chars() {
        if escape {
            current.push(ch);
            escape = false;
            continue;
        }
        match ch {
            '\\' => escape = true,
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            ' ' | '\t' if !in_single && !in_double => {
                if !current.is_empty() {
                    parts.push(current.clone());
                    current.clear();
                }
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() {
        parts.push(current);
    }
    Ok(parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_arvan() {
        let body = "<html>__arcsjs __arcsjsc Transferring to the website</html>";
        assert!(detect_arvan_challenge(body));
    }

    #[test]
    fn test_detect_cloudflare_turnstile() {
        let body = "<html><div class='cf-turnstile'></div></html>";
        let result = detect_cdn_challenge(body);
        assert_eq!(result.challenge_type, CdnChallengeType::CloudflareTurnstile);
    }

    #[test]
    fn test_detect_blocked() {
        let body = "<html>Access denied Error 1020</html>";
        let result = detect_cdn_challenge(body);
        assert_eq!(result.challenge_type, CdnChallengeType::Blocked);
    }

    #[test]
    fn test_no_challenge() {
        let body = "<html><h1>Welcome</h1></html>";
        let result = detect_cdn_challenge(body);
        assert_eq!(result.challenge_type, CdnChallengeType::Cloudflare);
    }

    #[test]
    fn test_parse_cookies() {
        let cookies = parse_cookie_string("__arcsjs=abc123; __arcsjsc=arcookie-123-def");
        assert_eq!(cookies.get("__arcsjs").unwrap(), "abc123");
    }

    #[test]
    fn test_session_state() {
        let mut state = CdnSessionState::new("example.com");
        state.mark_success();
        state.mark_success();
        state.mark_success();
        assert!(state.is_trusted);
    }

    #[test]
    fn test_parse_curl() {
        let cmd = r#"curl -X POST -H "Content-Type: application/json" https://example.com"#;
        let req = parse_curl_command(cmd).unwrap();
        assert_eq!(req.method, "POST");
    }
}
