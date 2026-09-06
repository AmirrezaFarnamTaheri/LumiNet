//! Toolchain Proxy Environment Wrapper
//!
//! Generates and configures proxy routing profiles for development toolchains
//! (Git, Pip, Npm, Gradle, Curl, Docker, and shell environment variables).

use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolchainType {
    Git,
    Pip,
    Npm,
    Gradle,
    Curl,
    Docker,
    EnvVars,
}

pub struct ToolchainProxyWrapper {
    pub http_proxy: String,
    pub socks5_proxy: String,
}

impl ToolchainProxyWrapper {
    pub fn new(http_proxy: impl Into<String>, socks5_proxy: impl Into<String>) -> Self {
        Self {
            http_proxy: http_proxy.into(),
            socks5_proxy: socks5_proxy.into(),
        }
    }

    pub fn generate_env_vars(&self) -> HashMap<String, String> {
        let mut envs = HashMap::new();
        envs.insert("http_proxy".to_string(), self.http_proxy.clone());
        envs.insert("https_proxy".to_string(), self.http_proxy.clone());
        envs.insert("HTTP_PROXY".to_string(), self.http_proxy.clone());
        envs.insert("HTTPS_PROXY".to_string(), self.http_proxy.clone());
        envs.insert("ALL_PROXY".to_string(), self.socks5_proxy.clone());
        envs.insert("all_proxy".to_string(), self.socks5_proxy.clone());
        envs.insert("NO_PROXY".to_string(), "localhost,127.0.0.1,::1".to_string());
        envs
    }

    pub fn generate_config_snippet(&self, toolchain: ToolchainType) -> String {
        match toolchain {
            ToolchainType::Git => {
                format!(
                    "# Git proxy configuration\n[http]\n\tproxy = {}\n[https]\n\tproxy = {}\n",
                    self.http_proxy, self.http_proxy
                )
            }
            ToolchainType::Pip => {
                format!(
                    "# pip.conf\n[global]\nproxy = {}\n",
                    self.http_proxy
                )
            }
            ToolchainType::Npm => {
                format!(
                    "# .npmrc\nproxy={}\nhttps-proxy={}\n",
                    self.http_proxy, self.http_proxy
                )
            }
            ToolchainType::Gradle => {
                let parts: Vec<&str> = self.http_proxy.trim_start_matches("http://").split(':').collect();
                let host = parts.get(0).unwrap_or(&"127.0.0.1");
                let port = parts.get(1).unwrap_or(&"8080");
                format!(
                    "# gradle.properties\nsystemProp.http.proxyHost={}\nsystemProp.http.proxyPort={}\nsystemProp.https.proxyHost={}\nsystemProp.https.proxyPort={}\n",
                    host, port, host, port
                )
            }
            ToolchainType::Curl => {
                format!(
                    "# .curlrc\nproxy = \"{}\"\n",
                    self.socks5_proxy
                )
            }
            ToolchainType::Docker => {
                format!(
                    "{{\n  \"proxies\": {{\n    \"default\": {{\n      \"httpProxy\": \"{}\",\n      \"httpsProxy\": \"{}\",\n      \"noProxy\": \"localhost,127.0.0.1\"\n    }}\n  }}\n}}\n",
                    self.http_proxy, self.http_proxy
                )
            }
            ToolchainType::EnvVars => {
                format!(
                    "export HTTP_PROXY=\"{}\"\nexport HTTPS_PROXY=\"{}\"\nexport ALL_PROXY=\"{}\"\n",
                    self.http_proxy, self.http_proxy, self.socks5_proxy
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_toolchain_proxy_snippets() {
        let wrapper = ToolchainProxyWrapper::new("http://127.0.0.1:8080", "socks5://127.0.0.1:1080");

        let git_cfg = wrapper.generate_config_snippet(ToolchainType::Git);
        assert!(git_cfg.contains("proxy = http://127.0.0.1:8080"));

        let gradle_cfg = wrapper.generate_config_snippet(ToolchainType::Gradle);
        assert!(gradle_cfg.contains("systemProp.http.proxyHost=127.0.0.1"));
        assert!(gradle_cfg.contains("systemProp.http.proxyPort=8080"));

        let envs = wrapper.generate_env_vars();
        assert_eq!(envs.get("ALL_PROXY").unwrap(), "socks5://127.0.0.1:1080");
    }
}
