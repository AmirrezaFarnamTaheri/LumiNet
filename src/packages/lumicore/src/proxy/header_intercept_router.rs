use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub enum InterceptAction {
    ForwardStandard,
    DivertToLocal(String), // target local address, e.g. "127.0.0.1:8080"
}

#[derive(Debug, Clone)]
pub struct InterceptRule {
    pub header_name: String,
    pub header_value_exact: String,
    pub target_local_address: String,
}

#[derive(Debug, Default)]
pub struct HeaderInterceptRouter {
    rules: Vec<InterceptRule>,
}

impl HeaderInterceptRouter {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn add_rule(&mut self, header_name: &str, header_value: &str, local_addr: &str) {
        self.rules.push(InterceptRule {
            header_name: header_name.to_ascii_lowercase(),
            header_value_exact: header_value.to_string(),
            target_local_address: local_addr.to_string(),
        });
    }

    pub fn evaluate_headers(&self, headers: &HashMap<String, String>) -> InterceptAction {
        for rule in &self.rules {
            for (k, v) in headers {
                if k.to_ascii_lowercase() == rule.header_name && v == &rule.header_value_exact {
                    return InterceptAction::DivertToLocal(rule.target_local_address.clone());
                }
            }
        }
        InterceptAction::ForwardStandard
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_intercept_routing() {
        let mut router = HeaderInterceptRouter::new();
        router.add_rule("x-telepresence-intercept-id", "dev-alice", "127.0.0.1:9090");

        let mut regular_headers = HashMap::new();
        regular_headers.insert("User-Agent".to_string(), "Mozilla/5.0".to_string());
        assert_eq!(router.evaluate_headers(&regular_headers), InterceptAction::ForwardStandard);

        let mut dev_headers = HashMap::new();
        dev_headers.insert("X-Telepresence-Intercept-Id".to_string(), "dev-alice".to_string());
        assert_eq!(
            router.evaluate_headers(&dev_headers),
            InterceptAction::DivertToLocal("127.0.0.1:9090".to_string())
        );
    }
}
