//! # Programmable Intercepting Proxy Pipeline
//!
//! Provides extensible request/response filtering pipeline with header inspection,
//! rewrite hooks, and selective proxy chaining.

pub enum PipelineVerdict {
    PassThrough,
    ShortCircuit { status_code: u16, body: Vec<u8> },
    ModifyHeaders(Vec<(String, String)>),
}

pub trait ProxyFilterHook: Send + Sync {
    fn on_request(&self, method: &str, path: &str, headers: &[(String, String)]) -> PipelineVerdict;
}

pub struct HeaderInjectorHook {
    header_name: String,
    header_value: String,
}

impl HeaderInjectorHook {
    pub fn new(name: &str, value: &str) -> Self {
        Self {
            header_name: name.to_string(),
            header_value: value.to_string(),
        }
    }
}

impl ProxyFilterHook for HeaderInjectorHook {
    fn on_request(&self, _method: &str, _path: &str, _headers: &[(String, String)]) -> PipelineVerdict {
        PipelineVerdict::ModifyHeaders(vec![(self.header_name.clone(), self.header_value.clone())])
    }
}

pub struct BlockPathHook {
    blocked_prefix: String,
}

impl BlockPathHook {
    pub fn new(prefix: &str) -> Self {
        Self {
            blocked_prefix: prefix.to_string(),
        }
    }
}

impl ProxyFilterHook for BlockPathHook {
    fn on_request(&self, _method: &str, path: &str, _headers: &[(String, String)]) -> PipelineVerdict {
        if path.starts_with(&self.blocked_prefix) {
            PipelineVerdict::ShortCircuit {
                status_code: 403,
                body: b"Forbidden by LumiProxy Pipeline".to_vec(),
            }
        } else {
            PipelineVerdict::PassThrough
        }
    }
}

pub struct ProgrammableProxyPipeline {
    hooks: Vec<Box<dyn ProxyFilterHook>>,
}

impl ProgrammableProxyPipeline {
    pub fn new() -> Self {
        Self { hooks: Vec::new() }
    }

    pub fn add_hook(&mut self, hook: Box<dyn ProxyFilterHook>) {
        self.hooks.push(hook);
    }

    pub fn process_request(
        &self,
        method: &str,
        path: &str,
        headers: &mut Vec<(String, String)>,
    ) -> Result<(), (u16, Vec<u8>)> {
        for hook in &self.hooks {
            match hook.on_request(method, path, headers) {
                PipelineVerdict::PassThrough => {}
                PipelineVerdict::ShortCircuit { status_code, body } => {
                    return Err((status_code, body));
                }
                PipelineVerdict::ModifyHeaders(new_headers) => {
                    for (k, v) in new_headers {
                        headers.push((k, v));
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_programmable_proxy_pipeline() {
        let mut pipeline = ProgrammableProxyPipeline::new();
        pipeline.add_hook(Box::new(HeaderInjectorHook::new("X-Proxy-By", "LumiNet")));
        pipeline.add_hook(Box::new(BlockPathHook::new("/admin/secret")));

        let mut headers = vec![("Host".to_string(), "api.com".to_string())];
        let ok_res = pipeline.process_request("GET", "/public/data", &mut headers);
        assert!(ok_res.is_ok());
        assert!(headers.iter().any(|(k, v)| k == "X-Proxy-By" && v == "LumiNet"));

        let mut bad_headers = vec![];
        let err_res = pipeline.process_request("GET", "/admin/secret/keys", &mut bad_headers);
        assert!(err_res.is_err());
        let (code, body) = err_res.unwrap_err();
        assert_eq!(code, 403);
        assert!(String::from_utf8_lossy(&body).contains("Forbidden"));
    }
}
