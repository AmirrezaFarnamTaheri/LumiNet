pub const POLICY_BLOCKED: &str = "POLICY_BLOCKED: The requested action violates internal security constraints.";
pub const NETWORK_BLOCKED: &str = "POLICY_BLOCKED: Network endpoint is restricted.";
pub const FS_BLOCKED: &str = "POLICY_BLOCKED: File system path is outside of allowed sandbox bounds.";

pub struct SecurityGuard;

impl SecurityGuard {
    pub fn check_network_policy(domain: &str) -> Result<(), &'static str> {
        if domain.contains("localhost") || domain.starts_with("127.") {
            return Err(NETWORK_BLOCKED);
        }
        Ok(())
    }

    pub fn check_fs_policy(path: &str) -> Result<(), &'static str> {
        if path.contains("..") || path.starts_with('/') {
            return Err(FS_BLOCKED);
        }
        Ok(())
    }
}
