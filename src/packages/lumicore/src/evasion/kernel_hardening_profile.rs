//! # Hardened Kernel Sysctl & Network Parameters Profile
//!
//! Validates network stack hardening parameters against spoofing, SYN floods,
//! and routing loops, returning compliance scores and remediation configs.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelHardeningParameter {
    pub key: &'static str,
    pub recommended_value: &'static str,
    pub current_value: Option<String>,
    pub required: bool,
}

pub struct KernelHardeningProfile;

impl KernelHardeningProfile {
    pub fn get_recommended_rules() -> Vec<KernelHardeningParameter> {
        vec![
            KernelHardeningParameter {
                key: "net.ipv4.tcp_syncookies",
                recommended_value: "1",
                current_value: None,
                required: true,
            },
            KernelHardeningParameter {
                key: "net.ipv4.tcp_rfc1337",
                recommended_value: "1",
                current_value: None,
                required: true,
            },
            KernelHardeningParameter {
                key: "net.ipv4.conf.all.rp_filter",
                recommended_value: "1",
                current_value: None,
                required: true,
            },
            KernelHardeningParameter {
                key: "net.ipv4.conf.all.accept_redirects",
                recommended_value: "0",
                current_value: None,
                required: false,
            },
            KernelHardeningParameter {
                key: "net.ipv4.conf.all.log_martians",
                recommended_value: "1",
                current_value: None,
                required: false,
            },
            KernelHardeningParameter {
                key: "net.ipv6.conf.all.accept_redirects",
                recommended_value: "0",
                current_value: None,
                required: false,
            },
        ]
    }

    pub fn calculate_compliance_score(parameters: &[KernelHardeningParameter]) -> u32 {
        if parameters.is_empty() {
            return 100;
        }
        let total = parameters.len();
        let matched = parameters
            .iter()
            .filter(|p| {
                if let Some(curr) = &p.current_value {
                    curr.trim() == p.recommended_value
                } else {
                    false
                }
            })
            .count();

        ((matched as f32 / total as f32) * 100.0) as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kernel_hardening_score() {
        let mut rules = KernelHardeningProfile::get_recommended_rules();
        assert_eq!(rules.len(), 6);
        assert_eq!(KernelHardeningProfile::calculate_compliance_score(&rules), 0);

        rules[0].current_value = Some("1".to_string());
        rules[1].current_value = Some("1".to_string());
        rules[2].current_value = Some("1".to_string());
        let score = KernelHardeningProfile::calculate_compliance_score(&rules);
        assert_eq!(score, 50);
    }
}
