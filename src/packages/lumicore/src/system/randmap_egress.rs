// SPDX-License-Identifier: MIT
//
// Randmap egress settings (R2 roadmap wiring).
//
// A serde-friendly, user-configurable facade over the two randmap
// engines (IPv4 `RandmapTransform` and IPv6 `Ipv6Transform`) so the
// tunnel/transport layer can expose source-address randomisation as a
// first-class egress option driven by JSON config:
//
// {
//   "ipv4": { "mode": "subnet_preserving", "randomise_port": true,
//             "port_min": 32768, "port_max": 60999 },
//   "ipv6": { "mangle_source": true, "mangle_destination": false,
//             "prefix_net": "2001:db8::", "prefix_mask": "ffff:ffff:ffff::",
//             "port_min": 1024, "port_max": 65535 }
// }
//
// Omitted sections disable that family; the resulting engines are
// stateless and safe to clone per egress worker.

use serde::{Deserialize, Serialize};

use super::netfilter_randmap::{RandmapConfig, RandmapMode, RandmapTransform};
use super::netfilter_randmap_v6::{mangle, Ipv6Config, Ipv6Range, Ipv6Transform};

fn default_port_min() -> u16 {
    32768
}
fn default_port_max() -> u16 {
    60999
}

/// Serde mirror of [`RandmapMode`] (keeps the engine type JSON-clean).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum RandmapV4Mode {
    #[default]
    #[serde(rename = "subnet_preserving")]
    SubnetPreserving,
    #[serde(rename = "global")]
    Global,
    #[serde(rename = "port_only")]
    PortOnly,
}

impl From<RandmapV4Mode> for RandmapMode {
    fn from(m: RandmapV4Mode) -> Self {
        match m {
            RandmapV4Mode::SubnetPreserving => RandmapMode::SubnetPreserving,
            RandmapV4Mode::Global => RandmapMode::Global,
            RandmapV4Mode::PortOnly => RandmapMode::PortOnly,
        }
    }
}

/// IPv4 egress randomisation settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RandmapV4Settings {
    #[serde(default)]
    pub mode: RandmapV4Mode,
    #[serde(default)]
    pub randomise_port: bool,
    #[serde(default = "default_port_min")]
    pub port_min: u16,
    #[serde(default = "default_port_max")]
    pub port_max: u16,
}

/// IPv6 egress randomisation settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RandmapV6Settings {
    #[serde(default)]
    pub mangle_source: bool,
    #[serde(default)]
    pub mangle_destination: bool,
    /// Prefix network component, e.g. "2001:db8::".
    #[serde(default)]
    pub prefix_net: Option<String>,
    /// Prefix mask component, e.g. "ffff:ffff:ffff::".
    #[serde(default)]
    pub prefix_mask: Option<String>,
    #[serde(default = "default_port_min")]
    pub port_min: u16,
    #[serde(default = "default_port_max")]
    pub port_max: u16,
}

/// Top-level egress option; either family may be omitted (disabled).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RandmapEgressSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv4: Option<RandmapV4Settings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<RandmapV6Settings>,
}

/// A pair of engines built from [`RandmapEgressSettings`]. `None` means
/// the family is disabled. Not `Clone`/`Debug`: the engines own a
/// non-cloneable RNG stream; build one instance per egress worker.
pub struct RandmapEgress {
    pub v4: Option<RandmapTransform>,
    pub v6: Option<Ipv6Transform>,
}

/// Errors surfaced while converting user settings into engines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RandmapEgressError {
    /// IPv6 settings requested but a prefix address failed to parse.
    BadPrefix(String),
    /// Port range is inverted (min > max).
    BadPortRange,
}

impl std::fmt::Display for RandmapEgressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RandmapEgressError::BadPrefix(s) => write!(f, "bad IPv6 prefix: {s}"),
            RandmapEgressError::BadPortRange => write!(f, "port_min must be <= port_max"),
        }
    }
}
impl std::error::Error for RandmapEgressError {}

impl RandmapEgressSettings {
    /// Parse from JSON config text (as delivered by the daemon config
    /// pipeline). Rejects unknown keys so typos fail loudly.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Build the engines. Port ranges are validated across both families.
    pub fn build(&self) -> Result<RandmapEgress, RandmapEgressError> {
        let v4 = self
            .ipv4
            .as_ref()
            .map(|s| {
                if s.port_min > s.port_max {
                    return Err(RandmapEgressError::BadPortRange);
                }
                Ok(RandmapTransform::new(RandmapConfig {
                    mode: s.mode.into(),
                    randomise_port: s.randomise_port,
                    port_min: s.port_min,
                    port_max: s.port_max,
                }))
            })
            .transpose()?;

        let v6 = match self.ipv6.as_ref() {
            None => None,
            Some(s) => {
                if s.port_min > s.port_max {
                    return Err(RandmapEgressError::BadPortRange);
                }
                let parse = |v: &Option<String>, what: &str| -> Result<
                    std::net::Ipv6Addr,
                    RandmapEgressError,
                > {
                    v.as_deref()
                        .map(|text| {
                            text.parse()
                                .map_err(|_| RandmapEgressError::BadPrefix(format!("{what}: {text}")))
                        })
                        .unwrap_or(Ok(std::net::Ipv6Addr::UNSPECIFIED))
                };
                let net = parse(&s.prefix_net, "prefix_net")?;
                let mask = parse(&s.prefix_mask, "prefix_mask")?;
                let range = Ipv6Range {
                    flags: mangle::IP | mangle::PROTO,
                    net,
                    mask,
                    min_proto: s.port_min,
                    max_proto: s.port_max,
                };
                let cfg = Ipv6Config {
                    src: if s.mangle_source {
                        range
                    } else {
                        Ipv6Range::default()
                    },
                    dst: if s.mangle_destination {
                        range
                    } else {
                        Ipv6Range::default()
                    },
                };
                Some(Ipv6Transform::new(cfg))
            }
        };

        Ok(RandmapEgress { v4, v6 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_settings_disable_both_families() {
        let e = RandmapEgressSettings::default().build().unwrap();
        assert!(e.v4.is_none() && e.v6.is_none());
    }

    #[test]
    fn json_config_builds_both_engines() {
        let s = RandmapEgressSettings::from_json(
            r#"{
                "ipv4": {"mode": "global", "randomise_port": true},
                "ipv6": {"mangle_source": true,
                         "prefix_net": "2001:db8::",
                         "prefix_mask": "ffff:ffff:ffff::",
                         "port_min": 1024, "port_max": 65535}
            }"#,
        )
        .unwrap();
        let e = s.build().unwrap();
        assert!(e.v4.is_some() && e.v6.is_some());
    }

    #[test]
    fn inverted_port_range_is_rejected() {
        let s = RandmapEgressSettings {
            ipv4: Some(RandmapV4Settings {
                port_min: 60000,
                port_max: 40000,
                ..Default::default()
            }),
            ipv6: None,
        };
        let err = s.build().err().unwrap();
        assert_eq!(err, RandmapEgressError::BadPortRange);
    }

    #[test]
    fn bad_prefix_is_rejected() {
        let s = RandmapEgressSettings {
            ipv4: None,
            ipv6: Some(RandmapV6Settings {
                mangle_source: true,
                prefix_net: Some("not-an-addr".into()),
                ..Default::default()
            }),
        };
        let err = s.build().err().unwrap();
        assert!(matches!(err, RandmapEgressError::BadPrefix(_)));
    }

    #[test]
    fn unknown_json_keys_are_rejected() {
        assert!(RandmapEgressSettings::from_json(r#"{"ipv5": {}}"#).is_err());
    }
}
