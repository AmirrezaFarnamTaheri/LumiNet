//! Multi-Hop Proxy Chain Router & Loop Prevention Engine.
//!
//! Manages 3-slot chained upstream proxies (Before / Pre-Hop Bridge, Base Proxy, After / Post-Hop Egress)
//! ensuring valid hop sequencing, automatic fallback selection, and loop/cycle prevention.

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum ProxyChainError {
    #[error("Loop detected in proxy chain: slot {0} specifies duplicate profile {1}")]
    LoopDetected(String, String),
    #[error("Automatic hop selection failed: no distinct candidates available for slot {0}")]
    NoCandidatesAvailable(String),
    #[error("Fixed profile reference not found in available catalog: {0}")]
    ProfileNotFound(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProxyChainSlot {
    Before,
    Base,
    After,
}

impl ProxyChainSlot {
    pub fn wire_name(&self) -> &'static str {
        match self {
            Self::Before => "before",
            Self::Base => "base",
            Self::After => "after",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ProxyProfileRef {
    pub subscription_id: String,
    pub fingerprint: String,
    pub name: String,
}

impl ProxyProfileRef {
    pub fn new(sub: impl Into<String>, fp: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            subscription_id: sub.into(),
            fingerprint: fp.into(),
            name: name.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProxyChainHopMode {
    Off,
    Automatic,
    Fixed(ProxyProfileRef),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProxyChainHop {
    pub slot: ProxyChainSlot,
    pub mode: ProxyChainHopMode,
}

impl ProxyChainHop {
    pub fn off(slot: ProxyChainSlot) -> Self {
        Self {
            slot,
            mode: ProxyChainHopMode::Off,
        }
    }

    pub fn automatic(slot: ProxyChainSlot) -> Self {
        Self {
            slot,
            mode: ProxyChainHopMode::Automatic,
        }
    }

    pub fn fixed(slot: ProxyChainSlot, profile: ProxyProfileRef) -> Self {
        Self {
            slot,
            mode: ProxyChainHopMode::Fixed(profile),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProxyChainSettings {
    pub enabled: bool,
    pub before: ProxyChainHop,
    pub after: ProxyChainHop,
}

impl Default for ProxyChainSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            before: ProxyChainHop::off(ProxyChainSlot::Before),
            after: ProxyChainHop::off(ProxyChainSlot::After),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProxyChainResolvedRoute {
    pub hops: Vec<ProxyProfileRef>,
    pub is_chained: bool,
}

pub struct ProxyChainRouter;

impl ProxyChainRouter {
    /// Resolves an ordered sequence of proxy hops from `base` and active `settings`,
    /// guaranteeing no duplicate fingerprints appear across the sequence.
    pub fn resolve_chain(
        base: &ProxyProfileRef,
        settings: &ProxyChainSettings,
        available: &[ProxyProfileRef],
    ) -> Result<ProxyChainResolvedRoute, ProxyChainError> {
        if !settings.enabled {
            return Ok(ProxyChainResolvedRoute {
                hops: vec![base.clone()],
                is_chained: false,
            });
        }

        let mut hops = Vec::new();

        // 1. Resolve Before Hop
        let before_resolved = match &settings.before.mode {
            ProxyChainHopMode::Off => None,
            ProxyChainHopMode::Fixed(fixed_ref) => {
                if fixed_ref.fingerprint == base.fingerprint {
                    return Err(ProxyChainError::LoopDetected(
                        "before".to_string(),
                        fixed_ref.fingerprint.clone(),
                    ));
                }
                Some(fixed_ref.clone())
            }
            ProxyChainHopMode::Automatic => {
                let candidate = available
                    .iter()
                    .find(|p| p.fingerprint != base.fingerprint)
                    .ok_or_else(|| ProxyChainError::NoCandidatesAvailable("before".to_string()))?;
                Some(candidate.clone())
            }
        };

        if let Some(ref b) = before_resolved {
            hops.push(b.clone());
        }

        // 2. Add Base Hop
        hops.push(base.clone());

        // 3. Resolve After Hop
        let after_resolved = match &settings.after.mode {
            ProxyChainHopMode::Off => None,
            ProxyChainHopMode::Fixed(fixed_ref) => {
                if fixed_ref.fingerprint == base.fingerprint {
                    return Err(ProxyChainError::LoopDetected(
                        "after".to_string(),
                        fixed_ref.fingerprint.clone(),
                    ));
                }
                if let Some(ref b) = before_resolved {
                    if fixed_ref.fingerprint == b.fingerprint {
                        return Err(ProxyChainError::LoopDetected(
                            "after".to_string(),
                            fixed_ref.fingerprint.clone(),
                        ));
                    }
                }
                Some(fixed_ref.clone())
            }
            ProxyChainHopMode::Automatic => {
                let candidate = available
                    .iter()
                    .find(|p| {
                        p.fingerprint != base.fingerprint
                            && before_resolved
                                .as_ref()
                                .map(|b| b.fingerprint != p.fingerprint)
                                .unwrap_or(true)
                    })
                    .ok_or_else(|| ProxyChainError::NoCandidatesAvailable("after".to_string()))?;
                Some(candidate.clone())
            }
        };

        if let Some(ref a) = after_resolved {
            hops.push(a.clone());
        }

        let is_chained = hops.len() > 1;
        Ok(ProxyChainResolvedRoute { hops, is_chained })
    }
}
