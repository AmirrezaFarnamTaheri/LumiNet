use serde::{Deserialize, Serialize};

/// Stability level of a DNS evasion auto-tune preset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AutoTunePresetStability {
    Stable,
    Aggressive,
}

/// Specialized parameter tuning for high-censorship DNS transport.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutoTunePreset {
    pub id: &'static str,
    pub label: &'static str,
    pub min_upload_mtu: u16,
    pub max_upload_mtu: u16,
    pub min_download_mtu: u16,
    pub max_download_mtu: u16,
    pub resolver_timeout_ms: u32,
    pub dns_frag_capacity: u32,
    pub upload_duplication: u8,
    pub download_duplication: u8,
    pub upload_compression: u8,
    pub download_compression: u8,
    pub stability: AutoTunePresetStability,
}

pub const AUTO_TUNE_PRESETS: &[AutoTunePreset] = &[
    AutoTunePreset {
        id: "iran-average",
        label: "Iran Default",
        min_upload_mtu: 40,
        max_upload_mtu: 140,
        min_download_mtu: 300,
        max_download_mtu: 3000,
        resolver_timeout_ms: 2500,
        dns_frag_capacity: 256,
        upload_duplication: 3,
        download_duplication: 7,
        upload_compression: 2,
        download_compression: 2,
        stability: AutoTunePresetStability::Stable,
    },
    AutoTunePreset {
        id: "iran-low-mtu-scan",
        label: "Iran Low MTU Scan",
        min_upload_mtu: 20,
        max_upload_mtu: 120,
        min_download_mtu: 160,
        max_download_mtu: 768,
        resolver_timeout_ms: 2500,
        dns_frag_capacity: 256,
        upload_duplication: 3,
        download_duplication: 7,
        upload_compression: 2,
        download_compression: 2,
        stability: AutoTunePresetStability::Stable,
    },
    AutoTunePreset {
        id: "iran-fast-low-mtu",
        label: "Iran Fast Low MTU",
        min_upload_mtu: 20,
        max_upload_mtu: 325,
        min_download_mtu: 100,
        max_download_mtu: 1270,
        resolver_timeout_ms: 2500,
        dns_frag_capacity: 100,
        upload_duplication: 5,
        download_duplication: 10,
        upload_compression: 2,
        download_compression: 2,
        stability: AutoTunePresetStability::Stable,
    },
    AutoTunePreset {
        id: "iran-compact-fixed",
        label: "Iran Compact Fixed",
        min_upload_mtu: 62,
        max_upload_mtu: 62,
        min_download_mtu: 414,
        max_download_mtu: 414,
        resolver_timeout_ms: 2500,
        dns_frag_capacity: 384,
        upload_duplication: 6,
        download_duplication: 8,
        upload_compression: 2,
        download_compression: 2,
        stability: AutoTunePresetStability::Stable,
    },
    AutoTunePreset {
        id: "iran-fixed-64-balanced",
        label: "Iran Fixed 64 Balanced",
        min_upload_mtu: 64,
        max_upload_mtu: 64,
        min_download_mtu: 756,
        max_download_mtu: 756,
        resolver_timeout_ms: 2500,
        dns_frag_capacity: 256,
        upload_duplication: 8,
        download_duplication: 8,
        upload_compression: 2,
        download_compression: 2,
        stability: AutoTunePresetStability::Stable,
    },
    AutoTunePreset {
        id: "iran-mid-reliable",
        label: "Iran Mid Reliable",
        min_upload_mtu: 120,
        max_upload_mtu: 160,
        min_download_mtu: 652,
        max_download_mtu: 1110,
        resolver_timeout_ms: 2500,
        dns_frag_capacity: 256,
        upload_duplication: 5,
        download_duplication: 11,
        upload_compression: 2,
        download_compression: 2,
        stability: AutoTunePresetStability::Stable,
    },
    AutoTunePreset {
        id: "iran-download-heavy",
        label: "Iran Download Heavy",
        min_upload_mtu: 104,
        max_upload_mtu: 139,
        min_download_mtu: 394,
        max_download_mtu: 1000,
        resolver_timeout_ms: 2500,
        dns_frag_capacity: 256,
        upload_duplication: 8,
        download_duplication: 30,
        upload_compression: 2,
        download_compression: 2,
        stability: AutoTunePresetStability::Stable,
    },
    AutoTunePreset {
        id: "iran-fixed-64-aggressive",
        label: "Iran Fixed 64 Wide",
        min_upload_mtu: 64,
        max_upload_mtu: 64,
        min_download_mtu: 756,
        max_download_mtu: 1317,
        resolver_timeout_ms: 2500,
        dns_frag_capacity: 230,
        upload_duplication: 14,
        download_duplication: 30,
        upload_compression: 2,
        download_compression: 2,
        stability: AutoTunePresetStability::Aggressive,
    },
    AutoTunePreset {
        id: "iran-large-download-aggressive",
        label: "Iran No Compression Max",
        min_upload_mtu: 100,
        max_upload_mtu: 600,
        min_download_mtu: 800,
        max_download_mtu: 6500,
        resolver_timeout_ms: 2500,
        dns_frag_capacity: 640,
        upload_duplication: 23,
        download_duplication: 30,
        upload_compression: 0,
        download_compression: 0,
        stability: AutoTunePresetStability::Aggressive,
    },
    AutoTunePreset {
        id: "iran-wide-range-aggressive",
        label: "Iran Wide Range Max",
        min_upload_mtu: 100,
        max_upload_mtu: 1000,
        min_download_mtu: 200,
        max_download_mtu: 2667,
        resolver_timeout_ms: 2500,
        dns_frag_capacity: 256,
        upload_duplication: 15,
        download_duplication: 30,
        upload_compression: 2,
        download_compression: 2,
        stability: AutoTunePresetStability::Aggressive,
    },
];

/// Retrieves an auto-tune preset by its canonical identifier.
pub fn get_preset_by_id(id: &str) -> Option<&'static AutoTunePreset> {
    AUTO_TUNE_PRESETS.iter().find(|p| p.id == id)
}

/// Splits a list of upstream DNS resolvers round-robin across worker threads.
pub fn chunk_resolvers_round_robin(
    resolvers: &[String],
    requested_workers: usize,
) -> Vec<Vec<String>> {
    let clean: Vec<String> = resolvers
        .iter()
        .map(|r| r.trim().to_string())
        .filter(|r| !r.is_empty())
        .collect();

    if clean.is_empty() {
        return Vec::new();
    }

    let worker_count = requested_workers.max(1).min(clean.len());
    let mut chunks: Vec<Vec<String>> = vec![Vec::new(); worker_count];

    for (i, resolver) in clean.into_iter().enumerate() {
        chunks[i % worker_count].push(resolver);
    }

    chunks
}

/// Encapsulates a DNS server profile record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsProfileRecord {
    pub name: String,
    pub domain: String,
    pub encryption_key: String,
    pub encryption_method: u8,
    pub engine: String,
}

#[derive(Serialize, Deserialize)]
struct ProfileWireRoot {
    schema: String,
    version: u32,
    profile: ProfileWireProfile,
}

#[derive(Serialize, Deserialize)]
struct ProfileWireProfile {
    name: String,
    server: ProfileWireServer,
}

#[derive(Serialize, Deserialize)]
struct ProfileWireServer {
    domain: String,
    encryption_key: String,
    encryption_method: u8,
}

/// Encodes a DNS profile into a standard URI link (e.g. stormdns://base64url).
pub fn encode_dns_profile_link(record: &DnsProfileRecord) -> Result<String, String> {
    if record.domain.trim().is_empty() || record.encryption_key.trim().is_empty() {
        return Err("domain and encryption key are required".to_string());
    }

    let wire = ProfileWireRoot {
        schema: "whitedns.profile".to_string(),
        version: 1,
        profile: ProfileWireProfile {
            name: if record.name.is_empty() {
                record.domain.clone()
            } else {
                record.name.clone()
            },
            server: ProfileWireServer {
                domain: record.domain.trim().trim_end_matches('.').to_string(),
                encryption_key: record.encryption_key.trim().to_string(),
                encryption_method: record.encryption_method.min(5),
            },
        },
    };

    let json_bytes = serde_json::to_vec(&wire).map_err(|e| e.to_string())?;
    use base64::Engine;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&json_bytes);
    let scheme = if record.engine.is_empty() {
        "stormdns"
    } else {
        record.engine.as_str()
    };
    Ok(format!("{scheme}://{b64}"))
}

/// Decodes a DNS profile URI link back into a DnsProfileRecord.
pub fn decode_dns_profile_link(link: &str) -> Result<DnsProfileRecord, String> {
    let parts: Vec<&str> = link.split("://").collect();
    if parts.len() != 2 {
        return Err("invalid profile URI format".to_string());
    }
    let engine = parts[0].to_lowercase();
    let payload = parts[1].split(['#', '?']).next().unwrap_or("").trim();
    if payload.is_empty() {
        return Err("empty profile payload".to_string());
    }

    use base64::Engine;
    let decoded_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(payload))
        .map_err(|e| format!("invalid base64 payload: {e}"))?;

    let wire: ProfileWireRoot = serde_json::from_slice(&decoded_bytes)
        .map_err(|e| format!("invalid profile JSON structure: {e}"))?;

    if wire.schema != "whitedns.profile" {
        return Err(format!("unsupported profile schema: {}", wire.schema));
    }

    Ok(DnsProfileRecord {
        name: wire.profile.name,
        domain: wire.profile.server.domain,
        encryption_key: wire.profile.server.encryption_key,
        encryption_method: wire.profile.server.encryption_method,
        engine,
    })
}
