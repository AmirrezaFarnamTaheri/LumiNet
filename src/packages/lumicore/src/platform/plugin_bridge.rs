use serde::{Deserialize, Serialize};

/// Action and metadata constants for Android external native plugin bridge IPC.
pub const ACTION_NATIVE_PLUGIN: &str = "io.nekohasekai.sagernet.plugin.ACTION_NATIVE_PLUGIN";
pub const EXTRA_ENTRY: &str = "io.nekohasekai.sagernet.plugin.EXTRA_ENTRY";
pub const METADATA_KEY_ID: &str = "io.nekohasekai.sagernet.plugin.id";
pub const METADATA_KEY_EXECUTABLE_PATH: &str = "io.nekohasekai.sagernet.plguin.executable_path";
pub const METHOD_GET_EXECUTABLE: &str = "sagernet:getExecutable";
pub const DEFAULT_PLUGIN_PERMISSIONS: u32 = 0o755; // 0b111101101 (rwxr-xr-x)

/// Detected binary file format of the native plugin executable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BinaryHeaderType {
    Elf,
    MachO,
    Pe,
    Unknown,
}

/// Detects binary executable format from initial bytes.
pub fn detect_binary_format(header: &[u8]) -> BinaryHeaderType {
    if header.len() >= 4 && header[0..4] == [0x7f, b'E', b'L', b'F'] {
        BinaryHeaderType::Elf
    } else if header.len() >= 2 && header[0..2] == [b'M', b'Z'] {
        BinaryHeaderType::Pe
    } else if header.len() >= 4
        && (header[0..4] == [0xfe, 0xed, 0xfa, 0xce]
            || header[0..4] == [0xfe, 0xed, 0xfa, 0xcf]
            || header[0..4] == [0xca, 0xfe, 0xba, 0xbe])
    {
        BinaryHeaderType::MachO
    } else {
        BinaryHeaderType::Unknown
    }
}

/// Descriptor detailing an external native plugin provider.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NativePluginDescriptor {
    pub id: String,
    pub name: String,
    pub executable_path: String,
    pub file_mode: u32,
    pub environment_args: Vec<String>,
}

impl NativePluginDescriptor {
    pub fn new(id: impl Into<String>, name: impl Into<String>, executable_path: impl Into<String>) -> Self {
        NativePluginDescriptor {
            id: id.into(),
            name: name.into(),
            executable_path: executable_path.into(),
            file_mode: DEFAULT_PLUGIN_PERMISSIONS,
            environment_args: Vec::new(),
        }
    }
}

/// Command builder formulating outbound runtime arguments for native proxy plugins.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginCommandBuilder {
    pub bind_address: String,
    pub bind_port: u16,
    pub remote_dns: String,
    pub sni: Option<String>,
    pub doh_url: Option<String>,
    pub split_sni: bool,
    pub udp_mode: bool,
}

impl PluginCommandBuilder {
    pub fn new(bind_address: impl Into<String>, bind_port: u16) -> Self {
        PluginCommandBuilder {
            bind_address: bind_address.into(),
            bind_port,
            remote_dns: "1.1.1.1".to_string(),
            sni: None,
            doh_url: None,
            split_sni: false,
            udp_mode: true,
        }
    }

    /// Formats command-line arguments passed to the external native plugin process.
    pub fn build_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        args.push("-l".to_string());
        args.push(format!("{}:{}", self.bind_address, self.bind_port));

        args.push("-d".to_string());
        args.push(self.remote_dns.clone());

        if let Some(ref sni) = self.sni {
            args.push("-s".to_string());
            args.push(sni.clone());
        }

        if let Some(ref doh) = self.doh_url {
            args.push("--doh".to_string());
            args.push(doh.clone());
        }

        if self.split_sni {
            args.push("--split-sni".to_string());
        }

        if self.udp_mode {
            args.push("-u".to_string());
        }

        args
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binary_header_detection() {
        let elf_hdr = [0x7f, b'E', b'L', b'F', 0x02, 0x01, 0x01, 0x00];
        assert_eq!(detect_binary_format(&elf_hdr), BinaryHeaderType::Elf);

        let pe_hdr = [b'M', b'Z', 0x90, 0x00];
        assert_eq!(detect_binary_format(&pe_hdr), BinaryHeaderType::Pe);

        let macho_hdr = [0xca, 0xfe, 0xba, 0xbe];
        assert_eq!(detect_binary_format(&macho_hdr), BinaryHeaderType::MachO);

        let random_hdr = [0x01, 0x02, 0x03, 0x04];
        assert_eq!(detect_binary_format(&random_hdr), BinaryHeaderType::Unknown);
    }

    #[test]
    fn test_plugin_descriptor_creation() {
        let desc = NativePluginDescriptor::new(
            "com.luminet.plugin.outbound",
            "LumiNet Plugin",
            "/data/app/lib/arm64/libproxy.so",
        );
        assert_eq!(desc.id, "com.luminet.plugin.outbound");
        assert_eq!(desc.file_mode, DEFAULT_PLUGIN_PERMISSIONS);
        assert_eq!(desc.file_mode, 0b111101101); // 0o755
    }

    #[test]
    fn test_command_builder_args() {
        let mut builder = PluginCommandBuilder::new("127.0.0.1", 10808);
        builder.remote_dns = "8.8.8.8".to_string();
        builder.sni = Some("speedtest.net".to_string());
        builder.doh_url = Some("https://1.1.1.1/dns-query".to_string());
        builder.split_sni = true;
        builder.udp_mode = true;

        let args = builder.build_args();
        assert!(args.contains(&"-l".to_string()));
        assert!(args.contains(&"127.0.0.1:10808".to_string()));
        assert!(args.contains(&"-d".to_string()));
        assert!(args.contains(&"8.8.8.8".to_string()));
        assert!(args.contains(&"-s".to_string()));
        assert!(args.contains(&"speedtest.net".to_string()));
        assert!(args.contains(&"--doh".to_string()));
        assert!(args.contains(&"https://1.1.1.1/dns-query".to_string()));
        assert!(args.contains(&"--split-sni".to_string()));
        assert!(args.contains(&"-u".to_string()));
    }
}
