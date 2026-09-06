//! # Device Fingerprint Spoofing
//!
//! Android device identity spoofing for anti-detection.
//!
//! Spoofs: Build fields, system properties, CPU info, ANDROID_ID,
//! fingerprint, SDK version, and other device identifiers.

use std::collections::HashMap;

/// Device profile containing all spoofable fields.
#[derive(Debug, Clone)]
pub struct DeviceProfile {
    pub manufacturer: String,
    pub brand: String,
    pub model: String,
    pub device: String,
    pub product: String,
    pub fingerprint: String,
    pub id: String,
    pub display: String,
    pub release: String,
    pub sdk_int: u32,
    pub board: String,
    pub hardware: String,
    pub cpu_abi: String,
    pub cpu_abi2: String,
    pub android_id: String,
    pub serial: String,
    pub build_type: String,
    pub build_tags: String,
    pub cpu_info: Option<String>,
}

/// Pre-defined device profiles for common devices.
pub fn known_device_profiles() -> HashMap<&'static str, DeviceProfile> {
    let mut profiles = HashMap::new();

    profiles.insert(
        "pixel_7",
        DeviceProfile {
            manufacturer: "Google".to_string(),
            brand: "google".to_string(),
            model: "Pixel 7".to_string(),
            device: "panther".to_string(),
            product: "panther".to_string(),
            fingerprint: "google/panther/panther:14/UP1A.231105.001/11026767:user/release-keys"
                .to_string(),
            id: "UP1A.231105.001".to_string(),
            display: "UP1A.231105.001".to_string(),
            release: "14".to_string(),
            sdk_int: 34,
            board: "tensor".to_string(),
            hardware: "tensor".to_string(),
            cpu_abi: "arm64-v8a".to_string(),
            cpu_abi2: "".to_string(),
            android_id: String::new(),
            serial: String::new(),
            build_type: "user".to_string(),
            build_tags: "release-keys".to_string(),
            cpu_info: None,
        },
    );

    profiles.insert(
        "samsung_s23",
        DeviceProfile {
            manufacturer: "samsung".to_string(),
            brand: "samsung".to_string(),
            model: "SM-S911B".to_string(),
            device: "r0s".to_string(),
            product: "r0s".to_string(),
            fingerprint: "samsung/r0s/r0s:14/UP1A.231005.007/S911BXXU3BWJM:user/release-keys"
                .to_string(),
            id: "UP1A.231005.007".to_string(),
            display: "UP1A.231005.007".to_string(),
            release: "14".to_string(),
            sdk_int: 34,
            board: "taro".to_string(),
            hardware: "qcom".to_string(),
            cpu_abi: "arm64-v8a".to_string(),
            cpu_abi2: "".to_string(),
            android_id: String::new(),
            serial: String::new(),
            build_type: "user".to_string(),
            build_tags: "release-keys".to_string(),
            cpu_info: None,
        },
    );

    profiles.insert(
        "oneplus_13",
        DeviceProfile {
            manufacturer: "OnePlus".to_string(),
            brand: "OnePlus".to_string(),
            model: "CPH2651".to_string(),
            device: "CPH2651".to_string(),
            product: "CPH2651".to_string(),
            fingerprint:
                "OnePlus/CPH2651/OP593FL1:15/AP3A.241205.015/U_15.0.1.501:user/release-keys"
                    .to_string(),
            id: "AP3A.241205.015".to_string(),
            display: "AP3A.241205.015".to_string(),
            release: "15".to_string(),
            sdk_int: 35,
            board: "taro".to_string(),
            hardware: "qcom".to_string(),
            cpu_abi: "arm64-v8a".to_string(),
            cpu_abi2: "".to_string(),
            android_id: String::new(),
            serial: String::new(),
            build_type: "user".to_string(),
            build_tags: "release-keys".to_string(),
            cpu_info: None,
        },
    );

    profiles.insert(
        "redmagic_9",
        DeviceProfile {
            manufacturer: "nubia".to_string(),
            brand: "nubia".to_string(),
            model: "NX769J".to_string(),
            device: "NX769J".to_string(),
            product: "NX769J".to_string(),
            fingerprint: "nubia/NX769J/NX769J:14/UKQ1.231108.001/20240306.142612:user/release-keys"
                .to_string(),
            id: "UKQ1.231108.001".to_string(),
            display: "UKQ1.231108.001".to_string(),
            release: "14".to_string(),
            sdk_int: 34,
            board: "taro".to_string(),
            hardware: "qcom".to_string(),
            cpu_abi: "arm64-v8a".to_string(),
            cpu_abi2: "".to_string(),
            android_id: String::new(),
            serial: String::new(),
            build_type: "user".to_string(),
            build_tags: "release-keys".to_string(),
            cpu_info: Some("Snapdragon 8 Gen 3".to_string()),
        },
    );

    profiles
}

/// Fake CPU info content for Snapdragon 8 Elite.
pub const SNAPDRAGON_8_ELITE_CPUINFO: &str = r#"Processor	: AArch64 Processor rev 2 (aarch64)
processor	: 0
BogoMIPS	: 38.40
processor	: 1
BogoMIPS	: 38.40
processor	: 2
BogoMIPS	: 38.40
processor	: 3
BogoMIPS	: 38.40
processor	: 4
BogoMIPS	: 38.40
processor	: 5
BogoMIPS	: 38.40
processor	: 6
BogoMIPS	: 38.40
processor	: 7
BogoMIPS	: 38.40
Hardware	: Qualcomm Technologies, Inc SM8750
CPU implementer	: 0x51
CPU architecture: 8
CPU variant	: 0x2
CPU part	: 0x802
CPU revision	: 2
"#;

/// System property mapping for spoofing.
pub fn build_property_map(profile: &DeviceProfile) -> HashMap<String, String> {
    let mut props = HashMap::new();

    // Product properties
    props.insert(
        "ro.product.manufacturer".to_string(),
        profile.manufacturer.clone(),
    );
    props.insert("ro.product.brand".to_string(), profile.brand.clone());
    props.insert("ro.product.model".to_string(), profile.model.clone());
    props.insert("ro.product.device".to_string(), profile.device.clone());
    props.insert("ro.product.name".to_string(), profile.product.clone());

    // Build properties
    props.insert(
        "ro.build.fingerprint".to_string(),
        profile.fingerprint.clone(),
    );
    props.insert("ro.build.id".to_string(), profile.id.clone());
    props.insert("ro.build.display.id".to_string(), profile.display.clone());
    props.insert(
        "ro.build.version.release".to_string(),
        profile.release.clone(),
    );
    props.insert(
        "ro.build.version.sdk".to_string(),
        profile.sdk_int.to_string(),
    );
    props.insert("ro.build.type".to_string(), profile.build_type.clone());
    props.insert("ro.build.tags".to_string(), profile.build_tags.clone());
    props.insert("ro.build.board".to_string(), profile.board.clone());
    props.insert("ro.hardware".to_string(), profile.hardware.clone());
    props.insert("ro.product.cpu.abi".to_string(), profile.cpu_abi.clone());
    props.insert("ro.product.cpu.abi2".to_string(), profile.cpu_abi2.clone());

    // Additional properties
    props.insert("ro.product.locale".to_string(), "en-US".to_string());
    props.insert(
        "ro.build.characteristics".to_string(),
        "default".to_string(),
    );
    props.insert("ro.build.version.codename".to_string(), "REL".to_string());
    props.insert("ro.build.version.preview_sdk".to_string(), "0".to_string());
    props.insert(
        "ro.build.version.security_patch".to_string(),
        "2024-11-01".to_string(),
    );

    props
}

/// JNI Build field mapping for Android.
#[derive(Debug, Clone)]
pub struct BuildField {
    pub class_name: String,
    pub field_name: String,
    pub field_type: String,
    pub value: BuildValue,
}

#[derive(Debug, Clone)]
pub enum BuildValue {
    String(String),
    Int(i32),
    StringArray(Vec<String>),
}

/// Generates JNI Build field spoofing instructions.
pub fn generate_build_fields(profile: &DeviceProfile) -> Vec<BuildField> {
    vec![
        BuildField {
            class_name: "android/os/Build".to_string(),
            field_name: "MANUFACTURER".to_string(),
            field_type: "Ljava/lang/String;".to_string(),
            value: BuildValue::String(profile.manufacturer.clone()),
        },
        BuildField {
            class_name: "android/os/Build".to_string(),
            field_name: "BRAND".to_string(),
            field_type: "Ljava/lang/String;".to_string(),
            value: BuildValue::String(profile.brand.clone()),
        },
        BuildField {
            class_name: "android/os/Build".to_string(),
            field_name: "MODEL".to_string(),
            field_type: "Ljava/lang/String;".to_string(),
            value: BuildValue::String(profile.model.clone()),
        },
        BuildField {
            class_name: "android/os/Build".to_string(),
            field_name: "DEVICE".to_string(),
            field_type: "Ljava/lang/String;".to_string(),
            value: BuildValue::String(profile.device.clone()),
        },
        BuildField {
            class_name: "android/os/Build".to_string(),
            field_name: "PRODUCT".to_string(),
            field_type: "Ljava/lang/String;".to_string(),
            value: BuildValue::String(profile.product.clone()),
        },
        BuildField {
            class_name: "android/os/Build".to_string(),
            field_name: "FINGERPRINT".to_string(),
            field_type: "Ljava/lang/String;".to_string(),
            value: BuildValue::String(profile.fingerprint.clone()),
        },
        BuildField {
            class_name: "android/os/Build".to_string(),
            field_name: "ID".to_string(),
            field_type: "Ljava/lang/String;".to_string(),
            value: BuildValue::String(profile.id.clone()),
        },
        BuildField {
            class_name: "android/os/Build".to_string(),
            field_name: "DISPLAY".to_string(),
            field_type: "Ljava/lang/String;".to_string(),
            value: BuildValue::String(profile.display.clone()),
        },
        BuildField {
            class_name: "android/os/Build".to_string(),
            field_name: "BOARD".to_string(),
            field_type: "Ljava/lang/String;".to_string(),
            value: BuildValue::String(profile.board.clone()),
        },
        BuildField {
            class_name: "android/os/Build".to_string(),
            field_name: "HARDWARE".to_string(),
            field_type: "Ljava/lang/String;".to_string(),
            value: BuildValue::String(profile.hardware.clone()),
        },
        BuildField {
            class_name: "android/os/Build".to_string(),
            field_name: "TYPE".to_string(),
            field_type: "Ljava/lang/String;".to_string(),
            value: BuildValue::String(profile.build_type.clone()),
        },
        BuildField {
            class_name: "android/os/Build".to_string(),
            field_name: "TAGS".to_string(),
            field_type: "Ljava/lang/String;".to_string(),
            value: BuildValue::String(profile.build_tags.clone()),
        },
        BuildField {
            class_name: "android/os/Build$VERSION".to_string(),
            field_name: "RELEASE".to_string(),
            field_type: "Ljava/lang/String;".to_string(),
            value: BuildValue::String(profile.release.clone()),
        },
        BuildField {
            class_name: "android/os/Build$VERSION".to_string(),
            field_name: "SDK_INT".to_string(),
            field_type: "I".to_string(),
            value: BuildValue::Int(profile.sdk_int as i32),
        },
    ]
}

/// Anti-detection measures for Zygisk modules.
pub struct AntiDetection {
    /// Override __cxa_atexit to prevent detection.
    pub override_atexit: bool,
    /// Hide mount traces from /proc/mounts.
    pub hide_mount_traces: bool,
    /// Use /data/adb/ instead of /data/local/tmp/.
    pub use_secure_path: bool,
    /// Unmount denylist entries.
    pub force_denylist_unmount: bool,
}

impl Default for AntiDetection {
    fn default() -> Self {
        Self {
            override_atexit: true,
            hide_mount_traces: true,
            use_secure_path: true,
            force_denylist_unmount: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_profiles() {
        let profiles = known_device_profiles();
        assert!(profiles.contains_key("pixel_7"));
        assert!(profiles.contains_key("samsung_s23"));
        assert!(profiles.contains_key("oneplus_13"));
    }

    #[test]
    fn test_property_map() {
        let profiles = known_device_profiles();
        let profile = profiles.get("pixel_7").unwrap();
        let props = build_property_map(profile);

        assert_eq!(props.get("ro.product.manufacturer").unwrap(), "Google");
        assert_eq!(props.get("ro.product.model").unwrap(), "Pixel 7");
        assert_eq!(props.get("ro.build.version.sdk").unwrap(), "34");
    }

    #[test]
    fn test_build_fields() {
        let profiles = known_device_profiles();
        let profile = profiles.get("samsung_s23").unwrap();
        let fields = generate_build_fields(profile);

        assert!(fields.iter().any(|f| f.field_name == "MANUFACTURER"));
        assert!(fields.iter().any(|f| f.field_name == "MODEL"));
    }
}
