// SPDX-License-Identifier: MIT

use lumicore::evasion::amneziawg_shaper::{
    forwarded_ports_include, parse_forwarded_ports, Obfuscation31, MAX_FORWARDED_PORTS,
};

#[test]
fn test_amneziawg_generation_and_validation() {
    for _ in 0..50 {
        let obfs = Obfuscation31::generate();
        assert!(
            obfs.validate().is_ok(),
            "Generated AmneziaWG obfuscation set must pass validation: {:?}",
            obfs
        );

        assert!(obfs.jc >= 3 && obfs.jc <= 6);
        assert!(obfs.jmin <= obfs.jmax);
        assert_ne!(obfs.s1 + 56, obfs.s2);
        assert!(obfs.s3 <= 64);
        assert!(obfs.s4 <= 32);
        assert!(obfs.header_protection_key.is_some());
    }
}

#[test]
fn test_amneziawg_validation_rejections() {
    let mut obfs = Obfuscation31::generate();

    // S1+56 == S2 invalidation
    obfs.s1 = 44;
    obfs.s2 = 100; // 44 + 56 = 100
    assert!(obfs.validate().is_err());

    // S3 > 64 invalidation
    obfs.s2 = 101;
    obfs.s3 = 65;
    assert!(obfs.validate().is_err());

    // S4 > 32 invalidation
    obfs.s3 = 30;
    obfs.s4 = 33;
    assert!(obfs.validate().is_err());

    // Jmin > Jmax invalidation
    obfs.s4 = 20;
    obfs.jmin = 200;
    obfs.jmax = 100;
    assert!(obfs.validate().is_err());

    // Header protection key with S1 < 12
    obfs.jmin = 50;
    obfs.jmax = 100;
    obfs.s1 = 11;
    assert!(obfs.validate().is_err());
}

#[test]
fn test_amneziawg_port_forward_parsing() {
    let spec = "80, 443; 8080-8082, 80";
    let ports = parse_forwarded_ports(spec);
    assert_eq!(ports, vec![80, 443, 8080, 8081, 8082]);

    assert!(forwarded_ports_include(spec, 80));
    assert!(forwarded_ports_include(spec, 8081));
    assert!(!forwarded_ports_include(spec, 9000));
}

#[test]
fn test_amneziawg_port_forward_cap() {
    let spec = "1-300";
    let ports = parse_forwarded_ports(spec);
    assert_eq!(ports.len(), MAX_FORWARDED_PORTS);
    assert_eq!(ports[0], 1);
    assert_eq!(ports[MAX_FORWARDED_PORTS - 1], 100);
}
