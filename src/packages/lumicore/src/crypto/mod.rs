//! # Crypto Module
//!
//! Cryptographic primitives for LumiNet.
//! Includes AES-GCM, ChaCha20 stream ciphers, FEC, HTTP tunnel,
//! Shadowsocks 2022 AEAD cipher suites, and Edwards25519/Curve25519 elliptic-curve operations.

pub mod aead_framing;
pub mod aes_ecb;
pub mod aes_gcm;
pub mod credential_bundle;
pub mod ecc_curve;
pub mod eih;
pub mod garlic_packet;
pub mod hkdf_keygen;
pub mod lower_base36;
pub mod mkem_kem;
pub mod mlkem;
pub mod qpp;
pub mod replay_ppbloom;
pub mod shadowsocks_2022;
pub mod stream_box;
pub mod tor_hybrid_encrypt;
pub mod tunnel;

pub use lower_base36 as lowerbase36;
pub use lower_base36::{decode as decode_lower_base36, encode as encode_lower_base36, encode_to_string as encode_lower_base36_to_string, LowerBase36Error};

pub use aead_framing::{Aead2022Reader, Aead2022Writer, AeadFramingError};
pub use aes_gcm::*;
pub use credential_bundle::CredentialBundle;
pub use ecc_curve::ECCCurve;
pub use eih::EihContext;
pub use hkdf_keygen::KeyGenerator;
pub use qpp::{qpp_decrypt, qpp_encrypt, QppCipher, QppConfig};
pub use replay_ppbloom::{PpbloomFilter, ReplayGuard};
pub use shadowsocks_2022::{
    Ss2022AeadCipher, Ss2022CipherKind, Ss2022Error,
};
pub use stream_box::*;
pub use tunnel::*;
