//! # SSH Handshake Seed Obfuscation
//!
//! Implements the RC4-based SSH connection obfuscator from obfuscated-openssh.
//!
//! The protocol replaces the plaintext "SSH-2.0-..." banner with a random
//! seed exchange. Both sides derive RC4 key streams from the seed and
//! XOR all subsequent traffic until the real SSH negotiation begins.
//!
//! Wire format:
//!   Client → Server: [random_seed : SEED_LEN bytes]
//!   Server uses seed to derive RC4 key, client uses same seed.
//!   All subsequent bytes are XOR'd with the RC4 key stream.
//!
//! Reference: obfuscated-openssh-master / obfuscate.c

use sha2::{Sha256, Digest};

/// Number of random seed bytes exchanged at connection start.
pub const SEED_LEN: usize = 16;
/// RC4 key schedule size.
const RC4_STATE_SIZE: usize = 256;

/// RC4 stream cipher state.
pub struct Rc4State {
    s: [u8; RC4_STATE_SIZE],
    i: u8,
    j: u8,
}

impl Rc4State {
    /// Initializes RC4 from a key derived by hashing the seed.
    ///
    /// The key schedule applies SHA-256(seed) as the RC4 key to avoid
    /// directly exposing the raw seed in the key stream.
    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Self {
        let key = Sha256::digest(seed);
        Self::from_key(&key)
    }

    /// Initializes RC4 from a raw key byte slice.
    pub fn from_key(key: &[u8]) -> Self {
        assert!(!key.is_empty(), "RC4 key must not be empty");
        let mut s: [u8; RC4_STATE_SIZE] = core::array::from_fn(|i| i as u8);
        let mut j: u8 = 0;
        for i in 0..RC4_STATE_SIZE {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }
        Self { s, i: 0, j: 0 }
    }

    /// Generates the next byte of the key stream.
    pub fn next_byte(&mut self) -> u8 {
        self.i = self.i.wrapping_add(1);
        self.j = self.j.wrapping_add(self.s[self.i as usize]);
        self.s.swap(self.i as usize, self.j as usize);
        self.s[self.s[self.i as usize].wrapping_add(self.s[self.j as usize]) as usize]
    }

    /// XOR-encodes/decodes a buffer with the RC4 key stream (in-place).
    pub fn apply_keystream(&mut self, buf: &mut [u8]) {
        for byte in buf.iter_mut() {
            *byte ^= self.next_byte();
        }
    }

    /// XOR-encodes a buffer and returns a new vector.
    pub fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        data.iter().map(|&b| b ^ self.next_byte()).collect()
    }
}

/// Manages the full SSH obfuscation handshake for the client side.
///
/// 1. Generates and sends a random seed.
/// 2. Derives the RC4 state from the seed.
/// 3. All subsequent I/O is passed through the RC4 cipher.
pub struct SshObfsClient {
    seed: [u8; SEED_LEN],
    cipher: Rc4State,
    handshake_done: bool,
}

impl SshObfsClient {
    /// Creates a new client with a freshly generated random seed.
    pub fn new() -> Self {
        let mut seed = [0u8; SEED_LEN];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut seed);
        let cipher = Rc4State::from_seed(&seed);
        Self { seed, cipher, handshake_done: false }
    }

    /// Returns the seed bytes to send to the server as the opening message.
    pub fn seed_bytes(&self) -> &[u8; SEED_LEN] {
        &self.seed
    }

    /// Marks handshake complete. Call after transmitting the seed.
    pub fn complete_handshake(&mut self) {
        self.handshake_done = true;
    }

    /// Encrypts outgoing SSH traffic. Only valid after handshake.
    pub fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        self.cipher.encrypt(data)
    }

    /// Decrypts incoming SSH traffic. Only valid after handshake.
    pub fn decrypt(&mut self, data: &[u8]) -> Vec<u8> {
        // RC4 is symmetric: XOR with key stream decrypts.
        self.cipher.encrypt(data)
    }
}

/// Manages the full SSH obfuscation handshake for the server side.
///
/// 1. Receives the client's seed.
/// 2. Derives the RC4 state from the seed.
/// 3. All subsequent I/O is passed through the RC4 cipher.
pub struct SshObfsServer {
    cipher: Option<Rc4State>,
}

impl SshObfsServer {
    pub fn new() -> Self {
        Self { cipher: None }
    }

    /// Processes the received client seed and initializes the cipher.
    ///
    /// # Errors
    /// Returns `ObfsError::ShortSeed` if the buffer is shorter than `SEED_LEN`.
    pub fn receive_seed(&mut self, data: &[u8]) -> Result<(), ObfsError> {
        if data.len() < SEED_LEN {
            return Err(ObfsError::ShortSeed {
                expected: SEED_LEN,
                got: data.len(),
            });
        }
        let seed: [u8; SEED_LEN] = data[..SEED_LEN].try_into().unwrap();
        self.cipher = Some(Rc4State::from_seed(&seed));
        Ok(())
    }

    /// Returns true once the seed has been received and the cipher is initialized.
    pub fn is_ready(&self) -> bool {
        self.cipher.is_some()
    }

    /// Decrypts incoming client traffic.
    ///
    /// # Errors
    /// Returns `ObfsError::NotReady` if `receive_seed` has not been called.
    pub fn decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>, ObfsError> {
        let cipher = self.cipher.as_mut().ok_or(ObfsError::NotReady)?;
        Ok(cipher.encrypt(data)) // RC4 is symmetric
    }

    /// Encrypts outgoing server traffic.
    pub fn encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>, ObfsError> {
        self.decrypt(data) // same operation
    }
}

/// Errors from SSH obfuscation operations.
#[derive(Debug, thiserror::Error)]
pub enum ObfsError {
    #[error("seed too short: expected {expected} bytes, got {got}")]
    ShortSeed { expected: usize, got: usize },
    #[error("cipher not initialized: call receive_seed() first")]
    NotReady,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rc4_roundtrip() {
        let seed = [0xABu8; SEED_LEN];
        let mut enc = Rc4State::from_seed(&seed);
        let mut dec = Rc4State::from_seed(&seed);

        let plaintext = b"SSH-2.0-OpenSSH_9.0 obfuscated";
        let ciphertext = enc.encrypt(plaintext);
        let recovered = dec.encrypt(&ciphertext);
        assert_eq!(&recovered, plaintext);
    }

    #[test]
    fn test_client_server_handshake() {
        let mut client = SshObfsClient::new();
        let mut server = SshObfsServer::new();

        // Server receives seed
        server.receive_seed(client.seed_bytes()).unwrap();
        assert!(server.is_ready());

        client.complete_handshake();

        // Client encrypts → server decrypts
        let data = b"fake SSH banner data";
        let ct = client.encrypt(data);
        let pt = server.decrypt(&ct).unwrap();
        assert_eq!(pt, data);
    }

    #[test]
    fn test_server_encrypt_client_decrypt() {
        let mut client = SshObfsClient::new();
        let mut server = SshObfsServer::new();
        server.receive_seed(client.seed_bytes()).unwrap();
        client.complete_handshake();

        let response = b"server response payload";
        let ct = server.encrypt(response).unwrap();
        let pt = client.decrypt(&ct);
        assert_eq!(pt, response);
    }

    #[test]
    fn test_short_seed_rejected() {
        let mut server = SshObfsServer::new();
        let result = server.receive_seed(b"too_short");
        assert!(matches!(result, Err(ObfsError::ShortSeed { .. })));
    }

    #[test]
    fn test_keystream_not_zero() {
        let seed = [0u8; SEED_LEN];
        let mut rc4 = Rc4State::from_seed(&seed);
        let stream: Vec<u8> = (0..32).map(|_| rc4.next_byte()).collect();
        // SHA-256 of all-zeros seed produces a non-trivial key stream
        assert!(stream.iter().any(|&b| b != 0));
    }
}
