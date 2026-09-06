
use crypto_box::{
    aead::{Aead, AeadCore, OsRng, Payload},
    ChaChaBox, Nonce, PublicKey, SecretKey,
};

use std::{
    fs::File,
    io::{self, Error, ErrorKind, Read, Write},
    path::Path,
};

const PLAINTEXT_MSG_LEN: usize = 65536; // 64 KiB per payload
const KEY_LEN: usize = 32; // Size of the public key and secret key
const NONCE_LEN: usize = 24; // Each message has a 24 byte nonce
const MAC_LEN: usize = 16; // Each message has a 16 byte mac
const CIPHERTEXT_MSG_LEN: usize = PLAINTEXT_MSG_LEN + NONCE_LEN + MAC_LEN;

pub fn write_public_key(key: &PublicKey, path: &Path) -> io::Result<()> {
    File::create(path)?.write_all(key.as_bytes())?;
    Ok(())
}

pub fn read_public_key(path: &Path) -> io::Result<PublicKey> {
    let mut buf = [0; KEY_LEN];
    File::open(path)?.read_exact(&mut buf)?;
    Ok(PublicKey::from(buf))
}

pub fn write_secret_key(key: &SecretKey, path: &Path) -> io::Result<()> {
    File::create(path)?.write_all(key.as_bytes())?;
    Ok(())
}

pub fn read_secret_key(path: &Path) -> io::Result<SecretKey> {
    let mut buf = [0; KEY_LEN];
    File::open(path)?.read_exact(&mut buf)?;
    Ok(SecretKey::from(buf))
}

pub fn generate_and_write_key_pair(sec_path: &Path, pub_path: &Path) -> io::Result<()> {
    let sec_key = SecretKey::generate(&mut OsRng);
    let pub_key = sec_key.public_key();
    write_secret_key(&sec_key, sec_path)?;
    write_public_key(&pub_key, pub_path)
}

/// AutoEncryptor reads plaintexts, encrypts them, and writes
/// ciphertexts to the output using NaCl crypto_box (XChaCha20Poly1305 + X25519).
pub struct AutoEncryptor<W: Write> {
    key: PublicKey,
    crypto_box: ChaChaBox,
    msg_buf: Vec<u8>,
    writer: Option<W>,
    wrote_header: bool,
}

impl<W: Write> AutoEncryptor<W> {
    pub fn new(peer_key: PublicKey, writer: W) -> Self {
        let key = SecretKey::generate(&mut OsRng);
        Self {
            key: key.public_key(),
            crypto_box: ChaChaBox::new(&peer_key, &key),
            msg_buf: Vec::with_capacity(PLAINTEXT_MSG_LEN),
            writer: Some(writer),
            wrote_header: false,
        }
    }

    pub fn finish(mut self) -> io::Result<W> {
        self.write_inner(true)?;
        self.writer.as_mut().unwrap().flush()?;
        Ok(self.writer.take().unwrap())
    }

    fn write_encrypted_message(&mut self, msg: &[u8]) -> io::Result<()> {
        let nonce = ChaChaBox::generate_nonce(&mut OsRng);

        let payload = Payload {
            msg,
            aad: nonce.as_ref(),
        };

        let ciphertext = match self.crypto_box.encrypt(&nonce, payload) {
            Ok(vec) => vec,
            Err(e) => return Err(Error::other(e.to_string())),
        };

        self.writer.as_mut().unwrap().write_all(nonce.as_ref())?;
        self.writer
            .as_mut()
            .unwrap()
            .write_all(ciphertext.as_slice())?;
        Ok(())
    }

    fn write_inner(&mut self, finalize: bool) -> io::Result<()> {
        if !self.wrote_header {
            // Write our generated public key first (needed for decryption)
            self.writer.as_mut().unwrap().write_all(self.key.as_ref())?;
            self.wrote_header = true;
        }

        while self.msg_buf.len() >= PLAINTEXT_MSG_LEN {
            let msg: Vec<u8> = self.msg_buf.drain(0..PLAINTEXT_MSG_LEN).collect();
            self.write_encrypted_message(msg.as_slice())?;
        }

        if finalize && !self.msg_buf.is_empty() {
            let remaining: Vec<u8> = self.msg_buf.drain(..).collect();
            self.write_encrypted_message(remaining.as_slice())?;
        }

        Ok(())
    }
}

impl<W: Write> Drop for AutoEncryptor<W> {
    fn drop(&mut self) {
        if self.writer.is_some() {
            let _ = self.write_inner(true);
            let _ = self.writer.as_mut().unwrap().flush();
        }
    }
}

impl<W: Write> Write for AutoEncryptor<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.msg_buf.extend_from_slice(buf);
        self.write_inner(false)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.write_inner(false)?;
        self.writer.as_mut().unwrap().flush()
    }
}

/// AutoDecryptor reads ciphertexts, decrypts, and writes plaintexts.
pub struct AutoDecryptor<W: Write> {
    key: SecretKey,
    crypto_box: Option<ChaChaBox>,
    msg_buf: Vec<u8>,
    writer: Option<W>,
    read_header: bool,
}

impl<W: Write> AutoDecryptor<W> {
    pub fn new(key: SecretKey, writer: W) -> Self {
        Self {
            key,
            crypto_box: None,
            msg_buf: Vec::with_capacity(CIPHERTEXT_MSG_LEN),
            writer: Some(writer),
            read_header: false,
        }
    }

    pub fn finish(mut self) -> io::Result<W> {
        self.write_inner(true)?;
        self.writer.as_mut().unwrap().flush()?;
        Ok(self.writer.take().unwrap())
    }

    fn write_decrypted_message(&mut self, msg: &[u8]) -> io::Result<()> {
        let crypto_box = match &self.crypto_box {
            Some(cb) => cb,
            None => return Err(Error::other("Crypto box is not initialized")),
        };

        if msg.len() < NONCE_LEN {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "message too short for nonce",
            ));
        }

        let nonce = {
            let mut nonce_buf: [u8; NONCE_LEN] = [0; NONCE_LEN];
            nonce_buf.copy_from_slice(&msg[0..NONCE_LEN]);
            Nonce::from(nonce_buf)
        };

        let payload = Payload {
            msg: msg[NONCE_LEN..].as_ref(),
            aad: nonce.as_ref(),
        };

        let plaintext = match crypto_box.decrypt(&nonce, payload) {
            Ok(vec) => vec,
            Err(e) => return Err(Error::other(e.to_string())),
        };

        self.writer
            .as_mut()
            .unwrap()
            .write_all(plaintext.as_ref())?;
        Ok(())
    }

    fn write_inner(&mut self, finalize: bool) -> io::Result<()> {
        if !self.read_header {
            if self.msg_buf.len() < KEY_LEN {
                return Err(Error::from(ErrorKind::WouldBlock));
            }

            // Read the generated peer public key
            let peer_key = {
                let key_bytes: Vec<u8> = self.msg_buf.drain(0..KEY_LEN).collect();
                let mut key_buf: [u8; KEY_LEN] = [0; KEY_LEN];
                key_buf.copy_from_slice(key_bytes.as_slice());
                PublicKey::from(key_buf)
            };

            self.crypto_box = Some(ChaChaBox::new(&peer_key, &self.key));
            self.read_header = true;
        }

        while self.msg_buf.len() >= CIPHERTEXT_MSG_LEN {
            let msg: Vec<u8> = self.msg_buf.drain(0..CIPHERTEXT_MSG_LEN).collect();
            self.write_decrypted_message(msg.as_slice())?;
        }

        if finalize && self.msg_buf.len() >= NONCE_LEN + MAC_LEN {
            let remaining: Vec<u8> = self.msg_buf.drain(..).collect();
            self.write_decrypted_message(remaining.as_slice())?;
        }

        Ok(())
    }
}

impl<W: Write> Drop for AutoDecryptor<W> {
    fn drop(&mut self) {
        if self.writer.is_some() {
            let _ = self.write_inner(true);
            let _ = self.writer.as_mut().unwrap().flush();
        }
    }
}

impl<W: Write> Write for AutoDecryptor<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.msg_buf.extend_from_slice(buf);
        match self.write_inner(false) {
            Ok(_) => Ok(buf.len()),
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(buf.len()),
            Err(e) => Err(e),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.write_inner(false) {
            Ok(_) => self.writer.as_mut().unwrap().flush(),
            Err(e) if e.kind() == ErrorKind::WouldBlock => self.writer.as_mut().unwrap().flush(),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_box_encrypt_decrypt() {
        let alice_sec = SecretKey::generate(&mut OsRng);
        let _alice_pub = alice_sec.public_key();

        let bob_sec = SecretKey::generate(&mut OsRng);
        let bob_pub = bob_sec.public_key();

        let mut cipher_buffer = Vec::new();
        // Alice encrypts for Bob
        let mut encryptor = AutoEncryptor::new(bob_pub, &mut cipher_buffer);

        let plaintext = b"Hello, this is a secret message to be encrypted with NaCl crypto_box stream encryptor!";
        encryptor.write_all(plaintext).unwrap();
        // Flush/finish
        let _ = encryptor.finish().unwrap();

        // Bob decrypts Alice's message
        let mut decrypted_buffer = Vec::new();
        let mut decryptor = AutoDecryptor::new(bob_sec, &mut decrypted_buffer);
        decryptor.write_all(&cipher_buffer).unwrap();
        let _ = decryptor.finish().unwrap();

        assert_eq!(decrypted_buffer, plaintext);
    }
}
