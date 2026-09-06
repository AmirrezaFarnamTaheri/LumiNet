// SPDX-License-Identifier: MIT
//
// Stable-toolchain fuzz-style harness (roadmap item 9 companion). The
// cargo-fuzz target under fuzz/ is the high-fidelity fuzzer (needs
// nightly + cargo-fuzz); this module gives every platform and CI the
// same crash-invariant guarantee deterministically: random mutation of
// a seed Initial datagram must never panic the parse/decrypt path.
//
// The PRNG is a fixed-seed xorshift so failures are reproducible.

#[cfg(test)]
mod fuzz_ish {
    use super::super::client_initial::decrypt_initial_v1;
    use std::net::Ipv4Addr;
    use std::net::SocketAddr;

    struct XorShift(u64);
    impl XorShift {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
    }

    fn seed_datagram() -> Vec<u8> {
        // Minimal plausible v1 Initial long header: 0xc3, version 1,
        // DCID len 8, some DCID, then garbage payload.
        let mut d = vec![0xc3, 0x00, 0x00, 0x00, 0x01];
        d.push(8);
        d.extend_from_slice(&[0xab; 8]);
        d.push(0x00); // packet number / token placeholder bytes
        d.extend_from_slice(&[0x55u8; 64]);
        d
    }

    #[test]
    fn mutated_initials_never_panic() {
        let addr = SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 443));
        let mut rng = XorShift(0x4c4f43414c);
        for round in 0..20_000u32 {
            let mut d = seed_datagram();
            // Mutate 1-8 random bytes and occasionally truncate.
            let mutations = 1 + (rng.next() % 8) as usize;
            for _ in 0..mutations {
                let idx = (rng.next() as usize) % d.len();
                d[idx] = (rng.next() & 0xff) as u8;
            }
            if rng.next() & 1 == 1 {
                let keep = 1 + (rng.next() as usize) % d.len();
                d.truncate(keep);
            }
            // The invariant: any input shape returns Ok/Err, never panics.
            let _ = decrypt_initial_v1(&d, false);
            let _ = decrypt_initial_v1(&d, true);
            let _ = addr;
            let _ = round;
        }
    }

    #[test]
    fn bitflip_corpus_never_panics() {
        // Exhaustive single-bit flips over the first 40 bytes: the whole
        // header-field space is covered deterministically.
        let d = seed_datagram();
        for byte_idx in 0..40.min(d.len()) {
            for bit in 0..8u32 {
                let mut m = d.clone();
                m[byte_idx] ^= 1 << bit;
                let _ = decrypt_initial_v1(&m, false);
                let _ = decrypt_initial_v1(&m, true);
            }
        }
    }
}
