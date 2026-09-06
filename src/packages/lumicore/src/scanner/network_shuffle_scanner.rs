
use std::net::Ipv4Addr;

pub struct BlackrockScanner {
    range: u32,
    rounds: u32,
    seed: u32,
    a: u32,
    b: u32,
}

impl BlackrockScanner {
    /// Creates a new Blackrock Feistel cipher state targeting a specific IP range size.
    pub fn new(range: u32, seed: u32) -> Self {
        // Find a and b such that a * b >= range
        let mut a = (range as f64).sqrt() as u32;
        while a * a < range {
            a += 1;
        }
        let b = a;

        BlackrockScanner {
            range,
            rounds: 4,
            seed,
            a,
            b,
        }
    }

    /// Encrypts index in the range [0, range) using the Feistel cipher
    /// to obtain a pseudo-randomized index with O(1) memory.
    pub fn shuffle(&self, index: u32) -> u32 {
        if index >= self.range {
            return index;
        }

        let mut val = index;
        loop {
            let mut l = val % self.a;
            let mut r = val / self.a;

            for round in 0..self.rounds {
                let next_l = r;
                let next_r = (l + self.feistel_round_function(r, round)) % self.b;
                l = next_l;
                r = next_r;
            }

            val = r * self.a + l;
            if val < self.range {
                return val;
            }
        }
    }

    fn feistel_round_function(&self, val: u32, round: u32) -> u32 {
        // Mocking round permutations using S-Box like seed operations
        let mut x = val ^ self.seed ^ round;
        x = x.wrapping_mul(0x5bd1e995);
        x ^= x >> 15;
        x
    }

    /// Resolves index to an IPv4 address.
    pub fn index_to_ip(&self, index: u32, start_ip: Ipv4Addr) -> Ipv4Addr {
        let base = u32::from(start_ip);
        let target = base.wrapping_add(self.shuffle(index));
        Ipv4Addr::from(target)
    }
}
