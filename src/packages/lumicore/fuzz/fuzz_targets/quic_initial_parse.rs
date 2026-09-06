// R5 hardening: fuzz the QUIC Initial parse/decrypt path (mirror of the
// DCID bounds bug class found during the clienthellod port).
// Run: cargo +nightly fuzz run quic_initial_parse -- -max_len=4096
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Must never panic regardless of input shape.
    let _ = lumicore::quic::client_initial::decrypt_initial_v1(data, false);
    let _ = lumicore::quic::client_initial::decrypt_initial_v1(data, true);
});
