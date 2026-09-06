# Post-refactor 83-donor operator runbook

## SSH host identity migration

Provisioning and SSH covert-tunnel requests now require `ssh_host_key_sha256` in OpenSSH fingerprint form (`SHA256:<base64-digest>`). Obtain the fingerprint from a trusted channel before connecting. A missing, malformed, or mismatching fingerprint is a hard failure; LumiNet does not use TOFU or an insecure fallback.

## Docker bootstrap

Automatic Docker installation is supported only on apt-based Debian/Ubuntu hosts. LumiNet refreshes signed apt metadata, resolves the distro `docker.io` candidate, pins that exact candidate in the installation command, and verifies Docker afterward. On other distributions, preinstall Docker before provisioning.

## Relay behavior

Polling relay connections have 1 MiB transmit and receive capacity. A write may block while capacity is exhausted and is governed by the write deadline. Reads wait for inbound data and are governed by the read deadline. Repeated upstream relay failures back off from 250 ms up to 10 seconds and reset after a successful exchange. Cancellation interrupts backoff.

## Endpoint pool admission

Endpoints with no observations or no successful observations remain visible in diagnostic evidence but are not eligible for `DispatchOrder`. At least one successful observation is required before an endpoint can receive dispatch authority.

## Rust FFI claim boundary

The legacy Rust C ABI is structurally frozen at 42 exported functions and passes static ABI/safety checkers. Native Rust compilation and Miri were not available in the verification environment; run `cargo fmt -- --check`, `cargo clippy`, `cargo test`, and Miri/native ABI verification before a native release when the declared Rust toolchain is available.
