# Post-refactor-222 security model

## Authority boundaries

Post-refactor-222 keeps one owner per consequential state transition. Peer repositories are evidence only. UI state, donor configuration, generated artifacts, risk scores, blocklists, benchmark scores, historical success, and documentation never grant authority by themselves.

- Configuration mutation authority remains `foundation/config.Manager.Mutate`: revision-CAS, fresh snapshot on retry, default three attempts, hard maximum eight, explicit expected revision means exactly one attempt.
- Remote side-effect retries remain `foundation/remoteaction.Executor`, with operation-scoped idempotency/reconciliation and bounded cancellation-aware retry semantics.
- API authentication remains the target-owned API-key/cookie middleware. Donor OAuth/password/OTP/email-account systems are not imported.
- Secrets remain behind the target secret store and shared redaction boundaries; donor plaintext/general JSON secret persistence and custom browser crypto are rejected.
- Remote endpoint admission uses canonical `netpolicy`; donor localhost-only URL checks do not become policy.
- Signed update staging owns artifact verification/publication. Device flashing/root/system-image workflows are excluded.

## Peer discovery trust boundary

The peer discovery plane is a read-only admission/planning surface. It accepts only operator-supplied candidate observations and an optional bounded local IPv4 CIDR deny list. It performs no DHT crawling, DNSBL lookups, tracker requests, peer handshakes, socket creation, persistence, routing or automatic trust updates.

Admission order is: parse local identity -> enforce candidate/result/CIDR bounds -> parse candidate identity/address -> reject self/duplicate identity -> require literal public IPv4 -> apply local CIDR deny policy -> require non-zero port -> reject duplicate endpoint -> verify BEP42 IP binding -> attach descriptive runtime trust -> annotate shared-address evidence -> sort by exact 160-bit XOR distance -> truncate to requested result bound.

A shared public address across multiple valid node IDs/ports is evidence, not automatic rejection, because NAT can produce that shape. Runtime trust is also evidence; it cannot bypass BEP42 or alter XOR ordering.

## Correlation and anonymity limits

Transport encryption, obfuscation, DNS tunneling, proxying, Tor integration, or other network-layer mechanisms must not be described as proof of anonymity against timing correlation, a global/passive observer, endpoint compromise, or application-layer identifiers. The deanonymization research donor is retained only as negative evidence for this claim boundary; no deanonymization tooling is imported.

## Access-risk heuristics

New-IP, device/browser/OS novelty, unusual time, impossible-travel, VPN/proxy/Tor, bot-user-agent, rapid-success and related login heuristics may be useful diagnostic risk signals in a future multi-user access model. In the current local-daemon product there is no such authoritative login-history entity, so these donor rules remain defensive reference/guardrail evidence.

If a future target-owned access-risk plane uses them, it must minimize retained PII, define expiry/deletion, separate observation from identity, test false-positive and replay behavior, and never authenticate a caller or automatically deny access solely because a heuristic score is high.

## Subscription deep-link admission

Deep links are untrusted proposals, not commands. LumiNet accepts only the bounded `luminet://import` shape and applies the canonical managed-profile HTTPS source validator before returning a proposal. Embedded credentials, fragments, paths, duplicate/unknown parameters, invalid names and oversized inputs fail closed. The inspect endpoint and Profiles prefill flow perform no fetch, persistence, refresh, activation, route mutation or configuration write; explicit profile creation remains the sole write path.

## Service identity and certificates

Remote/control service identity must fail closed. Warning-only unauthenticated modes, optional client verification for privileged RPC, and effectively perpetual generated self-signed certificates are not promoted. Compatibility fallbacks cannot silently disable caller authentication.

## Release trust

Update/release trust is target-owned and verification-first. Expected digests/signatures, bounded downloads, secure redirect admission, regular-file targets, file synchronization and durable publication are checked before a staged result becomes authoritative. On Unix, replacement uses atomic rename-overwrite followed by parent-directory synchronization. Windows retains an explicit portable remove-and-rename fallback and does not claim Unix directory-fsync semantics.

Donor signing keys, helper binaries, opaque JARs, ADB/fastboot/root workflows and OS-image mutation never become LumiNet release authority merely because a peer depends on them.

## DNS and non-executable payloads

DNS-Persist is retained through historical convergence evidence as a negative example of command/control, persistence and shellcode behavior over DNS. DNS names, records, tunnel payloads and resolver responses are untrusted data. DNS transport or parsing never implies code-execution authority; payload lengths, decoding and downstream use remain bounded and non-executable unless a separately authorized target contract explicitly defines an operation.

## Public configuration supply chain

High-churn public VPN/proxy aggregation (including goida-vpn-configs) is evidence about source diversity and unsafe-profile filtering, not trusted built-in product data. Explicitly configured remote sources remain subject to LumiNet source-health, egress, parser/schema, secret-redaction and profile-validation owners. Public scraped feeds cannot silently become authoritative defaults.

## Offensive or dual-use negative coverage

The CAPTCHA-solving donor, Tor deanonymization research, torrent fake-infohash/findspies probing, freerider/content-transfer behavior, and device-root/flashing workflows are accounted as evidence but are not promoted as operational capabilities. Where useful, their lessons become tests, claim limits, bounded admission policy, or guardrails around existing target owners.
