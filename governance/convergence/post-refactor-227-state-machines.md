# Post-refactor-227 state machines

## Captured SYN evidence

`absent -> registered -> consumed` or `absent -> registered -> expired/cleared`.

- Registration is exact-four-tuple scoped.
- Capacity is 4,096; stale entries are pruned and oldest evidence is evicted under pressure.
- `TakeConnSeq` is atomic and one-shot.
- Expired evidence cannot authorize an injection.

## SNI decoy handshake evidence

The read-only planner models:

1. no SYN: insufficient evidence;
2. SYN: expected real sequence is `client_isn + 1`;
3. valid SYN-ACK: ACK must equal the expected real sequence;
4. valid third ACK: client sequence must remain the expected real sequence and ACK the server sequence + 1;
5. fake injection evidence: expected fake sequence is `expected_real_seq - fake_payload_bytes`;
6. server confirmation: relay-ready only when the server still ACKs the expected real sequence;
7. RST at any modeled stage: failed-RST.

The planner has no side effect. It records what would be required for a live implementation to claim the donor lifecycle.

## Live out-of-window injection

`fresh exact SYN evidence -> consume -> inject canonical 517-byte decoy`; missing or stale evidence -> fail closed. The live path does not claim the full server-confirmation state machine above.
