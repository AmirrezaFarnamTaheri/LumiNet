# Post-refactor-222 operator runbook

## Command palette

- Press `Ctrl+K` (or `Cmd+K` on macOS) to open the navigation palette.
- Type a partial destination name. Ranking is deterministic and limited to the canonical LumiNet navigation registry.
- Use Arrow Up/Down and Enter to navigate; Escape closes. Up to five validated recent destinations are stored locally.
- Palette state cannot execute shell commands, open arbitrary files or create backend routes.

## Appearance

- In Settings choose **System**, **Light**, or **Dark**.
- System follows the OS preference. The preference is local, validated on read and synchronized across tabs.
- Appearance has no daemon/network authority.

## Subscription deep-link inspection

- In **Profiles**, paste a `luminet://import?url=...&name=...` proposal and choose **Inspect & prefill**.
- Inspection accepts only the `luminet://import` contract, requires the canonical managed-profile HTTPS source policy, rejects embedded credentials/extra parameters and bounds URI/name length.
- Inspection is deliberately non-authoritative: it never fetches remote bytes, saves or refreshes a subscription, activates a connection, or mutates routing/configuration. Review the prefilled profile and explicitly create it through the normal profile owner.

## Health and diagnostics

- Open **Health** to view readiness, capability, passive network and UI transport evidence.
- `healthy` is only emitted when required evidence is present; missing source evidence is degraded/unavailable rather than assumed healthy.
- Export creates `luminet.redacted-diagnostics.v1`, an allow-listed structural bundle. It excludes configuration bodies, API keys, raw logs, MAC/interface addresses, credential-bearing URLs, free-form readiness text and raw network/source error strings.

## Live logs

- Live tail follows new entries while the viewport is at the bottom.
- Scrolling upward pauses auto-follow so new entries do not yank the viewport.
- Use **Resume live tail** to return to bottom-follow behavior.

## Endpoint pool planning

- The endpoint planner may include latency, jitter, packet loss, success/quota evidence, a deterministic selection scope and a previous-success hint.
- Previous success is only a continuity hint inside the five-point quality band; it cannot make an ineligible or materially worse endpoint preferred.
- Deterministic diversity only reorders near-equivalent eligible endpoints.

## Peer discovery planning

- Operations exposes the read-only peer planner at `POST /api/system/peer-discovery-plan` through the authenticated system API group.
- Supply one local 40-hex node ID, 1–1000 operator-observed candidates, optional local IPv4 CIDR deny prefixes (maximum 128) and `max_results` from 1–64 (default 20).
- Candidate addresses must be literal public IPv4. Admission rejects malformed/self/duplicate/non-public/blocked/port-zero/BEP42-mismatched candidates before exact XOR-distance ordering.
- Multiple valid peers sharing one public address are marked as shared-address evidence; they are not rejected solely for sharing an address because NAT is legitimate.
- Runtime trust scores are descriptive only. The planner performs no DHT/tracker discovery, DNSBL lookup, peer dial, persistence, route mutation or automatic trust mutation.

Example request shape:

```json
{
  "local_node_id": "<40 hex characters>",
  "blocked_cidrs": ["203.0.113.0/24"],
  "max_results": 20,
  "candidates": [{"node_id": "<40 hex characters>", "address": "198.51.100.10", "port": 6881}]
}
```

## Configuration mutation retry

- Server-owned configuration mutations use optimistic revision CAS.
- Automatic mutation attempts default to 3 and are hard-capped at 8.
- Only revision conflicts retry, and each retry reloads a fresh snapshot.
- If the caller supplies an explicit expected revision, exactly one attempt is made.
- External side effects are not replayed through this loop; they remain under `remoteaction.Executor` reconciliation/idempotency rules.

## Signed update staging

- Signed-update admission verifies bounded download metadata/content before publication.
- Existing publication targets must be regular files; symlink targets are rejected.
- Unix replaces a regular target with one rename-overwrite and synchronizes the parent directory after publication.
- Windows uses the explicit portable remove-and-rename fallback and does not claim Unix directory-fsync semantics.
