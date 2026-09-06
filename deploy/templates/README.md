# Deployment templates

Each child directory is an independently deployable provider template. The provider directory itself is the deployment seam; there is no extra enterprise category layer.

## Layout

- `apps-script-relay/` — Google Apps Script relay template.
- `cloudflare-worker/` — Cloudflare Worker templates/reference material.
- `telegram-bot/` — Telegram bot template.
- `vercel-relay/` — Vercel relay project; its `api/` directory is retained because Vercel routing depends on that source layout.

Canonical runtime relay implementations and shared policy live under `deploy/relays/`. The shared fixed-target contract is `deploy/relays/fixed_http_contract.mjs`.
