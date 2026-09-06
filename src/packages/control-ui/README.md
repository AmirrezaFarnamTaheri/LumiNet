# LumiNet Control UI

This folder is the sole authored browser UI used by both the daemon web host and the Wails desktop host.

## Source and bundle ownership

- `src/` contains the React/TypeScript source.
- `public/` contains static assets copied by Vite.
- `dist/` in Git is intentionally a **fail-closed bootstrap**, not a production build. It prevents a source checkout from silently serving an obsolete functional bundle.
- `npm run build` replaces `dist/` with the current production bundle.
- CI and release workflows build the UI first, then build daemon/desktop hosts against that generated bundle.

A release must never package the checked bootstrap page. The release workflow's `build-control-ui` job is the authority for the production bundle.

## Commands

```bash
npm ci
npm test
npm run lint
npm run build
```

`npm test` includes contract parsing checks and the Wails session-transport fail-closed check.
