# Project Notes

- Tools are registered under their bare names (`search`, `get_release`). Do NOT add tool-name prefixing to this server: when it is deployed behind a Cloudflare MCP server portal, the portal's Server ID supplies the namespace (`music_search`), and a server-side prefix would double it.
- The stream server binds to `SERVER_HOST`. Cloud Run requires `0.0.0.0`, which is set explicitly on the dev and prod services rather than relying on the app default — security hardening changes that default to `127.0.0.1`.
- `READONLY_MODE=true` excludes every mutating tool from registration, so they are absent from the tool list rather than failing at call time. `tests/e2e/readonly-mode.e2e.mjs` verifies both directions against the real Discogs API.
