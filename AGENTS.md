# Project Notes

## Classifying a tool — the one rule

Every tool is classified in exactly one place: `TOOL_RISK` in
`src/tools/toolRisk.ts`. Adding a tool means adding one row there. Three
things derive from it automatically:

- **RBAC** — the `role` field is the minimum tier required to call the tool.
- **Read-only mode** — `READONLY_MODE=true` registers only tools whose
  `readOnly` is true. Do NOT add `if (options.readOnly)` blocks to tool
  files; `src/tools/register.ts` handles it.
- **MCP annotations** — the four `ToolAnnotations` hints are emitted from
  the same row.

Unclassified tools fall back to `UNKNOWN_TOOL_RISK` (admin + destructive),
so forgetting to classify denies access rather than granting it. A test
asserts every registered tool is classified, so this fails loudly in CI.

Annotations are hints for client UX per the MCP spec, not a security
boundary — clients may ignore or distrust them. Enforcement is the role
gate in `src/auth/toolAuthz.ts`, which runs server-side.

## Deployment

- Tools are registered under their bare names (`search`, `get_release`). Do
  NOT add tool-name prefixing to this server: behind a Cloudflare MCP server
  portal the portal's Server ID supplies the namespace (`music_search`), and
  a server-side prefix would double it.
- `SERVER_HOST` must be `0.0.0.0` on Cloud Run, set explicitly on the dev
  and prod services rather than relying on the app default — security
  hardening changes that default to `127.0.0.1`.
- RBAC is only enforced when `IDENTITY_ROLE_*_GROUPS` are set. When they're
  not, startup logs say so and `ALLOWED_GOOGLE_EMAILS` is the only gate.

## Tests

- `pnpm test` — 614 unit tests, no credentials needed.
- `tests/e2e/readonly-mode.e2e.mjs` — exercises `READONLY_MODE` against the
  real Discogs API (writes then restores one collection field). Needs
  `DISCOGS_PERSONAL_ACCESS_TOKEN`; excluded from `pnpm test`. Run it after
  any change to tool registration.
