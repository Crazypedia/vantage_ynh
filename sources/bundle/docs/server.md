# Vantage server — self-hosting guide

The hosted Vantage is a single Node process with **zero runtime
dependencies** (`node:http`, `node:sqlite`, `node:crypto`). It serves the
built UI and acts as the gateway between your browser and everything else:
your instance, OSINT services, and keyless lookups. See
[hosted-design.md](hosted-design.md) for the full design.

Phase 1 (this document) covers: static UI serving, instance login
(OAuth + PKCE for the Mastodon family, MiAuth for Misskey/Sharkey),
the instance allow-list, moderator role gating, vaulted tokens, sessions,
and the audit log. The instance/OSINT/lookup gateways arrive in later
phases.

## Quickstart

```bash
# Node ≥ 22.5 required (node:sqlite)
npm run build     # writes dist/index.html
npm start         # http://127.0.0.1:8686
```

First start creates `data/` with the SQLite database and a generated
`master.key`. **Back up `data/master.key`** (or pin the key via env) —
losing it means every vaulted token and API key is unrecoverable.

Log in by visiting `/auth/login?host=your.instance` (the UI gains a login
screen in phase 2). Your own instance shows its consent screen; accounts
without moderation permissions are rejected and their token revoked.

## Configuration

Everything is environment variables. Only `VANTAGE_PUBLIC_URL` is required
in production (OAuth/MiAuth callbacks must know the real origin).

| Variable | Default | Purpose |
|---|---|---|
| `VANTAGE_PORT` | `8686` | Listen port |
| `VANTAGE_HOST` | `127.0.0.1` | Bind address (`0.0.0.0` in containers) |
| `VANTAGE_PUBLIC_URL` | `http://localhost:<port>` | Public origin, used in OAuth redirect URIs |
| `VANTAGE_DATA_DIR` | `./data` | SQLite DB + generated master key |
| `VANTAGE_MASTER_KEY` | — | 32-byte vault key (64 hex chars or base64); wins over the key file |
| `VANTAGE_MASTER_KEY_FILE` | — | Path to a file holding the key |
| `VANTAGE_ALLOWED_INSTANCES` | unset (open) | Comma-separated allow-list of instance domains. **Recommended**: it also protects shared OSINT quotas |
| `VANTAGE_SESSION_TTL_HOURS` | `72` | Session lifetime |
| `VANTAGE_COOKIE_SECURE` | from public URL | `1` forces the `Secure` cookie flag |
| `VANTAGE_TRUST_PROXY` | `0` | `1` = behind a reverse proxy; rate limiting keys on `X-Forwarded-For` |
| `VANTAGE_DEV_ALLOW_HTTP` | `0` | Dev only: allow plain-http `localhost` instances |

## Security model (short version)

- **Same-origin only**: the browser talks exclusively to this server.
  There is no CORS proxy and no secret ever lands in localStorage.
- **Vault**: instance tokens and OAuth client secrets are AES-256-GCM
  encrypted at rest, keyed by `master.key`, with key ids for rotation.
- **Sessions**: HttpOnly + SameSite=Lax cookies; the DB stores only a
  hash of the session token; state-changing routes require the
  `X-Vantage-CSRF` header (value from `GET /auth/me`).
- **Role gating**: after login the server probes the account
  (Mastodon `verify_credentials` role bitmask + an admin-read probe;
  Misskey `i`). No moderation capability ⇒ session destroyed and the
  token revoked (Mastodon) or discarded with revocation instructions
  (Misskey has no revoke endpoint).
- **SSRF guard**: every outbound fetch is HTTPS-only, resolves DNS first,
  refuses private/link-local/reserved ranges, pins the vetted address,
  caps redirects, and enforces timeouts and body-size limits.
- **Audit log**: logins, rejected logins, and logouts are recorded with
  secret-shaped fields redacted.
- **Honest threat model**: a compromised server exposes vaulted secrets.
  Mitigations are minimal scopes, the audit log, and documented
  revocation paths — not magic.

## Endpoints (phase 1)

| Route | Purpose |
|---|---|
| `GET /` | The Vantage UI |
| `GET /healthz` | Liveness probe |
| `GET /auth/login?host=…` | Start login with an instance |
| `GET /auth/callback/oauth` | Mastodon-family OAuth callback |
| `GET /auth/callback/miauth` | Misskey/Sharkey MiAuth callback |
| `GET /auth/me` | Identity, capability map, CSRF token |
| `POST /auth/logout` | End session (needs `X-Vantage-CSRF`) |

## Reverse proxy

Terminate TLS in front (nginx/caddy/YunoHost), proxy to
`127.0.0.1:8686`, set `VANTAGE_PUBLIC_URL=https://vantage.example` and
`VANTAGE_TRUST_PROXY=1`, and make sure `X-Forwarded-For` is appended by
your proxy.

## Development

```bash
VANTAGE_DEV_ALLOW_HTTP=1 npm start   # allows http://localhost:* instances
npm run test:server                  # server unit + flow tests
npm test                             # contract tests + server tests
```

After `npm run build`, restart the server to pick up the new UI (it is
read once at startup).
