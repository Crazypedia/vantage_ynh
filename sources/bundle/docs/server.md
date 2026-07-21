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
| `VANTAGE_ALLOWED_INSTANCES` | unset (open) | Comma-separated allow-list of instance domains. **Recommended**: it also protects shared OSINT quotas. Locks the Global Admin panel's allow-list field read-only (env wins) — leave unset to manage the allow-list from the panel instead |
| `VANTAGE_SEED_ADMIN_HOST` | unset (bootstrap off) | The instance domain the first Global Admin must log in from. The first moderator who signs in from this host becomes the deployment admin — one-shot; once an admin exists, further admins are added from the Global Admin panel, not this variable |
| `VANTAGE_SESSION_TTL_HOURS` | `72` | Session lifetime |
| `VANTAGE_COOKIE_SECURE` | from public URL | `1` forces the `Secure` cookie flag |
| `VANTAGE_TRUST_PROXY` | `0` | `1` = behind a reverse proxy; rate limiting keys on `X-Forwarded-For` |
| `VANTAGE_SHARED_KEY_DAILY_CAP` | `200` | Per-user daily lookup cap on *instance-shared* OSINT keys (own keys are never capped). `0` disables |
| `VANTAGE_DEV_ALLOW_HTTP` | `0` | Dev only: allow plain-http `localhost` instances |

## Security model (short version)

- **Same-origin only**: the browser talks exclusively to this server.
  There is no CORS proxy and no secret ever lands in localStorage.
- **Vault**: instance tokens, OAuth client secrets, and OSINT API keys
  are AES-256-GCM encrypted at rest, keyed by `master.key`, with key ids
  for rotation. OSINT keys are write-only: entered once in Services, the
  API returns only the last 4 characters — delete/replace, never read.
- **OSINT gateway**: `/api/osint/<service>/<op>` is a *closed* op table
  (only the exact upstream calls the enrichment engine makes), not an
  open proxy. The key is resolved server-side — your own key first, then
  one an admin of your instance shared — and injected into the upstream
  call; per-key usage is tracked, and shared keys carry a per-user daily
  cap (`VANTAGE_SHARED_KEY_DAILY_CAP`).
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
- **Global Admin**: a deployment-level role, distinct from a moderator's role
  on their own fedi instance (`/auth/me`'s `isDeploymentAdmin`). Bootstrapped
  once via `VANTAGE_SEED_ADMIN_HOST` (see above), then self-managed from the
  Global Admin panel: the instance allow-list (when not locked by
  `VANTAGE_ALLOWED_INSTANCES`), the approved-admin list, and a deployment-wide
  OSINT key shared with every moderator regardless of instance. Every
  `/api/admin/*` route re-checks the role server-side.
- **Honest threat model**: a compromised server exposes vaulted secrets.
  Mitigations are minimal scopes, the audit log, and documented
  revocation paths — not magic.

## Endpoints

| Route | Purpose |
|---|---|
| `GET /` | The Vantage UI |
| `GET /healthz` | Liveness probe |
| `GET /auth/login?host=…` | Start login with an instance |
| `GET /auth/callback/oauth` | Mastodon-family OAuth callback |
| `GET /auth/callback/miauth` | Misskey/Sharkey MiAuth callback |
| `GET /auth/me` | Identity, capability map, CSRF token |
| `POST /auth/logout` | End session (needs `X-Vantage-CSRF`) |
| `POST /auth/unlink` | Detach a linked instance account (`{host}`; not the one signed in with) |
| `ANY /api/instance/<path>` | Moderation gateway to a connected instance; `X-Vantage-Instance: <host>` picks which (default: the sign-in instance) |
| `GET /api/osint/keys` | Vaulted OSINT keys visible to this session (last4 + usage only) |
| `PUT /api/osint/keys/<service>` | Add/replace a key (`{key, scope, host}`; `scope:"instance"` shares with `host`, needs admin there; `scope:"deployment"` shares with everyone, needs the Global Admin role) |
| `DELETE /api/osint/keys/<service>?scope=…&host=…` | Remove a key (instance scope: admin on that host; deployment scope: Global Admin) |
| `GET/POST /api/osint/<service>/<op>` | Keyed OSINT lookup with the vaulted key injected server-side |
| `GET /api/admin/status` | Global Admin only: allow-list (+ whether it's env-locked), approved admins, seed-host state |
| `PUT /api/admin/allowed-instances` | Global Admin only: set the runtime allow-list (`{instances: [...] \| null}`); 423 if env-locked |
| `POST /api/admin/admins` | Global Admin only: pre-approve another admin (`{acct}`) |
| `DELETE /api/admin/admins/<acct>` | Global Admin only: revoke an admin (refuses to remove the last one) |

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
