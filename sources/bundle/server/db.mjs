/* ============================================================
   Vantage server — SQLite schema + migrations (hosted-design §8)
   node:sqlite, WAL mode. Workspace-shaped from day one (D5):
   team data will hang off instance_host, not the user. Migrations
   are append-only; schema_meta.version records the last applied.
   ============================================================ */
import { DatabaseSync } from "node:sqlite";

const MIGRATIONS = [
  /* v1 — phase 1: identity, sessions, vaulted tokens, audit. */
  `
  CREATE TABLE instances (
    host          TEXT PRIMARY KEY,           -- lowercase domain
    software      TEXT NOT NULL,              -- raw nodeinfo software name
    family        TEXT NOT NULL,              -- 'mastodon' | 'misskey' admin dialect
    version       TEXT NOT NULL DEFAULT '',
    oauth_client_id     TEXT,                 -- Mastodon family: dynamic app registration cache
    oauth_client_secret TEXT,                 -- sealed with the vault
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
  );
  CREATE TABLE users (
    id                INTEGER PRIMARY KEY,
    instance_host     TEXT NOT NULL REFERENCES instances(host),
    remote_account_id TEXT NOT NULL,          -- id on their instance
    acct              TEXT NOT NULL,          -- user@host
    display           TEXT NOT NULL DEFAULT '',
    capabilities      TEXT NOT NULL DEFAULT '{}',  -- JSON capability map (§4.3)
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    last_login_at     TEXT,
    UNIQUE (instance_host, remote_account_id)
  );
  CREATE TABLE tokens (
    id         INTEGER PRIMARY KEY,
    user_id    INTEGER NOT NULL UNIQUE REFERENCES users(id),
    ciphertext TEXT NOT NULL,                 -- vault-sealed access token
    key_id     TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
  );
  CREATE TABLE user_keys (                    -- OSINT keys (§5); wired up in phase 3
    id            INTEGER PRIMARY KEY,
    service       TEXT NOT NULL,
    scope         TEXT NOT NULL CHECK (scope IN ('user','instance','deployment')),
    owner_user_id INTEGER NOT NULL REFERENCES users(id),
    instance_host TEXT REFERENCES instances(host),
    ciphertext    TEXT NOT NULL,
    key_id        TEXT NOT NULL,
    last4         TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
  );
  CREATE TABLE key_usage (
    key_id  INTEGER NOT NULL REFERENCES user_keys(id),
    user_id INTEGER NOT NULL REFERENCES users(id),
    day     TEXT NOT NULL,                    -- YYYY-MM-DD
    count   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (key_id, user_id, day)
  );
  CREATE TABLE sessions (
    id         TEXT PRIMARY KEY,              -- sha256 of the cookie token: a DB leak can't hijack sessions
    user_id    INTEGER NOT NULL REFERENCES users(id),
    csrf       TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    expires_at TEXT NOT NULL
  );
  CREATE TABLE auth_pending (                 -- in-flight logins (OAuth state / MiAuth session)
    state         TEXT PRIMARY KEY,
    host          TEXT NOT NULL,
    family        TEXT NOT NULL,
    secret        TEXT NOT NULL,              -- PKCE verifier (mastodon) or MiAuth session uuid (misskey)
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    expires_at    TEXT NOT NULL
  );
  CREATE TABLE audit_log (
    id      INTEGER PRIMARY KEY,
    at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    user_id INTEGER,                          -- NULL for pre-auth events (rejected logins)
    action  TEXT NOT NULL,
    detail  TEXT NOT NULL DEFAULT '{}'        -- JSON, redacted before insert
  );
  CREATE TABLE settings (
    k TEXT PRIMARY KEY,
    v TEXT NOT NULL
  );
  `,

  /* v2 — phase 2.5: one person (principal), many instances, ONE account per
     instance. Every existing user becomes their own principal. Sessions are
     rebuilt to hang off the principal while remembering which connection the
     person signed in with (dropping the table logs everyone out on upgrade —
     sessions are ephemeral by design). */
  `
  CREATE TABLE principals (
    id         INTEGER PRIMARY KEY,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
  );
  ALTER TABLE users ADD COLUMN principal_id INTEGER REFERENCES principals(id);
  INSERT INTO principals (id, created_at) SELECT id, created_at FROM users;
  UPDATE users SET principal_id = id;
  CREATE UNIQUE INDEX users_one_account_per_instance ON users (principal_id, instance_host);
  DROP TABLE sessions;
  CREATE TABLE sessions (
    id           TEXT PRIMARY KEY,              -- sha256 of the cookie token
    principal_id INTEGER NOT NULL REFERENCES principals(id),
    user_id      INTEGER NOT NULL REFERENCES users(id),  -- the connection signed in with
    csrf         TEXT NOT NULL,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    expires_at   TEXT NOT NULL
  );
  ALTER TABLE auth_pending ADD COLUMN link_principal INTEGER;  -- set = "add another server" for this principal
  `,
];

export function openDb(path) {
  const db = new DatabaseSync(path);
  db.exec("PRAGMA journal_mode = WAL");
  db.exec("PRAGMA foreign_keys = ON");
  db.exec("CREATE TABLE IF NOT EXISTS schema_meta (version INTEGER NOT NULL)");
  let row = db.prepare("SELECT version FROM schema_meta").get();
  if (!row) {
    db.prepare("INSERT INTO schema_meta (version) VALUES (0)").run();
    row = { version: 0 };
  }
  for (let v = row.version; v < MIGRATIONS.length; v++) {
    db.exec("BEGIN");
    try {
      db.exec(MIGRATIONS[v]);
      db.prepare("UPDATE schema_meta SET version = ?").run(v + 1);
      db.exec("COMMIT");
    } catch (e) {
      db.exec("ROLLBACK");
      throw new Error(`migration to schema v${v + 1} failed: ${e.message}`);
    }
  }
  return db;
}

export const SCHEMA_VERSION = MIGRATIONS.length;
export { MIGRATIONS }; // exported for upgrade-path tests only — never mutate
