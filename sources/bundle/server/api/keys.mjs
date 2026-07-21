/* ============================================================
   Vantage server — OSINT key custody (hosted-design §5, §10 phase 3
   and phase 5 D3c, pulled forward)
   /api/osint/keys manages the vaulted API keys the gateway
   injects. Keys are WRITE-ONLY through this API (§5.2): entered
   once, sealed with the vault, and only the last 4 characters
   ever come back — delete/replace, never read. Scopes:
     • user       — BYO key, visible to and usable by its owner only
     • instance   — shared by an admin with everyone whose login
                    instance matches; usable but not readable
     • deployment — shared by the Vantage Global Admin (admin.mjs)
                    with every moderator on this deployment, of any
                    instance. The OSINT gateway (osint.mjs) already
                    resolves this scope (own → instance → deployment);
                    this module is what lets a Global Admin write one.
   ============================================================ */
import { SERVICES } from "./osint.mjs";
import { isDeploymentAdmin } from "../admin.mjs";

const PREFIX = "/api/osint/keys";

/* Printable ASCII, no spaces — matches every real key format these services
   issue, and refuses pasted junk (newlines, "Bearer " prefixes, emoji). */
const KEY_RE = /^[\x21-\x7e]{4,512}$/;

function sendJson(res, status, body) {
  const buf = Buffer.from(JSON.stringify(body));
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Content-Length": buf.length });
  res.end(buf);
}

function readJson(req, maxBytes = 16 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > maxBytes) { req.destroy(); return reject(new Error("request body too large")); }
      chunks.push(c);
    });
    req.on("end", () => {
      if (!chunks.length) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8"))); }
      catch { reject(new Error("request body must be JSON")); }
    });
    req.on("error", reject);
  });
}

const today = () => new Date().toISOString().slice(0, 10);

export function makeKeyRoutes({ db, vault, sessions, audit, config }) {
  const listStmt = db.prepare(`
    SELECT k.id, k.service, k.scope, k.last4, k.created_at, k.owner_user_id, k.instance_host, u.acct AS owner_acct
      FROM user_keys k JOIN users u ON u.id = k.owner_user_id
     WHERE (k.scope = 'user' AND k.owner_user_id IN (SELECT id FROM users WHERE principal_id = ?))
        OR (k.scope = 'instance' AND k.instance_host IN (SELECT instance_host FROM users WHERE principal_id = ?))
        OR k.scope = 'deployment'
     ORDER BY k.service, k.scope, k.instance_host`);
  const myUserOn = db.prepare("SELECT id, capabilities FROM users WHERE principal_id = ? AND instance_host = ?");
  const myUse = db.prepare("SELECT count FROM key_usage WHERE key_id = ? AND user_id = ? AND day = ?");
  const allUse = db.prepare("SELECT COALESCE(SUM(count), 0) AS c FROM key_usage WHERE key_id = ? AND day = ?");
  const idsUser = db.prepare("SELECT id FROM user_keys WHERE service = ? AND scope = 'user' AND owner_user_id IN (SELECT id FROM users WHERE principal_id = ?)");
  const idsInstance = db.prepare("SELECT id FROM user_keys WHERE service = ? AND scope = 'instance' AND instance_host = ?");
  const idsDeployment = db.prepare("SELECT id FROM user_keys WHERE service = ? AND scope = 'deployment'");
  const dropUsage = db.prepare("DELETE FROM key_usage WHERE key_id = ?");
  const dropKey = db.prepare("DELETE FROM user_keys WHERE id = ?");
  const insert = db.prepare(`
    INSERT INTO user_keys (service, scope, owner_user_id, instance_host, ciphertext, key_id, last4)
    VALUES (?, ?, ?, ?, ?, ?, ?)`);

  /* Usage rows FK-reference the key (no cascade), so they go first. A replaced
     key is a new key — its counter starts fresh by design. Own keys are
     per-person (swept across all the principal's connections); instance keys
     are per-host; deployment keys are one-per-service, deployment-wide.
     Returns rows removed. */
  function removeKeys(service, scope, session, host) {
    const rows = scope === "user" ? idsUser.all(service, session.principalId)
      : scope === "instance" ? idsInstance.all(service, host)
      : idsDeployment.all(service);
    for (const row of rows) { dropUsage.run(row.id); dropKey.run(row.id); }
    return rows.length;
  }

  /* Sharing/unsharing on host H needs the admin capability of the principal's
     OWN connection on H — not whichever account they signed in with. */
  function adminConnectionOn(session, host) {
    const row = myUserOn.get(session.principalId, host);
    if (!row) return { error: `no connected account on ${host} — add it in Connections` };
    let caps = {};
    try { caps = JSON.parse(row.capabilities); } catch { /* treated as no capabilities */ }
    if (!caps.admin) return { error: `managing the ${host} shared key requires the admin role there` };
    return { userId: row.id };
  }

  /* GET /api/osint/keys — what the principal can see: their own keys (last4),
     the shared keys of every instance they're connected to, and the
     deployment-wide key if a Global Admin has shared one. Real key material
     never leaves. */
  function list(res, session) {
    const services = {};
    for (const row of listStmt.all(session.principalId, session.principalId)) {
      const entry = services[row.service] || (services[row.service] = { user: null, instances: [], deployment: null });
      if (row.scope === "user") {
        const usedToday = (myUse.get(row.id, row.owner_user_id, today()) || { count: 0 }).count;
        entry.user = { last4: row.last4, createdAt: row.created_at, usedToday };
      } else if (row.scope === "instance") {
        const mine = myUserOn.get(session.principalId, row.instance_host);
        entry.instances.push({
          host: row.instance_host,
          last4: row.last4,
          sharedBy: row.owner_acct,
          own: row.owner_user_id === (mine && mine.id),
          usedToday: mine ? (myUse.get(row.id, mine.id, today()) || { count: 0 }).count : 0,
          usedTodayAll: allUse.get(row.id, today()).c,
        });
      } else if (row.scope === "deployment") {
        const usedToday = (myUse.get(row.id, session.userId, today()) || { count: 0 }).count;
        entry.deployment = {
          last4: row.last4,
          sharedBy: row.owner_acct,
          usedToday,
          usedTodayAll: allUse.get(row.id, today()).c,
        };
      }
    }
    sendJson(res, 200, { services, sharedCap: config.sharedKeyDailyCap });
  }

  /* PUT /api/osint/keys/<service> {key, scope?, host?} — add or replace.
     scope "instance" shares with every moderator of `host` (default: the
     login instance) and requires the admin capability ON that instance at
     the time of sharing (§5.1 D3b). scope "deployment" shares with every
     moderator on the deployment and requires the Global Admin role
     (admin.mjs) — manage it from the Global Admin panel, not Services. */
  async function put(req, res, session, service) {
    let body;
    try { body = await readJson(req); }
    catch (e) { return sendJson(res, 400, { error: e.message }); }
    const key = String(body.key || "").trim();
    if (!KEY_RE.test(key)) return sendJson(res, 400, { error: "key must be 4–512 printable characters with no spaces" });
    const scope = body.scope || "user";
    if (scope !== "user" && scope !== "instance" && scope !== "deployment") return sendJson(res, 400, { error: "scope must be 'user', 'instance', or 'deployment'" });

    let ownerUserId = session.userId;
    let host = session.instanceHost;
    if (scope === "instance") {
      host = String(body.host || session.instanceHost).trim().toLowerCase();
      const admin = adminConnectionOn(session, host);
      if (admin.error) return sendJson(res, 403, { error: admin.error });
      ownerUserId = admin.userId;
    } else if (scope === "deployment") {
      if (!isDeploymentAdmin(db, session.acct)) return sendJson(res, 403, { error: "sharing a deployment-wide key requires the Global Admin role" });
      host = null;
    }

    db.exec("BEGIN");
    try {
      removeKeys(service, scope, session, host);
      insert.run(service, scope, ownerUserId, host, vault.seal(key), vault.keyId, key.slice(-4));
      db.exec("COMMIT");
    } catch (e) {
      db.exec("ROLLBACK");
      throw e;
    }
    audit.log(scope === "user" ? "key_add" : "key_share", { userId: session.userId, service, scope, host: scope === "instance" ? host : undefined });
    sendJson(res, 200, { service, scope, host: scope === "instance" ? host : undefined, last4: key.slice(-4) });
  }

  /* DELETE /api/osint/keys/<service>?scope=user|instance|deployment[&host=…]
     — removing an instance-shared key is any-admin-of-that-instance, not
     owner-only: whoever holds the admin role there can revoke what's shared
     with it. Removing a deployment key requires the Global Admin role. */
  function del(res, session, service, scope, hostParam) {
    if (scope !== "user" && scope !== "instance" && scope !== "deployment") return sendJson(res, 400, { error: "scope must be 'user', 'instance', or 'deployment'" });
    let host = session.instanceHost;
    if (scope === "instance") {
      host = String(hostParam || session.instanceHost).trim().toLowerCase();
      const admin = adminConnectionOn(session, host);
      if (admin.error) return sendJson(res, 403, { error: admin.error });
    } else if (scope === "deployment") {
      if (!isDeploymentAdmin(db, session.acct)) return sendJson(res, 403, { error: "removing the deployment-wide key requires the Global Admin role" });
      host = null;
    }
    let removed;
    db.exec("BEGIN");
    try {
      removed = removeKeys(service, scope, session, host);
      db.exec("COMMIT");
    } catch (e) {
      db.exec("ROLLBACK");
      throw e;
    }
    if (!removed) return sendJson(res, 404, { error: "no such key" });
    audit.log("key_delete", { userId: session.userId, service, scope, host: scope === "instance" ? host : undefined });
    sendJson(res, 200, { ok: true });
  }

  async function handle(req, res, url) {
    const session = sessions.load(req);
    if (!session) return sendJson(res, 401, { error: "not logged in" });

    const method = (req.method || "GET").toUpperCase();
    if (method !== "GET" && !sessions.checkCsrf(req, session)) {
      return sendJson(res, 403, { error: "missing or bad X-Vantage-CSRF header" });
    }

    const rest = url.pathname.slice(PREFIX.length).split("/").filter(Boolean);
    if (rest.length === 0) {
      if (method === "GET") return list(res, session);
      return sendJson(res, 405, { error: "method not allowed" });
    }
    if (rest.length === 1) {
      const service = rest[0];
      if (!SERVICES[service]) return sendJson(res, 404, { error: "unknown service" });
      if (method === "PUT") return put(req, res, session, service);
      if (method === "DELETE") return del(res, session, service, url.searchParams.get("scope") || "user", url.searchParams.get("host"));
      return sendJson(res, 405, { error: "method not allowed" });
    }
    return sendJson(res, 404, { error: "not found" });
  }

  return { handle };
}
