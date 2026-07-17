/* ============================================================
   Vantage server — instance gateway (hosted-design §6, §10 phase 2 + 2.5)
   /api/instance/<upstream-path> forwards a moderation call to one of
   the session principal's CONNECTED instances, attaching that
   connection's vaulted token server-side — the browser never holds
   it. The X-Vantage-Instance header picks which connection acts
   (default: the one signed in with); only hosts actually linked to
   the principal resolve. Mirrors api.js rawHttp: Mastodon family
   gets a Bearer header; Misskey family gets the token injected as
   `i` in the JSON body.
   ============================================================ */
import { originOf } from "../auth/routes.mjs";

const MAX_BODY_BYTES = 1 * 1024 * 1024;
const PREFIX = "/api/instance";

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > MAX_BODY_BYTES) { req.destroy(); return reject(new Error("request body too large")); }
      chunks.push(c);
    });
    req.on("end", () => resolve(chunks.length ? Buffer.concat(chunks) : null));
    req.on("error", reject);
  });
}

function sendJson(res, status, body) {
  const buf = Buffer.isBuffer(body) ? body : Buffer.from(JSON.stringify(body));
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Content-Length": buf.length });
  res.end(buf);
}

export function makeInstanceGateway({ db, vault, sessions, fetchFn, config }) {
  const connOf = db.prepare(
    `SELECT u.id, u.instance_host, i.family FROM users u
       JOIN instances i ON i.host = u.instance_host
      WHERE u.principal_id = ? AND u.instance_host = ?`);
  const tokenOf = db.prepare("SELECT ciphertext FROM tokens WHERE user_id = ?");

  async function handle(req, res, url, clientIp) {
    const session = sessions.load(req);
    if (!session) return sendJson(res, 401, { error: "not logged in" });

    const method = (req.method || "GET").toUpperCase();
    // CSRF on every state-changing call (§6). GET/HEAD are safe reads.
    if (method !== "GET" && method !== "HEAD" && !sessions.checkCsrf(req, session)) {
      return sendJson(res, 403, { error: "missing or bad X-Vantage-CSRF header" });
    }

    let upstreamPath = url.pathname.slice(PREFIX.length) + url.search;
    if (!upstreamPath.startsWith("/")) upstreamPath = "/" + upstreamPath;

    // Act-as selector (phase 2.5): the UI names the connection's host; only
    // instances actually linked to this principal resolve.
    const actHost = String(req.headers["x-vantage-instance"] || "").trim().toLowerCase() || session.instanceHost;
    const conn = connOf.get(session.principalId, actHost);
    if (!conn) return sendJson(res, 403, { error: `no connected account on ${actHost} — add it in Connections` });

    const row = tokenOf.get(conn.id);
    if (!row) return sendJson(res, 401, { error: `no vaulted token for ${actHost} — sign in with it again` });
    let token;
    try { token = vault.open(row.ciphertext); }
    catch { return sendJson(res, 500, { error: "token could not be unsealed" }); }

    const origin = originOf(conn.instance_host, config.devAllowHttp);
    const headers = { "Content-Type": "application/json" };
    let body = null;

    if (conn.family === "mastodon") {
      headers["Authorization"] = "Bearer " + token;
      if (method !== "GET" && method !== "HEAD") body = await readBody(req);
    } else {
      // Misskey/Sharkey: POST + token in body as `i`. Merge it into whatever
      // the browser sent (which carries no token) so the vaulted one is used.
      const raw = await readBody(req);
      let payload = {};
      if (raw) {
        try { payload = JSON.parse(raw.toString("utf8")); }
        catch { return sendJson(res, 400, { error: "request body must be JSON" }); }
      }
      payload.i = token;
      body = Buffer.from(JSON.stringify(payload));
    }

    let upstream;
    try {
      upstream = await fetchFn(origin + upstreamPath, { method, headers, body, devAllowHttp: config.devAllowHttp, allowPrivateHosts: config.allowedInstances });
    } catch (e) {
      // 500, not 502: Cloudflare swaps origin 502/504 bodies for its own error
      // page, which would hand api.js HTML instead of this JSON.
      return sendJson(res, 500, { error: `couldn't reach ${conn.instance_host}: ${e.message}` });
    }

    // Relay status + body verbatim; the UI's api.js parses the instance's own
    // JSON (and its {error:{message}} shape) exactly as it did over direct fetch.
    const text = upstream.text();
    const type = upstream.headers["content-type"] || "application/json; charset=utf-8";
    res.writeHead(upstream.status, { "Content-Type": type, "Content-Length": Buffer.byteLength(text) });
    res.end(text);
  }

  return { handle };
}
