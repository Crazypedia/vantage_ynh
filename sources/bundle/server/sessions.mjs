/* ============================================================
   Vantage server — sessions (hosted-design §3, §6)
   HttpOnly + SameSite cookies backed by a server-side SQLite
   store. The cookie carries a random 256-bit token; the DB keeps
   only its SHA-256, so a database leak cannot mint live sessions.
   Every session gets a CSRF token that state-changing routes
   require via the X-Vantage-CSRF header.
   ============================================================ */
import { randomBytes, createHash, timingSafeEqual } from "node:crypto";

export const COOKIE_NAME = "vantage_sid";

const hash = (token) => createHash("sha256").update(token).digest("hex");

export function makeSessions(db, { ttlHours, cookieSecure }) {
  const insert = db.prepare("INSERT INTO sessions (id, user_id, csrf, expires_at) VALUES (?, ?, ?, ?)");
  const select = db.prepare(
    `SELECT s.id, s.user_id, s.csrf, s.expires_at, u.instance_host, u.acct, u.display, u.capabilities
       FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.id = ? AND s.expires_at > strftime('%Y-%m-%dT%H:%M:%fZ','now')`
  );
  const remove = db.prepare("DELETE FROM sessions WHERE id = ?");
  const sweep = db.prepare("DELETE FROM sessions WHERE expires_at <= strftime('%Y-%m-%dT%H:%M:%fZ','now')");

  function create(userId) {
    const token = randomBytes(32).toString("base64url");
    const csrf = randomBytes(32).toString("base64url");
    const expiresAt = new Date(Date.now() + ttlHours * 3_600_000).toISOString();
    insert.run(hash(token), userId, csrf, expiresAt);
    return { token, csrf, expiresAt };
  }

  function load(req) {
    const token = parseCookies(req.headers.cookie)[COOKIE_NAME];
    if (!token) return null;
    const row = select.get(hash(token));
    if (!row) return null;
    return {
      id: row.id,
      userId: row.user_id,
      csrf: row.csrf,
      instanceHost: row.instance_host,
      acct: row.acct,
      display: row.display,
      capabilities: JSON.parse(row.capabilities),
    };
  }

  function checkCsrf(req, session) {
    const sent = req.headers["x-vantage-csrf"];
    if (typeof sent !== "string" || sent.length !== session.csrf.length) return false;
    return timingSafeEqual(Buffer.from(sent), Buffer.from(session.csrf));
  }

  const destroy = (session) => { remove.run(session.id); };
  const sweepExpired = () => { sweep.run(); };

  function cookie(token, { clear = false } = {}) {
    const parts = [
      `${COOKIE_NAME}=${clear ? "" : token}`,
      "Path=/",
      "HttpOnly",
      "SameSite=Lax",
      clear ? "Max-Age=0" : `Max-Age=${Math.floor(ttlHours * 3600)}`,
    ];
    if (cookieSecure) parts.push("Secure");
    return parts.join("; ");
  }

  return { create, load, destroy, checkCsrf, cookie, sweepExpired };
}

export function parseCookies(header) {
  const out = {};
  if (!header) return out;
  for (const pair of String(header).split(";")) {
    const eq = pair.indexOf("=");
    if (eq === -1) continue;
    out[pair.slice(0, eq).trim()] = pair.slice(eq + 1).trim();
  }
  return out;
}
