/* ============================================================
   Vantage server — /auth/* routes (hosted-design §4, §6)
   Login = "sign in with your instance". One entry point picks
   the flow by nodeinfo family; both callbacks converge on
   finishLogin: allow-list recheck → role probe → capability map
   → reject non-mods (revoke where supported) or vault the token
   and open a session.
   ============================================================ */
import { randomBytes } from "node:crypto";
import * as mastodon from "./mastodon.mjs";
import * as misskey from "./misskey.mjs";
import { fromMastodon, fromMisskey, isModerator } from "../capabilities.mjs";
import { detect } from "../nodeinfo.mjs";

const PENDING_TTL_MS = 10 * 60 * 1000;
const MAX_BODY_BYTES = 16 * 1024;

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > MAX_BODY_BYTES) { req.destroy(); return reject(new Error("request body too large")); }
      chunks.push(c);
    });
    req.on("end", () => resolve(chunks.length ? Buffer.concat(chunks).toString("utf8") : null));
    req.on("error", reject);
  });
}

/* "example.tld", "https://example.tld/about", "@me@example.tld" → host.
   The port survives (u.host, not u.hostname) so a dev instance on
   localhost:3000 is addressable; real instances never carry one. */
export function normalizeHost(input) {
  let s = String(input || "").trim().toLowerCase();
  if (!s) return null;
  if (s.includes("@")) s = s.slice(s.lastIndexOf("@") + 1);
  if (!/^[a-z]+:\/\//.test(s)) s = `https://${s}`;
  try {
    const u = new URL(s);
    return u.host || null; // punycoded, no path
  } catch { return null; }
}

/* Instances are HTTPS; the dev escape hatch (config.devAllowHttp) admits
   plain-http localhost so the full flow can run against a local fake. */
export function originOf(host, devAllowHttp) {
  const localhost = /^(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/.test(host);
  return devAllowHttp && localhost ? `http://${host}` : `https://${host}`;
}

export function hostAllowed(allowedInstances, host) {
  if (!allowedInstances) return true; // unset ⇒ open (§4.2, docs recommend enabling)
  return allowedInstances.includes(host);
}

export function makeAuthRoutes(ctx) {
  const { db, vault, sessions, audit, config, fetchFn, loginLimiter } = ctx;
  // allow-listed instances may share this box (YunoHost pins own domains to 127.0.0.1 in /etc/hosts)
  const fetchOpts = { devAllowHttp: config.devAllowHttp, allowPrivateHosts: config.allowedInstances };

  const pendingInsert = db.prepare("INSERT INTO auth_pending (state, host, family, secret, link_principal, expires_at) VALUES (?, ?, ?, ?, ?, ?)");
  const pendingTake = db.prepare("SELECT state, host, family, secret, link_principal FROM auth_pending WHERE state = ? AND expires_at > strftime('%Y-%m-%dT%H:%M:%fZ','now')");
  const pendingDelete = db.prepare("DELETE FROM auth_pending WHERE state = ?");
  const pendingSweep = db.prepare("DELETE FROM auth_pending WHERE expires_at <= strftime('%Y-%m-%dT%H:%M:%fZ','now')");

  function createPending(host, family, secret, linkPrincipal = null) {
    pendingSweep.run();
    const state = randomBytes(32).toString("base64url");
    pendingInsert.run(state, host, family, secret, linkPrincipal, new Date(Date.now() + PENDING_TTL_MS).toISOString());
    return state;
  }

  /* Single-use: a state is deleted the moment it's looked up, so a
     replayed callback (or a code-swap retry) finds nothing. */
  function takePending(state) {
    if (!state) return null;
    const row = pendingTake.get(state);
    pendingDelete.run(state);
    return row || null;
  }

  function upsertInstance(host, info) {
    db.prepare(
      `INSERT INTO instances (host, software, family, version) VALUES (?, ?, ?, ?)
       ON CONFLICT(host) DO UPDATE SET software = excluded.software, family = excluded.family, version = excluded.version`
    ).run(host, info.raw, info.family, info.version);
  }

  const userByAccount = db.prepare("SELECT id, principal_id FROM users WHERE instance_host = ? AND remote_account_id = ?");
  const userOnHost = db.prepare("SELECT id, remote_account_id FROM users WHERE principal_id = ? AND instance_host = ?");
  const connectionsOf = db.prepare(
    `SELECT u.id, u.instance_host, u.acct, u.display, u.capabilities, i.family, i.software
       FROM users u JOIN instances i ON i.host = u.instance_host
      WHERE u.principal_id = ? ORDER BY u.id`);

  function upsertUser(principalId, host, remoteId, acct, display, caps) {
    db.prepare(
      `INSERT INTO users (principal_id, instance_host, remote_account_id, acct, display, capabilities, last_login_at)
       VALUES (?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
       ON CONFLICT(instance_host, remote_account_id) DO UPDATE SET
         acct = excluded.acct, display = excluded.display, capabilities = excluded.capabilities,
         last_login_at = excluded.last_login_at`
    ).run(principalId, host, remoteId, acct, display, JSON.stringify(caps));
    return userByAccount.get(host, remoteId).id;
  }

  /* One account per instance per person (phase 2.5): linking a different
     account on an already-connected host REPLACES that connection in place —
     the row keeps its id (keys/usage/audit stay attached), gets the new
     account's identity, and the fresh token is vaulted over the old one. */
  function replaceConnection(userId, remoteId, acct, display, caps) {
    db.prepare(
      `UPDATE users SET remote_account_id = ?, acct = ?, display = ?, capabilities = ?,
         last_login_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?`
    ).run(remoteId, acct, display, JSON.stringify(caps), userId);
    return userId;
  }

  function vaultToken(userId, token) {
    db.prepare(
      `INSERT INTO tokens (user_id, ciphertext, key_id) VALUES (?, ?, ?)
       ON CONFLICT(user_id) DO UPDATE SET ciphertext = excluded.ciphertext, key_id = excluded.key_id,
         created_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')`
    ).run(userId, vault.seal(token), vault.keyId);
  }

  function openSession(res, principalId, userId) {
    const { token } = sessions.create(principalId, userId);
    res.writeHead(303, { "Set-Cookie": sessions.cookie(token), Location: "/" });
    res.end();
  }

  /* GET /auth/login?host=example.tld[&link=1]
     link=1 + a live session = "add another server": the callback attaches the
     new instance account to the signed-in principal instead of opening a new
     session. Without a live session, link is ignored (normal login). */
  async function login(req, res, url, clientIp) {
    if (!loginLimiter.allow(clientIp)) return failPage(res, 429, "Too many login attempts — try again in a few minutes.");
    const host = normalizeHost(url.searchParams.get("host"));
    if (!host) return failPage(res, 400, "That doesn't look like an instance domain.");
    if (!hostAllowed(config.allowedInstances, host)) {
      audit.log("login_rejected_allowlist", { host, ip: clientIp });
      return failPage(res, 403, `Logins from ${host} aren't accepted on this Vantage deployment.`);
    }
    let linkPrincipal = null;
    if (url.searchParams.get("link") === "1") {
      const session = sessions.load(req);
      if (!session) return failPage(res, 401, "Your session expired — sign in first, then add the server.");
      linkPrincipal = session.principalId;
    }
    const origin = originOf(host, config.devAllowHttp);
    let info;
    try { info = await detect(origin, fetchFn, fetchOpts); }
    catch (e) {
      audit.log("login_failed_detect", { host, ip: clientIp, error: e.message });
      // 500, not 502: Cloudflare replaces origin 502/504 bodies with its own
      // branded error page, which hides this message from the person logging in.
      return failPage(res, 500, e.message);
    }
    upsertInstance(host, info);

    if (info.family === "mastodon") {
      let app;
      try { app = await mastodon.ensureApp({ db, vault, fetchFn, fetchOpts, publicUrl: config.publicUrl, host, origin }); }
      catch (e) { return failPage(res, 500, e.message); } // 500 not 502 — see detect() above
      const { verifier, challenge } = mastodon.pkcePair();
      const state = createPending(host, "mastodon", verifier, linkPrincipal);
      res.writeHead(302, { Location: mastodon.authorizeUrl({ origin, clientId: app.clientId, publicUrl: config.publicUrl, state, challenge }) });
      return res.end();
    }
    // misskey family
    const state = createPending(host, "misskey", "", linkPrincipal); // uuid filled in below — createPending first so state exists for the callback URL
    const { uuid, url: authUrl } = misskey.beginMiAuth({ origin, publicUrl: config.publicUrl, state });
    db.prepare("UPDATE auth_pending SET secret = ? WHERE state = ?").run(uuid, state);
    res.writeHead(302, { Location: authUrl });
    res.end();
  }

  /* GET /auth/callback/oauth?code=…&state=… */
  async function callbackOauth(req, res, url, clientIp) {
    const pending = takePending(url.searchParams.get("state"));
    const code = url.searchParams.get("code");
    if (!pending || pending.family !== "mastodon" || !code) return failPage(res, 400, "This login attempt has expired or was already used — start again.");
    const origin = originOf(pending.host, config.devAllowHttp);
    return finishLogin(res, clientIp, pending, async () => {
      const app = await mastodon.ensureApp({ db, vault, fetchFn, fetchOpts, publicUrl: config.publicUrl, host: pending.host, origin });
      const token = await mastodon.exchangeCode({ fetchFn, fetchOpts, host: pending.host, origin, clientId: app.clientId, clientSecret: app.clientSecret, publicUrl: config.publicUrl, code, verifier: pending.secret });
      const { me, adminProbeOk } = await mastodon.probeAccount({ fetchFn, fetchOpts, origin, token });
      return {
        token,
        caps: fromMastodon(me, adminProbeOk),
        identity: { remoteId: String(me.id), acct: `${me.username}@${pending.host}`, display: me.display_name || me.username || "" },
        revoke: () => mastodon.revokeToken({ fetchFn, fetchOpts, origin, clientId: app.clientId, clientSecret: app.clientSecret, token }),
      };
    });
  }

  /* GET /auth/callback/miauth?state=…&session=… */
  async function callbackMiauth(req, res, url, clientIp) {
    const pending = takePending(url.searchParams.get("state"));
    if (!pending || pending.family !== "misskey" || !pending.secret) return failPage(res, 400, "This login attempt has expired or was already used — start again.");
    const origin = originOf(pending.host, config.devAllowHttp);
    return finishLogin(res, clientIp, pending, async () => {
      const { token } = await misskey.checkMiAuth({ fetchFn, fetchOpts, host: pending.host, origin, uuid: pending.secret });
      const { me } = await misskey.probeAccount({ fetchFn, fetchOpts, origin, token });
      return {
        token,
        caps: fromMisskey(me),
        identity: { remoteId: String(me.id), acct: `${me.username}@${pending.host}`, display: me.name || me.username || "" },
        /* Misskey has no token-revocation endpoint (§11) — discard and instruct. */
        revoke: null,
      };
    });
  }

  async function finishLogin(res, clientIp, pending, flow) {
    if (!hostAllowed(config.allowedInstances, pending.host)) { // re-check at callback (§4.2) — the list may have changed mid-flight
      audit.log("login_rejected_allowlist", { host: pending.host, ip: clientIp, phase: "callback" });
      return failPage(res, 403, `Logins from ${pending.host} aren't accepted on this Vantage deployment.`);
    }
    let result;
    try { result = await flow(); }
    catch (e) {
      audit.log("login_failed", { host: pending.host, ip: clientIp, error: e.message });
      return failPage(res, 500, `Login with ${pending.host} failed: ${e.message}`); // 500 not 502 — see detect() above
    }
    if (!isModerator(result.caps)) {
      let revoked = false;
      if (result.revoke) { try { revoked = await result.revoke(); } catch { revoked = false; } }
      audit.log("login_rejected_role", { host: pending.host, acct: result.identity.acct, ip: clientIp, revoked });
      const cleanup = revoked
        ? "The access token was revoked."
        : `The token was discarded — also remove "Vantage" in your account's app/integration settings on ${pending.host}.`;
      return failPage(res, 403, `Your account on ${pending.host} doesn't have moderation permissions, so it can't use Vantage. ${cleanup}`);
    }
    const existing = userByAccount.get(pending.host, result.identity.remoteId);

    if (pending.link_principal != null) {
      // "Add another server" for a signed-in principal (phase 2.5).
      if (existing && existing.principal_id !== pending.link_principal) {
        audit.log("link_rejected_taken", { host: pending.host, acct: result.identity.acct, ip: clientIp });
        return failPage(res, 409, `@${result.identity.acct} is already connected to a different Vantage login. Sign in with that account directly, or unlink it there first.`);
      }
      const onHost = userOnHost.get(pending.link_principal, pending.host);
      let userId;
      if (onHost && (!existing || onHost.id !== existing.id)) {
        // one account per instance: a different account on this host is replaced in place
        userId = replaceConnection(onHost.id, result.identity.remoteId, result.identity.acct, result.identity.display, result.caps);
        audit.log("connection_replaced", { userId, host: pending.host, acct: result.identity.acct, ip: clientIp });
      } else {
        userId = upsertUser(pending.link_principal, pending.host, result.identity.remoteId, result.identity.acct, result.identity.display, result.caps);
        audit.log("connection_linked", { userId, host: pending.host, acct: result.identity.acct, ip: clientIp });
      }
      vaultToken(userId, result.token);
      // The person's existing session cookie stays valid — just go home.
      res.writeHead(303, { Location: "/" });
      return res.end();
    }

    // Normal login. A returning account rejoins its principal; a new account
    // becomes a new principal.
    const principalId = existing
      ? existing.principal_id
      : Number(db.prepare("INSERT INTO principals DEFAULT VALUES").run().lastInsertRowid);
    const userId = upsertUser(principalId, pending.host, result.identity.remoteId, result.identity.acct, result.identity.display, result.caps);
    vaultToken(userId, result.token);
    audit.log("login_success", { userId, host: pending.host, acct: result.identity.acct, ip: clientIp });
    openSession(res, principalId, userId);
  }

  /* GET /auth/me — identity + capability map + the bits the UI needs to seed
     connections: the admin dialect ("Mastodon"/"Misskey", the two api.js
     branches) and a display role per connection. Top-level fields describe
     the LOGIN connection (back-compat); `connections` lists every instance
     account attached to the principal. */
  function me(req, res) {
    const session = sessions.load(req);
    if (!session) return json(res, 401, { error: "not logged in" });
    const roleOf = (caps) => (caps.admin ? "admin" : (caps.actOnAccounts || caps.actOnReports) ? "moderator" : "auditor");
    const connections = connectionsOf.all(session.principalId).map((c) => {
      const caps = JSON.parse(c.capabilities);
      return {
        instance: c.instance_host,
        acct: c.acct,
        username: c.acct.split("@")[0],
        display: c.display,
        software: c.family === "mastodon" ? "Mastodon" : "Misskey",
        family: c.family,
        role: roleOf(caps),
        capabilities: caps,
        current: c.id === session.userId, // the one signed in with
      };
    });
    const caps = session.capabilities;
    json(res, 200, {
      acct: session.acct,
      username: session.acct.split("@")[0],
      display: session.display,
      instance: session.instanceHost,
      software: session.family === "mastodon" ? "Mastodon" : "Misskey", // admin dialect
      family: session.family,
      role: roleOf(caps),
      capabilities: caps,
      connections,
      csrf: session.csrf,
    });
  }

  /* POST /auth/unlink {host} — detach a linked connection: its token, its
     vaulted OSINT keys (and their usage rows — FKs, no cascade), then the
     connection itself. The login connection can't be unlinked from its own
     session (sign in with another connected account to remove it). */
  async function unlink(req, res) {
    const session = sessions.load(req);
    if (!session) return json(res, 401, { error: "not logged in" });
    if (!sessions.checkCsrf(req, session)) return json(res, 403, { error: "missing or bad X-Vantage-CSRF header" });
    let body = {};
    try { body = JSON.parse((await readBody(req)) || "{}"); }
    catch { return json(res, 400, { error: "request body must be JSON" }); }
    const host = normalizeHost(body.host);
    if (!host) return json(res, 400, { error: "host required" });
    const conn = userOnHost.get(session.principalId, host);
    if (!conn) return json(res, 404, { error: `no connected account on ${host}` });
    if (conn.id === session.userId) return json(res, 409, { error: "that's the account this session is signed in with — sign in with another connected server to remove it, or just sign out" });

    db.exec("BEGIN");
    try {
      db.prepare("DELETE FROM key_usage WHERE user_id = ? OR key_id IN (SELECT id FROM user_keys WHERE owner_user_id = ?)").run(conn.id, conn.id);
      db.prepare("DELETE FROM user_keys WHERE owner_user_id = ?").run(conn.id);
      db.prepare("DELETE FROM tokens WHERE user_id = ?").run(conn.id);
      db.prepare("DELETE FROM sessions WHERE user_id = ?").run(conn.id);
      db.prepare("DELETE FROM users WHERE id = ?").run(conn.id);
      db.exec("COMMIT");
    } catch (e) {
      db.exec("ROLLBACK");
      throw e;
    }
    audit.log("connection_unlinked", { userId: session.userId, host });
    json(res, 200, { ok: true });
  }

  /* POST /auth/logout — CSRF-guarded (§6) */
  function logout(req, res) {
    const session = sessions.load(req);
    if (!session) return json(res, 401, { error: "not logged in" });
    if (!sessions.checkCsrf(req, session)) return json(res, 403, { error: "missing or bad X-Vantage-CSRF header" });
    sessions.destroy(session);
    audit.log("logout", { userId: session.userId });
    res.writeHead(204, { "Set-Cookie": sessions.cookie("", { clear: true }) });
    res.end();
  }

  return { login, callbackOauth, callbackMiauth, me, logout, unlink };
}

function json(res, status, body) {
  const buf = JSON.stringify(body);
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Content-Length": Buffer.byteLength(buf) });
  res.end(buf);
}

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

/* Browser-facing failure page for the redirect flows (callbacks land as
   top-level navigations, so JSON errors would be unreadable). */
function failPage(res, status, message) {
  const html = `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Vantage — sign-in problem</title>
<body style="font-family:system-ui,sans-serif;max-width:36rem;margin:15vh auto;padding:0 1rem;line-height:1.5">
<h1 style="font-size:1.2rem">Sign-in problem</h1>
<p>${esc(message)}</p>
<p><a href="/">Back to Vantage</a></p>`;
  res.writeHead(status, { "Content-Type": "text/html; charset=utf-8" });
  res.end(html);
}
