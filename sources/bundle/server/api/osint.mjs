/* ============================================================
   Vantage server — OSINT gateway (hosted-design §5, §6, §10 phase 3)
   /api/osint/<service>/<op> runs a keyed OSINT lookup with the API
   key resolved from the vault (user key → instance-shared →
   deployment, §5.1) and injected server-side — the browser never
   holds a key and needs no CORS proxy. The op table is CLOSED:
   only the exact upstream calls the enrichment engine makes are
   reachable, so this is a gateway, not an open proxy. Rate-limit
   headers pass through verbatim; every keyed call is tallied in
   key_usage; instance-shared keys carry a per-user daily cap so
   one moderator can't drain the admin's quota (§5.2).
   ============================================================ */

const PREFIX = "/api/osint";
const MAX_BODY_BYTES = 64 * 1024;

/* Params are validated by named type before they touch a URL. `?` marks
   an optional param. Everything is encodeURIComponent'd at build time. */
const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;
const PARAM_CHECKS = {
  ip: (v) => IPV4_RE.test(v),
  email: (v) => v.includes("@") && v.length <= 320 && !/[\s\x00-\x1f]/.test(v),
  domain: (v) => /^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/i.test(v),
  text: (v) => v.length <= 600 && !/[\x00-\x1f]/.test(v),
};

/* One entry per upstream call enrich.js makes. `build` returns the exact
   fetch the server will run; the key lands in a header, the URL path, or
   the form body depending on what the service's API demands. */
export const SERVICES = {
  abuseipdb: {
    keyRequired: true,
    ops: {
      check: {
        params: { ip: "ip" },
        build: (q, key) => ({
          url: `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(q.ip)}&maxAgeInDays=90`,
          headers: { Key: key, Accept: "application/json" },
        }),
      },
    },
  },
  virustotal: {
    keyRequired: true,
    ops: {
      domain: {
        params: { domain: "domain" },
        build: (q, key) => ({
          url: `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(q.domain)}`,
          headers: { "x-apikey": key },
        }),
      },
    },
  },
  ipqs: {
    keyRequired: true,
    ops: {
      ip: {
        params: { ip: "ip" },
        build: (q, key) => ({ url: `https://ipqualityscore.com/api/json/ip/${encodeURIComponent(key)}/${encodeURIComponent(q.ip)}` }),
      },
      email: {
        params: { email: "email" },
        build: (q, key) => ({ url: `https://ipqualityscore.com/api/json/email/${encodeURIComponent(key)}/${encodeURIComponent(q.email)}` }),
      },
    },
  },
  emailrep: {
    keyRequired: false, // keyless works at a low rate limit — a key only raises it
    ops: {
      query: {
        params: { email: "email" },
        build: (q, key) => ({
          url: `https://emailrep.io/${encodeURIComponent(q.email)}`,
          headers: key ? { Key: key, Accept: "application/json" } : { Accept: "application/json" },
        }),
      },
    },
  },
  hibp: {
    keyRequired: true,
    ops: {
      breachedaccount: {
        params: { email: "email" },
        build: (q, key) => ({
          url: `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(q.email)}?truncateResponse=false`,
          headers: { "hibp-api-key": key, Accept: "application/json" },
        }),
      },
    },
  },
  stopforumspam: {
    keyRequired: true, // lookups are keyless JSONP browser-side; only the submit POST needs the key
    ops: {
      add: {
        method: "POST",
        params: { username: "text", email: "email", ip: "ip", evidence: "text?" },
        build: (q, key) => {
          const body = new URLSearchParams({ username: q.username, email: q.email, ip_addr: q.ip, api_key: key });
          if (q.evidence) body.set("evidence", q.evidence);
          return { url: "https://www.stopforumspam.com/add", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: body.toString() };
        },
      },
    },
  },
};

/* Upstream response headers relayed to the browser (same-origin, so the UI
   can finally read AbuseIPDB's quota headers without a cooperating proxy). */
const PASS_HEADERS = ["x-ratelimit-remaining", "x-ratelimit-limit", "x-ratelimit-reset", "retry-after"];

function sendJson(res, status, body) {
  const buf = Buffer.from(JSON.stringify(body));
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Content-Length": buf.length });
  res.end(buf);
}

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

const today = () => new Date().toISOString().slice(0, 10);

export function makeOsintGateway({ db, vault, sessions, fetchFn, config }) {
  /* §5.1 resolution order: the principal's own key (whichever connection it
     was added from), then an instance-shared key of ANY instance the person
     is a connected moderator of, then a deployment-wide key (D3c, far-future
     — nothing can create one yet, but resolution is ready for it). */
  const resolveKeyStmt = db.prepare(`
    SELECT k.id, k.scope, k.ciphertext, k.owner_user_id, k.instance_host FROM user_keys k
     WHERE k.service = ?
       AND ((k.scope = 'user' AND k.owner_user_id IN (SELECT id FROM users WHERE principal_id = ?))
         OR (k.scope = 'instance' AND k.instance_host IN (SELECT instance_host FROM users WHERE principal_id = ?))
         OR k.scope = 'deployment')
     ORDER BY CASE k.scope WHEN 'user' THEN 0 WHEN 'instance' THEN 1 ELSE 2 END, k.id DESC
     LIMIT 1`);
  const myUserOn = db.prepare("SELECT id FROM users WHERE principal_id = ? AND instance_host = ?");
  const usageOf = db.prepare("SELECT count FROM key_usage WHERE key_id = ? AND user_id = ? AND day = ?");
  const bumpUsage = db.prepare(`
    INSERT INTO key_usage (key_id, user_id, day, count) VALUES (?, ?, ?, 1)
    ON CONFLICT (key_id, user_id, day) DO UPDATE SET count = count + 1`);

  async function handle(req, res, url) {
    const session = sessions.load(req);
    if (!session) return sendJson(res, 401, { error: "not logged in" });

    const method = (req.method || "GET").toUpperCase();
    if (method !== "GET" && method !== "HEAD" && !sessions.checkCsrf(req, session)) {
      return sendJson(res, 403, { error: "missing or bad X-Vantage-CSRF header" });
    }

    const parts = url.pathname.slice(PREFIX.length).split("/").filter(Boolean); // [service, op]
    const svc = SERVICES[parts[0]];
    const op = svc && svc.ops[parts[1]];
    if (!svc || !op || parts.length !== 2) return sendJson(res, 404, { error: "unknown OSINT service or operation" });
    if (method !== (op.method || "GET")) return sendJson(res, 405, { error: `${parts[0]}/${parts[1]} is ${op.method || "GET"}-only` });

    // Params come from the query string (GET) or a JSON body (POST) — the op
    // table names and type-checks every one; anything else is rejected.
    let source = {};
    if (method === "GET") {
      for (const [k, v] of url.searchParams) source[k] = v;
    } else {
      const raw = await readBody(req);
      if (raw) {
        try { source = JSON.parse(raw.toString("utf8")); }
        catch { return sendJson(res, 400, { error: "request body must be JSON" }); }
      }
    }
    const params = {};
    for (const [name, spec] of Object.entries(op.params)) {
      const optional = spec.endsWith("?");
      const type = optional ? spec.slice(0, -1) : spec;
      const value = source[name];
      if (value == null || value === "") {
        if (optional) continue;
        return sendJson(res, 400, { error: `missing parameter: ${name}` });
      }
      if (typeof value !== "string" || !PARAM_CHECKS[type](value)) {
        return sendJson(res, 400, { error: `invalid parameter: ${name}` });
      }
      params[name] = value;
    }

    const row = resolveKeyStmt.get(parts[0], session.principalId, session.principalId);
    if (!row && svc.keyRequired) {
      return sendJson(res, 412, { error: `no ${parts[0]} key available — add one in Services` });
    }
    let key = null;
    let usageUserId = null;
    if (row) {
      try { key = vault.open(row.ciphertext); }
      catch { return sendJson(res, 500, { error: "key could not be unsealed" }); }
      // Usage is charged to ONE user row per person per key: the owner row for
      // own keys, the person's connection on the key's instance for shared
      // keys (exactly one exists — that's what made the key resolve).
      usageUserId = row.scope === "user" ? row.owner_user_id
        : row.scope === "instance" ? myUserOn.get(session.principalId, row.instance_host).id
        : session.userId;
      // Per-user daily cap on keys the person doesn't own themselves (§5.2).
      if (row.scope !== "user" && config.sharedKeyDailyCap > 0) {
        const used = usageOf.get(row.id, usageUserId, today());
        if (used && used.count >= config.sharedKeyDailyCap) {
          return sendJson(res, 429, { error: `daily cap on the shared ${parts[0]} key reached (${config.sharedKeyDailyCap}/user) — add your own key in Services or retry tomorrow` });
        }
      }
    }

    const call = op.build(params, key);
    let upstream;
    try {
      upstream = await fetchFn(call.url, { method, headers: call.headers || {}, body: call.body || null });
    } catch (e) {
      return sendJson(res, 502, { error: `couldn't reach ${parts[0]}: ${e.message}` });
    }
    // The upstream call happened — it consumed quota whatever the status, so
    // tally it (cache hits never reach the server; the browser caches first).
    // The key row can vanish mid-flight (owner deleted it); losing that one
    // tally beats failing a lookup that already succeeded upstream.
    if (row) { try { bumpUsage.run(row.id, usageUserId, today()); } catch { /* key deleted concurrently */ } }

    const text = upstream.text();
    const headers = {
      "Content-Type": upstream.headers["content-type"] || "application/json; charset=utf-8",
      "Content-Length": Buffer.byteLength(text),
      "X-Vantage-Key-Scope": row ? row.scope : "none",
    };
    for (const h of PASS_HEADERS) if (upstream.headers[h] != null) headers[h] = upstream.headers[h];
    res.writeHead(upstream.status, headers);
    res.end(text);
  }

  return { handle };
}
