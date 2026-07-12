/* ============================================================
   Vantage server — entry point (hosted-design §3, §10 phase 1)
   One node:http process: serves the built UI and the /auth/*
   routes. Zero runtime dependencies (D4): node:http, node:sqlite,
   node:crypto. Later phases add /api/instance, /api/osint,
   /api/lookup, /api/workspace behind the same router.
   ============================================================ */
import { createServer } from "node:http";
import { loadConfig } from "./config.mjs";
import { openDb } from "./db.mjs";
import { makeVault } from "./vault.mjs";
import { makeSessions } from "./sessions.mjs";
import { makeAudit, redact } from "./audit.mjs";
import { makeRateLimiter } from "./rate-limit.mjs";
import { makeAuthRoutes } from "./auth/routes.mjs";
import { makeInstanceGateway } from "./api/instance.mjs";
import { makeStatic } from "./static.mjs";
import { safeFetch } from "./safe-fetch.mjs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

export function startServer(overridesEnv = process.env) {
  const config = loadConfig(overridesEnv);
  const db = openDb(config.dbPath);
  const vault = makeVault(config.masterKey);
  const sessions = makeSessions(db, { ttlHours: config.sessionTtlHours, cookieSecure: config.cookieSecure });
  const audit = makeAudit(db);
  const loginLimiter = makeRateLimiter({ limit: 10, windowMs: 5 * 60 * 1000 });
  const callbackLimiter = makeRateLimiter({ limit: 30, windowMs: 5 * 60 * 1000 });
  const auth = makeAuthRoutes({ db, vault, sessions, audit, config, fetchFn: safeFetch, loginLimiter });
  const instanceGateway = makeInstanceGateway({ db, vault, sessions, fetchFn: safeFetch, config });
  const apiLimiter = makeRateLimiter({ limit: 240, windowMs: 60 * 1000 });
  const { serveUi, uiPath } = makeStatic(ROOT);

  function clientIp(req) {
    if (config.trustProxy) {
      const xff = req.headers["x-forwarded-for"];
      if (typeof xff === "string" && xff.length) {
        const parts = xff.split(",").map((s) => s.trim()).filter(Boolean);
        if (parts.length) return parts[parts.length - 1]; // last hop = appended by our own proxy
      }
    }
    return req.socket.remoteAddress || "unknown";
  }

  const server = createServer(async (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
    const route = `${req.method} ${url.pathname}`;
    try {
      // Instance gateway is a prefix route (/api/instance/<upstream-path>).
      if (url.pathname === "/api/instance" || url.pathname.startsWith("/api/instance/")) {
        if (!apiLimiter.allow(clientIp(req))) return plain(res, 429, "too many requests");
        return await instanceGateway.handle(req, res, url, clientIp(req));
      }
      switch (route) {
        case "GET /auth/login": return await auth.login(req, res, url, clientIp(req));
        case "GET /auth/callback/oauth":
          if (!callbackLimiter.allow(clientIp(req))) return plain(res, 429, "too many requests");
          return await auth.callbackOauth(req, res, url, clientIp(req));
        case "GET /auth/callback/miauth":
          if (!callbackLimiter.allow(clientIp(req))) return plain(res, 429, "too many requests");
          return await auth.callbackMiauth(req, res, url, clientIp(req));
        case "GET /auth/me": return auth.me(req, res);
        case "POST /auth/logout": return auth.logout(req, res);
        case "GET /healthz": return plain(res, 200, "ok");
        case "GET /":
        case "GET /index.html": return serveUi(req, res);
        default: return plain(res, 404, "not found");
      }
    } catch (e) {
      /* Redaction guarantee (§5.2): never echo internals to the client. */
      console.error(`[vantage] ${route} failed:`, redact({ error: e.message }));
      if (!res.headersSent) plain(res, 500, "internal error");
      else res.end();
    }
  });

  const sweeper = setInterval(() => sessions.sweepExpired(), 60 * 60 * 1000);
  sweeper.unref();

  server.listen(config.port, config.host, () => {
    console.log(`[vantage] listening on http://${config.host}:${config.port} (public URL ${config.publicUrl})`);
    console.log(`[vantage] serving UI from ${uiPath}`);
    console.log(`[vantage] data dir ${config.dataDir} · master key from ${config.masterKeySource}` +
      (config.masterKeySource.startsWith("generated") ? " — back up data/master.key; losing it loses all vaulted secrets" : ""));
    console.log(`[vantage] instance allow-list: ${config.allowedInstances ? config.allowedInstances.join(", ") : "OFF (any instance may log in — set VANTAGE_ALLOWED_INSTANCES)"}`);
  });

  function shutdown() {
    clearInterval(sweeper);
    server.close(() => { db.close(); process.exit(0); });
  }

  return { server, db, config, shutdown };
}

function plain(res, status, text) {
  res.writeHead(status, { "Content-Type": "text/plain; charset=utf-8" });
  res.end(text);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const { shutdown } = startServer();
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}
