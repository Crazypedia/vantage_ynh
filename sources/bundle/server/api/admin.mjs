/* ============================================================
   Vantage server — Global Admin gateway (hosted-design §10 phase 5,
   pulled forward on request 2026-07-21)
   /api/admin/* is the deployment-admin console: who may sign in
   (the instance allow-list), and who else holds the Global Admin
   role (admin.mjs). Deployment-wide OSINT key sharing reuses
   /api/osint/keys with scope "deployment" (server/api/keys.mjs) —
   gated the same way, by isDeploymentAdmin, so key custody stays in
   one place. Every route here requires BOTH a session and the
   Global Admin role; this is a deployment-level role, distinct from
   `capabilities.admin` (that account's role on its OWN fedi
   instance) — see /auth/me's `isDeploymentAdmin` field.
   ============================================================ */
import {
  getDeploymentAdmins, addDeploymentAdmin, removeDeploymentAdmin,
  isDeploymentAdmin, effectiveAllowedInstances, setAllowedInstancesOverride,
} from "../admin.mjs";
import { normalizeHost } from "../host.mjs";

const PREFIX = "/api/admin";

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

export function makeAdminRoutes({ db, sessions, audit, config }) {
  function status(res) {
    const allowed = effectiveAllowedInstances(db, config);
    sendJson(res, 200, {
      admins: getDeploymentAdmins(db),
      allowedInstances: allowed,
      seedAdminHost: config.seedAdminHost,
      seedClaimed: getDeploymentAdmins(db).length > 0,
    });
  }

  /* PUT /api/admin/allowed-instances {instances: string[]|null} — null/empty
     accepts any instance. Locked (423) when VANTAGE_ALLOWED_INSTANCES is set
     server-side (§4.2: env wins) — edit the server config instead. */
  async function setAllowedInstances(req, res) {
    const current = effectiveAllowedInstances(db, config);
    if (!current.editable) {
      return sendJson(res, 423, { error: "the allow-list is set by VANTAGE_ALLOWED_INSTANCES on the server — edit that instead of here" });
    }
    let body;
    try { body = await readJson(req); }
    catch (e) { return sendJson(res, 400, { error: e.message }); }
    let hosts = null;
    if (body.instances != null) {
      if (!Array.isArray(body.instances)) return sendJson(res, 400, { error: "instances must be an array of domains, or null" });
      hosts = [];
      for (const raw of body.instances) {
        const h = normalizeHost(raw);
        if (!h) return sendJson(res, 400, { error: `"${raw}" doesn't look like an instance domain` });
        if (!hosts.includes(h)) hosts.push(h);
      }
      if (hosts.length === 0) hosts = null; // empty list means "open", same as null
    }
    const list = setAllowedInstancesOverride(db, hosts);
    audit.log("allowed_instances_changed", { list });
    sendJson(res, 200, { allowedInstances: { list, source: "settings", editable: true } });
  }

  async function addAdmin(req, res, session) {
    let body;
    try { body = await readJson(req); }
    catch (e) { return sendJson(res, 400, { error: e.message }); }
    const result = addDeploymentAdmin(db, body.acct);
    if (result.error) return sendJson(res, 400, { error: result.error });
    audit.log("admin_added", { userId: session.userId, acct: String(body.acct || "").trim().toLowerCase() });
    sendJson(res, 200, { admins: result.admins });
  }

  function removeAdmin(res, session, acct) {
    const result = removeDeploymentAdmin(db, acct);
    if (result.error) return sendJson(res, 400, { error: result.error });
    audit.log("admin_removed", { userId: session.userId, acct: String(acct || "").trim().toLowerCase() });
    sendJson(res, 200, { admins: result.admins });
  }

  async function handle(req, res, url) {
    const session = sessions.load(req);
    if (!session) return sendJson(res, 401, { error: "not logged in" });
    if (!isDeploymentAdmin(db, session.acct)) return sendJson(res, 403, { error: "the Global Admin panel is restricted to this deployment's approved admins" });

    const method = (req.method || "GET").toUpperCase();
    if (method !== "GET" && !sessions.checkCsrf(req, session)) {
      return sendJson(res, 403, { error: "missing or bad X-Vantage-CSRF header" });
    }

    const rest = url.pathname.slice(PREFIX.length).split("/").filter(Boolean);

    if (rest.length === 1 && rest[0] === "status" && method === "GET") return status(res);
    if (rest.length === 1 && rest[0] === "allowed-instances" && method === "PUT") return setAllowedInstances(req, res);
    if (rest.length === 1 && rest[0] === "admins") {
      if (method === "POST") return addAdmin(req, res, session);
      return sendJson(res, 405, { error: "method not allowed" });
    }
    if (rest.length === 2 && rest[0] === "admins" && method === "DELETE") {
      return removeAdmin(res, session, decodeURIComponent(rest[1]));
    }
    return sendJson(res, 404, { error: "not found" });
  }

  return { handle };
}
