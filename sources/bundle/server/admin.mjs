/* ============================================================
   Vantage server — deployment admin (hosted-design §10 phase 5,
   pulled forward on request 2026-07-21)

   A Vantage *deployment* (not a fedi instance) can have its own
   "Global Admin" — someone who manages, from inside Vantage:
     • which instance domains may sign in (the allow-list)
     • deployment-wide OSINT key sharing (D3c: user_keys scope
       'deployment' — the OSINT gateway already RESOLVES that
       scope; server/api/keys.mjs is what lets an admin WRITE one)
     • the list of accounts allowed to open the Global Admin panel

   Bootstrap: the operator names one "seed" instance domain at
   install time (VANTAGE_SEED_ADMIN_HOST, standalone .env or the
   YunoHost install/config-panel question). The FIRST moderator who
   successfully logs in FROM that host becomes the deployment admin
   — one-shot and race-free because node:sqlite is synchronous, so
   there's no await between "is the admin list still empty" and
   "write the claim" for two concurrent logins to interleave around.
   Once at least one admin exists, the seed host is inert; further
   admins are added/removed from the Global Admin panel itself.

   No new tables: both the admin list and the allow-list override
   live in the existing generic `settings` k/v table.
   ============================================================ */
import { normalizeHost } from "./host.mjs";
import { isModerator } from "./capabilities.mjs";

const ADMINS_KEY = "deployment_admins";
const ALLOWED_OVERRIDE_KEY = "allowed_instances_override";

function readJsonSetting(db, key, fallback) {
  const row = db.prepare("SELECT v FROM settings WHERE k = ?").get(key);
  if (!row) return fallback;
  try { return JSON.parse(row.v); } catch { return fallback; }
}

function writeJsonSetting(db, key, value) {
  db.prepare(
    "INSERT INTO settings (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v"
  ).run(key, JSON.stringify(value));
}

export function getDeploymentAdmins(db) {
  return readJsonSetting(db, ADMINS_KEY, []);
}

function setDeploymentAdmins(db, admins) {
  writeJsonSetting(db, ADMINS_KEY, admins);
}

export function isDeploymentAdmin(db, acct) {
  if (!acct) return false;
  return getDeploymentAdmins(db).includes(String(acct).toLowerCase());
}

/* acct strings are the human-readable identity already used everywhere else
   in this codebase (key-sharing's "sharedBy", session.acct, …): username@host,
   lowercased for comparison since fedi handles are case-insensitive. Adding
   an acct that hasn't logged in yet is intentional — it's a pre-approval,
   consistent with "approved list of users" rather than "promote someone
   already here". */
export function addDeploymentAdmin(db, acct) {
  const norm = String(acct || "").trim().toLowerCase();
  if (!norm || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(norm)) return { error: "acct must look like username@instance.tld" };
  const admins = getDeploymentAdmins(db);
  if (admins.includes(norm)) return { error: `${norm} is already an admin` };
  const next = [...admins, norm];
  setDeploymentAdmins(db, next);
  return { admins: next };
}

export function removeDeploymentAdmin(db, acct) {
  const norm = String(acct || "").trim().toLowerCase();
  const admins = getDeploymentAdmins(db);
  if (!admins.includes(norm)) return { error: `${norm} is not an admin` };
  if (admins.length === 1) return { error: "at least one admin is required — add another before removing the last one" };
  const next = admins.filter((a) => a !== norm);
  setDeploymentAdmins(db, next);
  return { admins: next };
}

/* Call once per successful login (auth/routes.mjs finishLogin), synchronously
   — no await between the emptiness check and the write. Returns true if this
   login just became the deployment admin (worth an audit-log line). */
export function maybeClaimSeedAdmin(db, config, loginHost, acct, caps) {
  if (!config.seedAdminHost) return false;
  if (loginHost !== config.seedAdminHost) return false;
  if (!isModerator(caps)) return false;
  if (getDeploymentAdmins(db).length > 0) return false; // already claimed — one-shot
  setDeploymentAdmins(db, [String(acct).toLowerCase()]);
  return true;
}

/* §4.2's env-wins pattern, extended with a runtime-editable fallback: env
   (VANTAGE_ALLOWED_INSTANCES) wins outright and locks the Global Admin
   panel's allow-list field to read-only; otherwise the settings-table
   override the panel writes applies; otherwise unset (open, any instance). */
export function effectiveAllowedInstances(db, config) {
  if (config.allowedInstances) return { list: config.allowedInstances, source: "env", editable: false };
  return { list: readJsonSetting(db, ALLOWED_OVERRIDE_KEY, null), source: "settings", editable: true };
}

export function setAllowedInstancesOverride(db, hosts) {
  if (hosts == null) { writeJsonSetting(db, ALLOWED_OVERRIDE_KEY, null); return null; }
  const list = [];
  for (const h of hosts) {
    const norm = normalizeHost(h);
    if (norm && !list.includes(norm)) list.push(norm);
  }
  writeJsonSetting(db, ALLOWED_OVERRIDE_KEY, list.length ? list : null);
  return list.length ? list : null;
}
