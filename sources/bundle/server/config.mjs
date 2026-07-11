/* ============================================================
   Vantage server — configuration (hosted-design §1, §4.2, §5.2)
   One process, one config: everything comes from the environment
   (or a key file), with safe defaults for a first `npm start`.
   ============================================================ */
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { randomBytes } from "node:crypto";

const KEY_BYTES = 32;

function decodeKey(raw, source) {
  const s = String(raw).trim();
  let buf = null;
  if (/^[0-9a-fA-F]{64}$/.test(s)) buf = Buffer.from(s, "hex");
  else {
    try { buf = Buffer.from(s, "base64"); } catch { buf = null; }
  }
  if (!buf || buf.length !== KEY_BYTES) {
    throw new Error(`${source} must be ${KEY_BYTES} bytes as 64 hex chars or base64 — got something else`);
  }
  return buf;
}

/* Master-key resolution (§5.2): VANTAGE_MASTER_KEY (inline) wins, then
   VANTAGE_MASTER_KEY_FILE, then a generated key persisted to
   <dataDir>/master.key so a bare `npm start` works out of the box.
   Losing that file means losing every vaulted token/key, so the docs tell
   self-hosters to back it up or pin it via env. */
function resolveMasterKey(env, dataDir) {
  if (env.VANTAGE_MASTER_KEY) return { key: decodeKey(env.VANTAGE_MASTER_KEY, "VANTAGE_MASTER_KEY"), source: "env" };
  if (env.VANTAGE_MASTER_KEY_FILE) return { key: decodeKey(readFileSync(env.VANTAGE_MASTER_KEY_FILE, "utf8"), env.VANTAGE_MASTER_KEY_FILE), source: "file" };
  const path = join(dataDir, "master.key");
  if (existsSync(path)) return { key: decodeKey(readFileSync(path, "utf8"), path), source: "generated" };
  const key = randomBytes(KEY_BYTES);
  writeFileSync(path, key.toString("hex") + "\n", { mode: 0o600 });
  return { key, source: "generated-new" };
}

function parseAllowedInstances(raw) {
  if (raw == null || String(raw).trim() === "") return null; // unset ⇒ any instance may log in (§4.2)
  return String(raw)
    .split(",")
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean);
}

export function loadConfig(env = process.env) {
  const port = Number(env.VANTAGE_PORT || 8686);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("VANTAGE_PORT must be a valid TCP port");
  const host = env.VANTAGE_HOST || "127.0.0.1";
  const publicUrl = (env.VANTAGE_PUBLIC_URL || `http://localhost:${port}`).replace(/\/+$/, "");
  const dataDir = env.VANTAGE_DATA_DIR || join(process.cwd(), "data");
  mkdirSync(dataDir, { recursive: true });
  const { key: masterKey, source: masterKeySource } = resolveMasterKey(env, dataDir);
  const sessionTtlHours = Number(env.VANTAGE_SESSION_TTL_HOURS || 72);
  if (!(sessionTtlHours > 0)) throw new Error("VANTAGE_SESSION_TTL_HOURS must be a positive number");
  return {
    port,
    host,
    publicUrl,
    dataDir,
    dbPath: join(dataDir, "vantage.sqlite"),
    masterKey,
    masterKeySource,
    allowedInstances: parseAllowedInstances(env.VANTAGE_ALLOWED_INSTANCES),
    cookieSecure: env.VANTAGE_COOKIE_SECURE != null ? env.VANTAGE_COOKIE_SECURE === "1" : publicUrl.startsWith("https:"),
    sessionTtlHours,
    /* Behind a reverse proxy (nginx, YunoHost), rate limiting should key on
       the real client: set VANTAGE_TRUST_PROXY=1 to honour X-Forwarded-For
       (the last entry — the hop the proxy itself appended). */
    trustProxy: env.VANTAGE_TRUST_PROXY === "1",
    /* Dev escape hatch: lets login/nodeinfo target plain-http localhost
       instances (never private ranges elsewhere — safeFetch still guards). */
    devAllowHttp: env.VANTAGE_DEV_ALLOW_HTTP === "1",
  };
}

export { parseAllowedInstances };
