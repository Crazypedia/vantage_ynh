/* ============================================================
   Vantage server — SSRF-guarded outbound fetch (hosted-design §6)
   The server fetches user-supplied hostnames (login, nodeinfo),
   so every outbound request goes through this guard:
     - HTTPS only (plain http allowed solely for localhost in dev)
     - DNS resolved up front; private / link-local / localhost
       ranges denied; the connection is PINNED to the vetted
       address so a rebinding DNS answer can't redirect it
     - redirects followed manually, each hop re-guarded, capped
     - hard timeout and response-size cap
   Returns { status, headers, text(), json() } — a deliberately
   small surface so callers can't bypass the guard.
   ============================================================ */
import { request as httpsRequest } from "node:https";
import { request as httpRequest } from "node:http";
import { lookup as dnsLookup } from "node:dns";
import { isIP } from "node:net";

const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_REDIRECTS = 3;
const DEFAULT_MAX_BODY_BYTES = 2 * 1024 * 1024;

/* RFC1918 + loopback + link-local + CGNAT + benchmarking + multicast +
   reserved, and the IPv6 equivalents (incl. v4-mapped). */
export function isForbiddenAddress(addr) {
  const family = isIP(addr);
  if (family === 4) return isForbiddenV4(addr);
  if (family === 6) {
    const a = addr.toLowerCase();
    const mapped = a.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return isForbiddenV4(mapped[1]);
    if (a === "::" || a === "::1") return true;
    const first = parseInt(a.split(":")[0] || "0", 16);
    if ((first & 0xfe00) === 0xfc00) return true; // fc00::/7 unique-local
    if ((first & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
    if ((first & 0xff00) === 0xff00) return true; // ff00::/8 multicast
    return false;
  }
  return true; // not an IP literal at all ⇒ refuse
}

function isForbiddenV4(addr) {
  const p = addr.split(".").map(Number);
  if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  const [a, b] = p;
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;  // 100.64.0.0/10 CGNAT
  if (a === 169 && b === 254) return true;             // link-local
  if (a === 172 && b >= 16 && b <= 31) return true;    // 172.16.0.0/12
  if (a === 192 && b === 168) return true;
  if (a === 192 && b === 0) return true;               // 192.0.0.0/24 + 192.0.2.0/24 doc range
  if (a === 198 && (b === 18 || b === 19)) return true; // benchmarking
  if (a >= 224) return true;                            // multicast + reserved
  return false;
}

function resolveVetted(hostname) {
  return new Promise((resolve, reject) => {
    if (isIP(hostname)) {
      if (isForbiddenAddress(hostname)) return reject(new Error(`refusing to fetch private/reserved address ${hostname}`));
      return resolve(hostname);
    }
    dnsLookup(hostname, { all: true, verbatim: true }, (err, addrs) => {
      if (err) return reject(new Error(`DNS lookup failed for ${hostname}: ${err.code || err.message}`));
      if (!addrs || addrs.length === 0) return reject(new Error(`DNS lookup returned no addresses for ${hostname}`));
      const bad = addrs.find((a) => isForbiddenAddress(a.address));
      if (bad) return reject(new Error(`refusing ${hostname}: resolves to private/reserved address`));
      resolve(addrs[0].address); // pin — the socket connects to this vetted address only
    });
  });
}

export function checkUrl(url, { devAllowHttp = false } = {}) {
  let u;
  try { u = new URL(url); } catch { throw new Error(`invalid URL: ${url}`); }
  const localhost = u.hostname === "localhost" || u.hostname === "127.0.0.1" || u.hostname === "::1";
  if (u.protocol === "http:" && !(devAllowHttp && localhost)) throw new Error("outbound requests must be HTTPS");
  if (u.protocol !== "https:" && u.protocol !== "http:") throw new Error(`unsupported protocol ${u.protocol}`);
  if (u.username || u.password) throw new Error("credentials in URLs are not allowed");
  return { url: u, devLocalhost: localhost && devAllowHttp };
}

function requestOnce(u, pinnedAddress, { method, headers, body, timeoutMs }) {
  return new Promise((resolve, reject) => {
    const isHttps = u.protocol === "https:";
    const req = (isHttps ? httpsRequest : httpRequest)({
      host: pinnedAddress,
      port: u.port || (isHttps ? 443 : 80),
      path: u.pathname + u.search,
      method,
      headers: { Host: u.host, "User-Agent": "Vantage", Accept: "application/json", ...headers },
      servername: isHttps ? u.hostname : undefined, // SNI + cert check against the real name, not the IP
      timeout: timeoutMs,
    });
    req.on("timeout", () => req.destroy(new Error(`request to ${u.hostname} timed out after ${timeoutMs}ms`)));
    req.on("error", reject);
    req.on("response", (res) => resolve(res));
    if (body != null) req.write(body);
    req.end();
  });
}

function readBody(res, maxBytes) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    res.on("data", (c) => {
      size += c.length;
      if (size > maxBytes) { res.destroy(); return reject(new Error(`response exceeded ${maxBytes} bytes`)); }
      chunks.push(c);
    });
    res.on("end", () => resolve(Buffer.concat(chunks)));
    res.on("error", reject);
  });
}

export async function safeFetch(url, opts = {}) {
  const {
    method = "GET", headers = {}, body = null,
    timeoutMs = DEFAULT_TIMEOUT_MS, maxRedirects = DEFAULT_MAX_REDIRECTS,
    maxBodyBytes = DEFAULT_MAX_BODY_BYTES, devAllowHttp = false,
  } = opts;
  const deadline = Date.now() + timeoutMs;
  let current = url;
  for (let hop = 0; hop <= maxRedirects; hop++) {
    const { url: u, devLocalhost } = checkUrl(current, { devAllowHttp });
    const pinned = devLocalhost && u.hostname === "localhost" ? "127.0.0.1" : await resolveVetted(u.hostname);
    const remaining = deadline - Date.now();
    if (remaining <= 0) throw new Error(`request to ${u.hostname} timed out after ${timeoutMs}ms`);
    const res = await requestOnce(u, pinned, { method, headers, body, timeoutMs: remaining });
    if (res.statusCode >= 301 && res.statusCode <= 308 && res.headers.location) {
      res.resume(); // drain — the redirect body is discarded
      current = new URL(res.headers.location, u).href;
      continue; // next hop re-runs checkUrl + resolveVetted
    }
    const buf = await readBody(res, maxBodyBytes);
    return {
      status: res.statusCode,
      ok: res.statusCode >= 200 && res.statusCode < 300,
      headers: res.headers,
      text: () => buf.toString("utf8"),
      json: () => JSON.parse(buf.toString("utf8")),
    };
  }
  throw new Error(`too many redirects fetching ${url}`);
}
