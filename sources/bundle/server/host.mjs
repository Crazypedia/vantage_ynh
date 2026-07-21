/* ============================================================
   Vantage server — instance-host normalization (shared)
   Split out of auth/routes.mjs so config.mjs and admin.mjs can
   normalize a host (e.g. VANTAGE_SEED_ADMIN_HOST, an admin-panel
   allow-list edit) without importing the auth route layer.
   ============================================================ */

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
