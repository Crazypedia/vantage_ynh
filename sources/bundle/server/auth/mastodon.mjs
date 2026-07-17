/* ============================================================
   Vantage server — Mastodon-family login (hosted-design §4.1)
   OAuth 2 authorization-code + PKCE. The server registers itself
   per instance via POST /api/v1/apps (dynamic — no
   pre-registration anywhere) and caches the client credentials,
   sealed, in the instances table. The instance's consent screen
   lists the scopes natively.
   ============================================================ */
import { createHash, randomBytes } from "node:crypto";

/* The complete moderation surface Vantage drives (§11 scope audit, 2026-07-16),
   fine-grained rather than the admin:read/admin:write umbrellas so the consent
   screen shows exactly what's taken:
     read:accounts                      identify the signed-in account
     write:accounts                     moderator note (POST /api/v1/accounts/:id/note)
     admin:read/write:accounts          review queue, search, approve/reject/action
     admin:read/write:reports           report list + resolve
     admin:read/write:ip_blocks         server-side IP blocks (4.0+)
     admin:read/write:email_domain_blocks  email-domain blocks (4.1+)
     admin:read/write:domain_blocks     federation domain blocks
   Widening this list re-registers each instance's app (see ensureApp). */
export const OAUTH_SCOPES = "read:accounts write:accounts admin:read:accounts admin:write:accounts admin:read:reports admin:write:reports admin:read:ip_blocks admin:write:ip_blocks admin:read:email_domain_blocks admin:write:email_domain_blocks admin:read:domain_blocks admin:write:domain_blocks";

export function redirectUri(publicUrl) {
  return `${publicUrl}/auth/callback/oauth`;
}

/* Fetch-or-register the OAuth app for an instance. Client secret is
   vault-sealed at rest. */
export async function ensureApp({ db, vault, fetchFn, fetchOpts, publicUrl, host, origin }) {
  const row = db.prepare("SELECT oauth_client_id, oauth_client_secret, oauth_scopes FROM instances WHERE host = ?").get(host);
  // Cached app is only reusable if it was registered with the CURRENT scope
  // list — Mastodon rejects authorize requests for scopes the app didn't
  // declare, so a widened OAUTH_SCOPES forces a fresh registration here.
  if (row && row.oauth_client_id && row.oauth_client_secret && row.oauth_scopes === OAUTH_SCOPES) {
    return { clientId: row.oauth_client_id, clientSecret: vault.open(row.oauth_client_secret) };
  }
  const res = await fetchFn(`${origin}/api/v1/apps`, {
    ...fetchOpts,
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_name: "Vantage",
      redirect_uris: redirectUri(publicUrl),
      scopes: OAUTH_SCOPES,
      website: "https://github.com/Crazypedia/fediDash",
    }),
  });
  if (!res.ok) throw new Error(`app registration on ${host} failed (HTTP ${res.status})`);
  const app = res.json();
  if (!app.client_id || !app.client_secret) throw new Error(`app registration on ${host} returned no client credentials`);
  db.prepare("UPDATE instances SET oauth_client_id = ?, oauth_client_secret = ?, oauth_scopes = ? WHERE host = ?")
    .run(app.client_id, vault.seal(app.client_secret), OAUTH_SCOPES, host);
  return { clientId: app.client_id, clientSecret: app.client_secret };
}

export function pkcePair() {
  const verifier = randomBytes(48).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}

export function authorizeUrl({ origin, clientId, publicUrl, state, challenge }) {
  const q = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: redirectUri(publicUrl),
    scope: OAUTH_SCOPES,
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
  });
  return `${origin}/oauth/authorize?${q}`;
}

export async function exchangeCode({ fetchFn, fetchOpts, host, origin, clientId, clientSecret, publicUrl, code, verifier }) {
  const res = await fetchFn(`${origin}/oauth/token`, {
    ...fetchOpts,
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      grant_type: "authorization_code",
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: redirectUri(publicUrl),
      code,
      code_verifier: verifier,
    }),
  });
  if (!res.ok) throw new Error(`token exchange with ${host} failed (HTTP ${res.status})`);
  const body = res.json();
  if (!body.access_token) throw new Error(`token exchange with ${host} returned no access token`);
  return body.access_token;
}

/* Role probe (§4.3): verify_credentials for identity + role, plus one
   cheap admin read as the tiebreaker for forks without the permissions
   bitmask. 403/401 on the probe simply means "not a mod". */
export async function probeAccount({ fetchFn, fetchOpts, origin, token }) {
  const auth = { Authorization: `Bearer ${token}` };
  const me = await fetchFn(`${origin}/api/v1/accounts/verify_credentials`, { ...fetchOpts, headers: auth });
  if (!me.ok) throw new Error(`verify_credentials on ${new URL(origin).host} failed (HTTP ${me.status})`);
  const probe = await fetchFn(`${origin}/api/v1/admin/reports?limit=1`, { ...fetchOpts, headers: auth });
  return { me: me.json(), adminProbeOk: probe.ok };
}

/* D2: a rejected login's token is revoked, not just discarded. */
export async function revokeToken({ fetchFn, fetchOpts, origin, clientId, clientSecret, token }) {
  const res = await fetchFn(`${origin}/oauth/revoke`, {
    ...fetchOpts,
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ client_id: clientId, client_secret: clientSecret, token }),
  });
  return res.ok;
}
