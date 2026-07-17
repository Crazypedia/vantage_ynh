/* ============================================================
   Vantage server — Misskey/Sharkey login via MiAuth
   (hosted-design §4.1). Generate a session UUID, send the user to
   https://host/miauth/{uuid}?…, then call POST
   /api/miauth/{uuid}/check for the token + user object. MiAuth
   cannot step up without re-auth, so the full moderation
   permission set is requested at first login.
   ============================================================ */
import { randomUUID } from "node:crypto";

/* The complete moderation surface Vantage drives (§11 permission audit,
   2026-07-16, kinds verified against Sharkey develop endpoint sources).
   MiAuth can't step up without a fresh grant, so the full set is requested
   at login; a token from before this list widened must sign out and back in.
   Sharkey-only kinds (approve/decline/silence) are harmless on vanilla
   Misskey — unknown kinds simply never match an endpoint. Role checks
   (requireModerator/requireAdmin) still apply on top of these. */
export const MIAUTH_PERMISSIONS = [
  "read:account",                            // identify (/api/i) + role probe
  // account review + inspection
  "read:admin:show-user",                    // admin/show-user + admin/show-users (queue, search)
  "read:admin:user-ips",                     // admin/get-user-ips (sign-in IP history)
  "write:admin:approve-user",                // Sharkey signup approval
  "write:admin:decline-user",                // Sharkey signup rejection
  "write:admin:delete-account",              // admin/accounts/delete (reject fallback / removal)
  "write:admin:suspend-user",
  "write:admin:unsuspend-user",
  "write:admin:silence-user",
  "write:admin:unsilence-user",
  "write:admin:user-note",                   // moderator memo
  "write:admin:send-email",                  // confirmation-mail substitute
  // reports
  "read:admin:abuse-user-reports",
  "write:admin:resolve-abuse-user-report",
  // server-side blocks (domain blocks live in instance meta on Misskey-family)
  "read:admin:meta",
  "write:admin:meta",
  "write:admin:federation",                  // per-instance federation actions (suspend/refresh)
];

export function callbackUri(publicUrl) {
  return `${publicUrl}/auth/callback/miauth`;
}

export function beginMiAuth({ origin, publicUrl, state }) {
  const uuid = randomUUID();
  const q = new URLSearchParams({
    name: "Vantage",
    callback: `${callbackUri(publicUrl)}?state=${encodeURIComponent(state)}`,
    permission: MIAUTH_PERMISSIONS.join(","),
  });
  return { uuid, url: `${origin}/miauth/${uuid}?${q}` };
}

export async function checkMiAuth({ fetchFn, fetchOpts, host, origin, uuid }) {
  const res = await fetchFn(`${origin}/api/miauth/${uuid}/check`, {
    ...fetchOpts,
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: "{}",
  });
  if (!res.ok) throw new Error(`MiAuth check with ${host} failed (HTTP ${res.status})`);
  const body = res.json();
  if (!body.ok || !body.token) throw new Error(`MiAuth session on ${host} was not approved`);
  return { token: body.token, user: body.user || null };
}

/* Role probe (§4.3): `i` carries isAdmin/isModerator. Fetched fresh even
   though check() returns a user object, so the map reflects the account
   as the token sees it. */
export async function probeAccount({ fetchFn, fetchOpts, origin, token }) {
  const res = await fetchFn(`${origin}/api/i`, {
    ...fetchOpts,
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ i: token }),
  });
  if (!res.ok) throw new Error(`identity check (i) on ${new URL(origin).host} failed (HTTP ${res.status})`);
  return { me: res.json() };
}
