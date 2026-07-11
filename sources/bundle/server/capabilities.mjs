/* ============================================================
   Vantage server — capability maps (hosted-design §4.3, D2)
   OAuth grants scopes, not powers: anyone can approve an
   admin:read scope, but the instance 403s if their account lacks
   the role. After token acquisition we probe the account and
   build a capability map per session. v1 policy: no moderation
   capability ⇒ login rejected. The map (not a binary flag) is
   what a future read/audit tier flips.
   ============================================================ */

/* Mastodon 4.x UserRole permission bitmask (app/models/user_role.rb).
   verify_credentials returns role.permissions as a stringified int. */
export const MASTODON_FLAGS = {
  administrator: 1 << 0,
  devops: 1 << 1,
  view_audit_log: 1 << 2,
  view_dashboard: 1 << 3,
  manage_reports: 1 << 4,
  manage_federation: 1 << 5,
  manage_settings: 1 << 6,
  manage_blocks: 1 << 7,
  manage_taxonomies: 1 << 8,
  manage_appeals: 1 << 9,
  manage_users: 1 << 10,
  manage_invites: 1 << 11,
  manage_rules: 1 << 12,
  manage_announcements: 1 << 13,
  manage_custom_emojis: 1 << 14,
  manage_webhooks: 1 << 15,
  invite_users: 1 << 16,
  manage_roles: 1 << 17,
  manage_user_access: 1 << 18,
  delete_user_data: 1 << 19,
};

const NONE = Object.freeze({ viewReports: false, actOnReports: false, actOnAccounts: false, viewAuditLog: false, admin: false });
const ALL = Object.freeze({ viewReports: true, actOnReports: true, actOnAccounts: true, viewAuditLog: true, admin: true });

/* me = verify_credentials body. adminProbeOk = did a cheap admin read
   (GET /api/v1/admin/reports?limit=1) succeed — the tiebreaker for
   forks (GoToSocial, Pixelfed) whose role object has a name but no
   permissions bitmask. */
export function fromMastodon(me, adminProbeOk = false) {
  const role = me && me.role;
  const bits = role && role.permissions != null ? Number(role.permissions) : NaN;
  if (Number.isFinite(bits) && bits > 0) {
    if (bits & MASTODON_FLAGS.administrator) return { ...ALL };
    return {
      viewReports: !!(bits & MASTODON_FLAGS.manage_reports),
      actOnReports: !!(bits & MASTODON_FLAGS.manage_reports),
      actOnAccounts: !!(bits & MASTODON_FLAGS.manage_users),
      viewAuditLog: !!(bits & MASTODON_FLAGS.view_audit_log),
      admin: false,
    };
  }
  const name = String((role && role.name) || "").toLowerCase();
  if (/admin|owner/.test(name)) return { ...ALL };
  if (/moderator/.test(name) || adminProbeOk) {
    return { viewReports: true, actOnReports: true, actOnAccounts: true, viewAuditLog: false, admin: /admin|owner/.test(name) };
  }
  return { ...NONE };
}

/* i = Misskey/Sharkey `i` endpoint body. */
export function fromMisskey(i) {
  if (i && i.isAdmin) return { ...ALL };
  if (i && i.isModerator) return { viewReports: true, actOnReports: true, actOnAccounts: true, viewAuditLog: false, admin: false };
  return { ...NONE };
}

/* D2: the login gate — any moderation capability admits the session. */
export function isModerator(caps) {
  return !!(caps && (caps.viewReports || caps.actOnReports || caps.actOnAccounts));
}
