/* ============================================================
   Vantage server — audit log + redaction (hosted-design §6)
   Records logins, rejected logins, logouts (later: key
   add/share/delete and moderation writes). Redaction is applied
   to every detail object before insert AND is exported for the
   error/log paths — tokens and keys never appear in logs or
   error bodies (§5.2).
   ============================================================ */

const SECRET_KEY_RE = /token|secret|key|password|authorization|cookie|ciphertext|code|verifier/i;

export function redact(value, depth = 0) {
  if (depth > 6 || value == null) return value;
  if (Array.isArray(value)) return value.map((v) => redact(v, depth + 1));
  if (typeof value === "object") {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = SECRET_KEY_RE.test(k) ? "[redacted]" : redact(v, depth + 1);
    }
    return out;
  }
  return value;
}

export function makeAudit(db) {
  const insert = db.prepare("INSERT INTO audit_log (user_id, action, detail) VALUES (?, ?, ?)");
  return {
    log(action, { userId = null, ...detail } = {}) {
      insert.run(userId, action, JSON.stringify(redact(detail)));
    },
  };
}
