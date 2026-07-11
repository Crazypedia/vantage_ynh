/* ============================================================
   Vantage server — rate limiting (hosted-design §6)
   Fixed-window in-memory limiter, keyed per client IP or per
   session. In-memory is correct here: the deployment is a single
   process (D4), and losing counters on restart is acceptable for
   an abuse brake. Buckets are pruned as they expire.
   ============================================================ */

export function makeRateLimiter({ limit, windowMs }) {
  const buckets = new Map(); // key → { count, resetAt }

  function allow(key, now = Date.now()) {
    const b = buckets.get(key);
    if (!b || b.resetAt <= now) {
      if (buckets.size > 10_000) prune(now); // bound memory under address-spray abuse
      buckets.set(key, { count: 1, resetAt: now + windowMs });
      return true;
    }
    b.count += 1;
    return b.count <= limit;
  }

  function prune(now) {
    for (const [k, b] of buckets) if (b.resetAt <= now) buckets.delete(k);
  }

  return { allow };
}
