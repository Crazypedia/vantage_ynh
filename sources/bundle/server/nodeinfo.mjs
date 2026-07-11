/* ============================================================
   Vantage server — software detection via nodeinfo (hosted-design §4.1)
   Server-side port of src/api.js detect(). Same two admin
   dialects: Mastodon (Bearer REST, /api/v1/admin/*) and Misskey
   (POST + token as `i`, /api/admin/*). The megalodon fallback is
   gone — the server reads nodeinfo directly, trying the
   well-known document first, then the conventional paths.
   ============================================================ */

export function familyOf(softwareName) {
  const name = String(softwareName || "").toLowerCase();
  if (name.includes("sharkey")) return { software: "Sharkey", family: "misskey" };
  if (name.includes("misskey") || name.includes("cherrypick") || name.includes("firefish") || name.includes("iceshrimp") || name.includes("foundkey") || name.includes("catodon")) {
    return { software: "Misskey", family: "misskey" };
  }
  if (name.includes("mastodon") || name.includes("hometown") || name.includes("glitch") || name.includes("gotosocial") || name.includes("pixelfed") || name.includes("pleroma") || name.includes("akkoma")) {
    return { software: "Mastodon", family: "mastodon" };
  }
  return { software: null, family: null };
}

/* `origin` is scheme+host(+port), e.g. "https://example.social" —
   computed by the caller so the dev http-localhost escape hatch works. */
export async function detect(origin, fetchFn, fetchOpts = {}) {
  const base = origin;
  const host = new URL(origin).host;
  const get = async (url) => {
    const r = await fetchFn(url, fetchOpts);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  };

  let node = null;
  try {
    const wk = await get(`${base}/.well-known/nodeinfo`);
    const links = Array.isArray(wk.links) ? wk.links : [];
    const pick = links.find((l) => /nodeinfo\/2\.1$/.test(l.rel)) || links.find((l) => /nodeinfo\/2\.0$/.test(l.rel));
    if (pick && pick.href) node = await get(pick.href);
  } catch { /* fall through to conventional paths */ }
  if (!node) {
    try { node = await get(`${base}/nodeinfo/2.1`); }
    catch {
      try { node = await get(`${base}/nodeinfo/2.0`); }
      catch {
        throw new Error(`Couldn't read nodeinfo for ${host} — is it a Mastodon / GoToSocial / Pixelfed / Sharkey / Misskey instance?`);
      }
    }
  }

  const raw = (node.software && node.software.name) || "";
  const { software, family } = familyOf(raw);
  if (!family) throw new Error(`${host} runs "${raw || "unknown"}", which Vantage doesn't support yet`);
  return { software, family, raw: raw.toLowerCase(), version: (node.software && node.software.version) || "" };
}
