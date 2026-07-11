/* ============================================================
   Vantage server — static UI serving (hosted-design §3)
   The server serves the built UI itself — the browser talks only
   to Vantage, same-origin. Prefers dist/index.html (written by
   scripts/build.mjs); falls back to the newest standalone
   deliverable in the repo root so a fresh checkout still runs.
   ============================================================ */
import { readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { join } from "node:path";

export function findUiFile(root) {
  const dist = join(root, "dist", "index.html");
  if (existsSync(dist)) return dist;
  const candidates = readdirSync(root)
    .filter((f) => /^Vantage Admin \(standalone\).*\.html$/.test(f))
    .map((f) => ({ f, mtime: statSync(join(root, f)).mtimeMs }))
    .sort((a, b) => b.mtime - a.mtime);
  if (candidates.length === 0) return null;
  return join(root, candidates[0].f);
}

export function makeStatic(root) {
  const path = findUiFile(root);
  if (!path) throw new Error("no built UI found — run `npm run build` first");
  const html = readFileSync(path); // read once at startup; restart after rebuild

  function serveUi(req, res) {
    res.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
      "Content-Length": html.length,
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
      "Cache-Control": "no-cache",
    });
    res.end(html);
  }

  return { serveUi, uiPath: path };
}
