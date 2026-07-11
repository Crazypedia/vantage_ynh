Vantage is a self-hosted Fediverse moderation console. Moderators sign in with
their own instance (Mastodon-family OAuth or Misskey/Sharkey MiAuth); only
accounts holding a moderation role are admitted. It triages signups and reports
with transparent, tweakable heuristic risk scoring and OSINT enrichment.

This package runs the zero-dependency Node server (`node:http` / `node:sqlite`
/ `node:crypto`): the browser talks only to Vantage, secrets are vaulted
server-side, and there is no CORS proxy. Install it on a dedicated (sub)domain.
