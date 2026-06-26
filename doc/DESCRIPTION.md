Vantage is a single-page, client-side Fediverse moderation console
(pending-signup triage and report review for Mastodon, GoToSocial, Pixelfed,
Pleroma, Sharkey, Misskey and Firefish) with transparent heuristic risk
scoring and keyless OSINT enrichment.

This package vendors the prebuilt standalone build — there is no server
component. It runs entirely in the visitor's browser; admin tokens and any
OSINT API keys live only in that browser's `localStorage`. It is gated behind
YunoHost's single sign-on, so only members of the permission group chosen at
install can open it.
