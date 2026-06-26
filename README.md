# Vantage (YunoHost package)

Self-hosted deployment of [Vantage](https://github.com/Crazypedia/fediDash)
behind YunoHost's SSO, for sharing the live console with someone (e.g. an
outside moderator) without them needing to set anything up themselves.

No server component, no `nodejs`/`ports`/`systemd` resources — this package
just serves a vendored prebuilt `sources/index.html` (see `doc/ADMIN.md` for
how to refresh it) through nginx, with the YunoHost SSOWAT panel enforcing
login.

Pair it with [`cac-proxy_ynh`](https://github.com/Crazypedia/cac-proxy_ynh)
for the keyed OSINT lookups (AbuseIPDB/VirusTotal/IPQS) — add this app's
domain to the proxy's `cors_allowed_origins` setting after both are
installed.
