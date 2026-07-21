# Vantage for YunoHost

Node + systemd package for the self-hosted **Vantage** Fediverse moderation
console. Not submitted to the YunoHost catalog (private upstream) — for
self-hosting only.

## This directory is a template

The hand-written package lives here. The **installable** package is produced by
`npm run pack` from the repository root, which builds the UI, vendors the
zero-dependency server bundle under `sources/bundle/`, and writes the whole
thing to `dist-ynh/`. Do not vendor the bundle by hand.

```bash
npm run pack            # → dist-ynh/  (packaging + vendored server bundle)
```

## Deploying

From a machine with the YunoHost admin CLI, install straight from the assembled
directory (or a git repo you push `dist-ynh/`'s contents to):

```bash
yunohost app install /path/to/dist-ynh -a "domain=vantage.example.org&path=/&allowed_instances=example.org&seed_admin_host=example.org"
```

`seed_admin_host` is required: the first moderator who logs in from that
instance becomes this deployment's Global Admin (see `doc/POST_INSTALL.md`).

Vantage serves its routes at the origin root, so install it on its own
(sub)domain at path `/`. See `doc/POST_INSTALL.md` for sign-in, the allow-list,
Global Admin, and backup/secret notes, and the repo's `docs/server.md` for the
full config reference.
