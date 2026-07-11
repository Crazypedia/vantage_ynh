Vantage is installed and running at __DOMAIN__.

**Signing in.** Open the site and sign in with your instance. Your instance
shows its own consent screen; Vantage requests the moderation permissions it
needs. Accounts **without** a moderation role are rejected (and their token
revoked where the instance supports it).

**Allow-list.** If you set an instance allow-list at install, only those
instances can log in. Change it later in the app's config (the
`VANTAGE_ALLOWED_INSTANCES` line in the `.env`) — leaving it empty accepts any
instance, which also lets anyone spend your shared OSINT API quotas, so setting
it is recommended.

**Secrets.** Vaulted tokens and API keys are encrypted with a master key at
`data/master.key`, generated on first start. It is included in YunoHost
backups; if you ever restore onto a fresh box, restore the backup (which carries
both the database and the key) rather than reinstalling, or every vaulted secret
becomes unreadable.

**Optional SSO outer gate.** By design Vantage is public and authenticates users
against their instance. If you'd rather only YunoHost portal users even reach
the login screen, set `sso = "true"` in the manifest, pick a permission group,
and uncomment the `yunohost_panel.conf.inc` include in the nginx config.
