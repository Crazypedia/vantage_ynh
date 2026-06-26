## Granting access to someone outside your YunoHost users

Vantage is gated by the permission group chosen at install (default
`admins`). To let someone else (e.g. an outside moderator) view it without
giving them any other admin access:

1. **Users > Groups**: create a group (e.g. `vantage`) if you don't already
   have one scoped to just this app, and add their user account to it.
2. **Users > [this app's permission]**: set the allowed group to that group.
3. Send them the app's URL. They'll hit the YunoHost SSO login first.

## Updating the build

This package has no upstream download source — it vendors a prebuilt
`sources/index.html` directly in the package repo. To ship a new build:

1. In `fediDash`, run `npm run build`.
2. Copy the generated `Vantage Admin (standalone) (*).html` over
   `sources/index.html` in this repo (rename to `index.html`).
3. Bump `version` in `manifest.toml`.
4. Commit and push, then use the YunoHost admin dashboard's "force upgrade"
   (or `yunohost app upgrade vantage`) to pull and redeploy it.

## Taking it down when not needed

`yunohost app remove vantage` removes the nginx config and install
directory. Re-running the install script later restores it from the same
vendored build.
