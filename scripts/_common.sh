#!/bin/bash

#=================================================
# COMMON VARIABLES AND CUSTOM HELPERS
#=================================================

# Node.js version installed via the ynh_nodejs_* helpers. Vantage's server uses
# node:sqlite (DatabaseSync), which is only dependable on Node 22.5+ and fully
# stable on 24 — pin 24.
nodejs_version=24

#=================================================
# PERSONAL HELPERS
#=================================================

# Deploy the vendored, prebuilt server bundle into $install_dir.
#
# Vantage has ZERO runtime dependencies (node:http / node:sqlite / node:crypto
# only) and its UI is a single prebuilt dist/index.html, so there is nothing to
# npm-install or compile on the server — we just lay down the files that
# `npm run pack` vendored under sources/.
_vantage_deploy_bundle() {
    local dest="$1"

    # server/ (the process), dist/index.html (the built UI), package.json, docs/.
    cp --recursive ../sources/bundle/. "$dest/"

    chown -R "$app:www-data" "$dest"
    chmod -R o-rwx,g-w "$dest"
}
