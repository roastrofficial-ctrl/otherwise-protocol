#!/bin/sh
# Maintenance only: resolve signed APT metadata into immutable download hashes.
# Run inside a fresh pinned Debian base with /out mounted to an empty directory.
set -eu
apt-get update > /tmp/apt-update.log
apt-get --yes --print-uris install --no-install-recommends php-cli php-common libsodium23 openssl ca-certificates > /out/uris.txt
apt-get --yes --download-only install --no-install-recommends php-cli php-common libsodium23 openssl ca-certificates > /tmp/apt-download.log
sha256sum /var/cache/apt/archives/*.deb > /out/sha256.txt
