#!/bin/sh
# Each public .deb is authenticated by its committed SHA-256; no floating index.
set -eu
mkdir -p /tmp/otherwise-debs
while read -r filename checksum url; do
  case "$filename" in ''|'#'*) continue ;; esac
  /usr/lib/apt/apt-helper download-file "$url" "/tmp/otherwise-debs/$filename" "SHA256:$checksum"
done < "$1"
dpkg --install /tmp/otherwise-debs/*.deb
rm -rf /tmp/otherwise-debs
