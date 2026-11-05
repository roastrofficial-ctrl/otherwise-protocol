#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
if [ "${CLEAN_BUILD:-0}" = 1 ]; then
  docker build --no-cache -t otherwise-solo:reference .
  docker build --no-cache -f Dockerfile.php -t otherwise-solo:php .
else
  docker build -t otherwise-solo:reference .
  docker build -f Dockerfile.php -t otherwise-solo:php .
fi
docker run --rm --network none --read-only --tmpfs /tmp:rw,nosuid,size=512m otherwise-solo:reference
docker run --rm --network none --read-only --tmpfs /tmp:rw,nosuid,size=128m otherwise-solo:php
