#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
docker run --rm --network none --read-only --tmpfs /tmp:rw,nosuid,size=128m otherwise-solo:reference sh examples/solo.sh
