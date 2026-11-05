#!/bin/sh
set -eu
if command -v python >/dev/null 2>&1 || command -v python3 >/dev/null 2>&1; then
  echo 'Independent PHP image unexpectedly contains Python' >&2
  exit 1
fi
test ! -d reference/python
exec php -d ffi.enable=true reference/php/verifier.php --corpus conformance/vectors.json
