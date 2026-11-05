#!/bin/sh
# Local packaging only. This script never publishes or pushes.
set -eu
cd "$(dirname "$0")/.."
RELEASE_TAG=${1:-v0.1.0-alpha.1}
test "$RELEASE_TAG" = v0.1.0-alpha.1
test -z "$(git status --porcelain)"
test "$(git rev-parse "$RELEASE_TAG^{commit}")" = "$(git rev-parse HEAD)"
RELEASE_EPOCH=$(git log -1 --format=%ct "$RELEASE_TAG")
mkdir -p dist
RELEASE_DIST=$(pwd)/dist
git archive --format=tar --prefix="otherwise-protocol-$RELEASE_TAG/" "$RELEASE_TAG" | gzip -n > "dist/otherwise-protocol-$RELEASE_TAG.tar.gz"
docker run --rm --network none --read-only --tmpfs /tmp:rw,nosuid,size=128m \
  --env SOURCE_DATE_EPOCH="$RELEASE_EPOCH" \
  --mount "type=bind,source=$RELEASE_DIST,target=/out" otherwise-solo:reference sh -ec '
    mkdir /tmp/source
    tar -xzf /out/otherwise-protocol-v0.1.0-alpha.1.tar.gz -C /tmp/source --strip-components=1
    python -m pip wheel --no-index --no-deps --no-build-isolation --wheel-dir /out /tmp/source
    python - <<"PY"
import hashlib
from pathlib import Path
r=Path("/out")
files=sorted(list(r.glob("*.whl"))+list(r.glob("*.tar.gz")))
(r/"SHA256SUMS").write_text("".join(hashlib.sha256(p.read_bytes()).hexdigest()+"  "+p.name+"\n" for p in files))
print((r/"SHA256SUMS").read_text(),end="")
PY
  '
