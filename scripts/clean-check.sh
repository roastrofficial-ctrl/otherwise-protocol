#!/bin/sh
# Validate an independent clone, without linking Git objects or retaining its origin.
set -eu
cd "$(dirname "$0")/.."
REF=${1:-v0.1.0-alpha.1}
RELEASE_ROOT=$(pwd)
CLEAN_DIR=$(mktemp -d "${TMPDIR:-/tmp}/otherwise-clean.XXXXXX")
trap 'rm -rf "$CLEAN_DIR"' EXIT HUP INT TERM
EXPECTED=$(git rev-parse "$REF^{commit}")
git -c advice.detachedHead=false clone --quiet --no-local --no-hardlinks --branch "$REF" "$RELEASE_ROOT" "$CLEAN_DIR/repository"
cd "$CLEAN_DIR/repository"
test "$(git rev-parse HEAD)" = "$EXPECTED"
git remote remove origin
CLEAN_BUILD=1 ./scripts/check.sh
./scripts/demo.sh
