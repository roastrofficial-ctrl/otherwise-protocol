# Reproducing the alpha

The ordinary developer path needs Git, Docker/Linux containers, a POSIX shell, internet access during builds, and enough Docker memory for the capacity tests. Run `./scripts/check.sh`, then `./scripts/demo.sh` from this repository. Test/demo containers have networking disabled. A package-index upload or hosted service is not needed.

## Frozen inputs

- Dockerfiles pin the multi-platform Python/Debian base digests, rather than trusting a mutable tag.
- `requirements.lock` freezes runtime dependencies, `requirements-build.lock` build tools, and `requirements-test.lock` schema-check tools. Every accepted wheel has a version-specific public PyPI SHA-256. Binary-only, hash-required installation refuses unlisted content.
- `build/debian/{arm64,amd64}.lock` freezes complete native dependency downloads for each included platform. The locks were resolved using signed Debian metadata and verified downloads. The installer checks SHA-256 on each exact public `.deb` and performs no floating index resolution during a build.
- The PyPI and Debian provenance manifests and retained third-party notices document the actual inputs.
- The reference version is `0.1.0a1`; the Git release name is `v0.1.0-alpha.1`. Wire/spec/suite/corpus identifiers remain unchanged.

The public Debian snapshot endpoint was unavailable during preparation. Exact, hash-verified package URLs were used instead; no unpinned fallback is implemented. Upstream repositories can remove an old artifact. Such a build fails closed rather than selecting a new version. This alpha does not promise perpetual upstream availability.

## Clean validation

```sh
CLEAN_BUILD=1 ./scripts/check.sh
./scripts/demo.sh
```

`CLEAN_BUILD=1` disables image-layer reuse. It does not prune your Docker daemon or other projects. The release handoff also validates an independent local Git clone of the final tag with its origin removed. The exact executed platforms, versions and outcomes belong in [RELEASE_REPORT.md](RELEASE_REPORT.md); an included dependency lock alone is not evidence that a platform was tested.

The reference Docker image runs all Python tests, invokes PHP independently, checks fixture regeneration and JSON Schema, and verifies installed-package operation outside the checkout import path. The PHP-only image contains no Python reference/interpreter and rejects their presence before verifying the corpus. Source code does not import any parent project or optional communication service.

## Native Python (optional)

Docker is the tested default. If independently setting up Python 3.12+, a virtual environment can install the same locks:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --only-binary=:all: --require-hashes --no-deps \
  -r requirements.lock -r requirements-build.lock -r requirements-test.lock
python -m pip install --no-deps --no-build-isolation .
otherwise-solo --help
```

The complete suite also requires the documented native PHP/Sodium/FFI/OpenSSL setup; installing Python alone does not reproduce the separate PHP environment. No native-host test pass is claimed by these instructions.

## Artifacts and reproducibility limits

After the reviewed commit is tagged, `./scripts/package-release.sh v0.1.0-alpha.1` creates an ignored `dist/` source archive, Python wheel and SHA256SUMS. Source archives come from the exact Git tag, exclude Git metadata/untracked files, and use `gzip -n`. Wheel timestamps use the tag commit's `SOURCE_DATE_EPOCH`. Repeating packaging with the same tag/toolchain should reproduce those artifacts; the release report states whether that comparison was actually run.

Pinned inputs and stable fixtures support functional reproduction. OCI image digests are not promised to be byte-identical across Docker/BuildKit versions, platforms, package maintainer scripts or host configurations. Runtime identities and demo archives intentionally use fresh randomness, so their hashes vary between demos while decisions and fixture bytes remain reproducible. Single-host tests do not establish WAN timing, physical power-loss durability or production security.

Dependency changes require reviewed lock regeneration and the complete interoperability suite. `scripts/lock-python.py` consumes a pip JSON resolution report and version-specific public PyPI metadata; `scripts/resolve-debian.sh` is a maintenance-only resolver intended for an empty pinned Debian container. Neither runs during normal protocol use. Retain provenance and supplied notices when updating locks.
