# v0.1.0-alpha.1 release preparation report

Prepared 5 November 2026. This report records executed preflight validation and the release-engineering scope. Final commit/tag/clean-clone verification is also supplied in the handoff and ignored `dist/` evidence, rather than treating a documented command as a test result.

## Scope and compatibility

The repository began with an unborn `main` branch: zero commits, blobs and tags. No existing public history was rewritten. All reference runtime source is unchanged from the approved Solo implementation except `otherwise_solo.__version__ = '0.1.0a1'`; all existing fixture JSON and schema bytes are unchanged. `tests/test_release.py` verifies the committed baseline. Specification prose was edited to remove obsolete procedural gates and clarify existing validation precedence, without changing fields, rules or identifiers.

This release adds documentation, a complete same-Capsule synthetic demonstration, dependency/provenance locks, schema/package compatibility checks, audit/packaging tools and local release metadata. No research/SaaS source, new crypto feature, hosted service, key rotation or custody model was introduced. The security-reporting policy uses this repository's future GitHub channel, not another project. Historical rationale links are optional reading and are not dependencies.

## Commands actually executed (preflight)

```sh
CLEAN_BUILD=1 ./scripts/check.sh
./scripts/demo.sh
python3 scripts/audit.py --json /tmp/otherwise-alpha-audit-pre.json
```

The first command was run with Docker output redirected to `/tmp/otherwise-alpha-first-build.log`; the same `examples/solo.sh` invoked by `demo.sh` was executed in the read-only, network-disabled reference container with output recorded in `/tmp/otherwise-alpha-demo.log`. Committed evidence copies are in `docs/evidence/alpha/`.

| Check | Actual preflight result |
|---|---|
| Python/Docker complete suite | **37 methods passed in 42.338 seconds** |
| Independent PHP-only image | **88 cases; 0 disagreements**; startup rejects a Python interpreter/reference |
| Existing fixed fixture regeneration | Exact byte equality passed |
| Portable stateful scenarios | Four scenarios / 30 operations passed |
| Actual capacity limit | 10000-event terminal boundary passed in Python/PHP |
| Crash/race/recovery | Process deaths, torn uncommitted WAL, corrupt material refusal, lost replies and competing workers passed |
| New public schema/package checks | Draft 2020-12 schema, positive fixture/results validation, installed alpha version and approved-byte compatibility passed |
| Updated end-to-end demo | Check-in at 1060, grace observation at 1121, RELEASE at 1131, explicit export and independent PHP `VALID / COMMITTED / DECRYPTED` passed |
| Initial included-file audit | Zero unresolved findings; deterministic fixture/private fields and required public attribution are explicit exceptions |
| Apache licence verification | Included LICENSE byte-equal to the publisher's canonical Apache-2.0 text |

Tests ran in Linux arm64 containers on Docker Desktop 27.2.0. amd64 Debian dependencies were separately resolved/downloaded under emulation; this alone is not an amd64 full-suite pass. No native-host suite, public GitHub Actions run, third-party security audit, physical power-loss test or external delivery test is claimed.

## Exact preflight runtime

- Python 3.12.16 (GCC 12.2.0); SQLite 3.40.1.
- cryptography 46.0.3, bundled OpenSSL 3.5.4; PyNaCl 1.6.2.
- PHP 8.2.35; native Sodium 1.0.18; native OpenSSL 3.0.22.
- cffi 2.1.1; pycparser 3.12. Build/schema dependencies and native packages are recorded in the provenance manifests/locks.
- Spec `0.1-draft.2`; profile `otherwise.solo.v1`; unchanged v1 suite and corpus IDs.

## Failures and recoveries

1. The public Debian snapshot lookup returned HTTP 503. It was not used as a floating fallback. Exact Debian package URLs/SHA-256 locks were resolved from signed metadata and used successfully.
2. A concurrent amd64/arm64 pull hit Docker Desktop's `cannot overwrite digest` image-store error. Resolving the immutable platform-specific amd64 digest allowed its dependency-lock preparation to complete. This was setup, not a conformance failure.
3. The first audit pattern flagged its own certificate-detection string. Requiring a complete PEM certificate block removed that false positive without excluding source files from inspection. The re-run had no findings.

4. Git whitespace checking reported trailing spaces in verbatim upstream licence files. The files were preserved byte-for-byte and `.gitattributes` scopes normalization/style checks appropriately; upstream notices were not edited.

No preflight conformance test failed. These setup/audit failures are retained here rather than hidden. Later final-clone/packaging failures, if any, must be reported with their actual outcome before publication.

## Audit and licence scope

The audit examines every included file and all local Git blobs/commit/tag objects, including unreachable objects. It checks private-artifact filenames, complete PEM keys/certificates, common credential-token forms, private home paths, unexpected contact addresses and structured private-key fields. It never prints matching secret bytes. Deterministic fixture material is retained only in explicitly labelled corpus files and reproducible generators. Generated demo keys/certificates/databases remain temporary. The Git author/tagger uses an intentional public GitHub noreply address, rather than the configured work email.

Required copyright attribution and public third-party licence contacts are intentional public information. `THIRD_PARTY_NOTICES.md`, supplied licence copies and provenance manifests document all Python inputs and selected native inventories; full native notices remain in the built images. This is a bounded pattern/structure/provenance review, not proof that every conceivable secret or dependency vulnerability has been excluded.

## Known limits

The custodian can decrypt early, falsify recorded claims, fork, censor, refuse release or lose state. Signed evidence does not prove honesty. Capacity does not itself authorize release, but inability to renew can leave the existing lease eligible. There is no indefinite continuity, lost-key account reset, production vault, real delivery or production security review. Dependency pins do not guarantee permanent artifact availability or byte-identical OCI images. See RELEASE_NOTES.md and the threat model for the full declared boundary.

## Executed independent-clone validation

`./scripts/clean-check.sh main` was executed against candidate commit `17457b6`, using a fresh clone with Git hardlinks disabled and its origin removed. It rebuilt without Docker layer reuse, passed **37 Python methods in 41.938 seconds**, passed **88 PHP cases with zero disagreements**, and completed the new synthetic demo including independent PHP verification. The complete relevant output is retained in [clean-clone evidence](evidence/alpha/clean-clone.txt). Subsequent candidate edits are release documentation/attributes/evidence only; final-tag checks are also recorded in the handoff.
