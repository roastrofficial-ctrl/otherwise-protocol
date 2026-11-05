# Historical development execution results

For the alpha release preparation and newly executed checks, see [Release report](RELEASE_REPORT.md). The following records the 29–30 October development run, not the alpha acceptance run.

Executed locally across 29–30 October 2026 (final complete run on 30 October) in Docker, using only the standalone protocol build context. No publication, deployment, real message ingestion, private SaaS import or external disclosure was performed. All runtime tests used disabled container networking; HTTPS tests used loopback and disposable certificates.

**33 test methods passed in 37.886 seconds. The 88 fixed fixtures produced zero disagreements in Python/PHP; the final separate PHP-only container also reported 88 cases, zero disagreements.** Its startup check rejects the presence of either Python interpreter or reference implementation. The installed Python library was also exercised in isolated interpreter mode outside the checkout path. These are bounded execution observations, not production timing guarantees.

## Approved amendment evidence

| Obligation | Executed evidence | Limit |
|---|---|---|
| Exact release recovery | Child process killed after event write, archive write, before commit and after commit; postcommit exports and recipient decryption recovered original bytes | Process death / SQLite durability boundary, not physical power loss |
| Torn persistence | Uncommitted WAL frames were forced to disk, child killed, final WAL tail truncated; previous accepted prefix recovered | Does not promise recovery after destruction of committed storage |
| Corrupt committed material | Changed archive BLOB detected as STORAGE_INTEGRITY; neither release reconstruction nor late disarm silently substituted a result | Checksums do not stop a malicious operator rewriting all state |
| Lost acknowledgements | Lost committed check-in response recovered via exact pending command; lost export response retried byte-identically across restart | No claim of delivery, reading or network availability |
| Competing workers | Independent processes raced release and cancellation; three release workers returned the same package; one terminal winner | Honest single-custodian SQLite serialization |
| Capacity | Real prefixes through 9899/9998/9999/10000; warning threshold, last renewal, repeated CAPACITY rejection, unchanged deadline, final held-time disarm and separately eligible release | No indefinite continuity, rollover or disclosure-on-full predicate |
| Synthetic backup | Working creator/recipient files deleted; original authority restored from an independent temporary backup; fresh check-in/disarm and offline recipient decrypt succeeded | Unencrypted labelled laboratory backups, no production vault or account-reset replacement |
| Client certainty | A valid receipt for another request rejected; accepted request with lost reply retried without a second renewal | Operator-delivered malicious UI/client code remains outside the trusted-client assumption |
| Separability | Standalone CLI without SaaS, two transport adapters, isolated installed package, PHP-only verifier without Python | Shared host is not independent administration; transports have different timing/privacy assumptions |

## Remaining negative results

The custodian decrypts the synthetic message before eligibility using its retained DEK. Both signed terminal forks can verify individually if no contradictory anchor is supplied; a retained conflicting anchor exposes the fork. Missing authority is not reinitialized automatically. Lost/wrong creator keys cannot reset authority. A stolen valid creator seed can still cancel. A recipient needs its original private key, and malformed content remains detectable even when public recorded authorization verifies. These are explicit limits, not repaired claims.

No material architectural conflict was introduced by the three amendments. The PHP reference requires CLI FFI access to native Sodium point-validation calls; this is an integration constraint, not a relaxation of strict Ed25519 rules. Both language implementations share the Sodium family, with independently written parsing, hashing orchestration and lifecycle evaluation.

## Reproduction and provenance

Run `./scripts/check.sh` from the protocol root. [Conformance log](evidence/conformance-run.txt), [standalone example](evidence/standalone-example.txt) and [source hashes](evidence/source-hashes.json) retain execution evidence. Four additional portable lifecycle scenarios exercise 30 declared command/restart/export operations. Fixed verification corpus SHA-256: `ce4702f106086d733b48795fe9f1bcf06f194b18ae6b1671fc51959e33f1f2ab`.

Tested versions: Python 3.12.16; SQLite 3.40.1; cryptography 46.0.3 / OpenSSL 3.5.4; PyNaCl 1.6.2; PHP 8.2.35 / native Sodium 1.0.18. Strict subgroup checks include the published workaround for older Sodium releases.

Local reference image: `sha256:85a0c711af035fe37b8b632923cf8d8718e334a5e8dd07341c95034487450190`. Final independent PHP image: `sha256:e8d2fa49c108db56681266299836efaf06e33d203abc39b6e54cf7a098f89d82`. Docker base tags / Debian repositories can change on rebuild; these IDs identify this execution, not a claim of hermetic reproducibility. Future builds must rerun the corpus and experiments.

The parent research implementation and its historical counterexamples were not altered. No old research passing count is counted as Solo conformance. External review, production storage/time operations, authenticated client distribution and long-term key/service continuity remain outside the demonstrated guarantees.
