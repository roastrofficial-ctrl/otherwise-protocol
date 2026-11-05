# Solo conformance

Spec: `0.1-draft.2`; profile: `otherwise.solo.v1`; suite: `ed25519-sha256-aes256gcm-sodiumseal-v1`; implementation/corpus: `0.1.0a1` / `solo-0.1.0`. These version axes are separate.

`conformance/vectors.json` contains exact base64url wire input bytes, independently supplied pins/context and complete declared expected result objects. It includes 88 fixed cases covering activation, boundary time, accepted renewal, terminal order, domain/scope/substitution, strict Ed25519 encodings/subgroups, canonical JSON/base64, snapshots, historical anchors, and recipient authentication. A PHP producer supplies an independent positive release; expected decisions are declared from text instead of obtained by calling the Python verifier.

`conformance/lifecycle.json` adds four portable stateful scenarios (30 operations) with fixture identities, signed commands, injected clock context and declared acceptance/rejection/retry expectations. They cover idempotency, stale basis, expired participation, final cancellation, unhealthy clocks, restart and immutable export recovery; they do not prescribe SQLite. `conformance/generate_lifecycle.py` reproducibly creates them.

`conformance/generate.py` reproducibly regenerates the corpus; `--out PATH` permits comparison without modifying the checked-in file. Deterministic keys, nonces and ephemeral encryption exist **only in this fixture generator**. Do not reuse any fixture identity or payload key for real data. `conformance/produce.php` independently constructs its fixture using PHP Sodium/OpenSSL. `conformance/capacity.py` is a deterministic full-size history recipe, avoiding a shortened test limit or a large duplicated checked-in fixture.

Run `./scripts/check.sh` for the Docker conformance and independent PHP image. Tests also regenerate exact fixture bytes, exercise the actual 10000-event bound, kill real child processes around commits, tear uncommitted WAL data, lose acceptance/export replies, race workers, restore synthetic backups, reject false success and complete the CLI lifecycle without SaaS. The HTTPS and file/stdin adapters preserve the same commands/receipts and committed archive in the tested run; they do not promise equivalent timing or administrative isolation.

To verify fixed cases directly in the PHP-only image:

```sh
docker run --rm --network none otherwise-solo:php
```

The PHP CLI also reads one JSON harness request from stdin: `input` is base64url of exact archive bytes; `pins` contains independently authenticated `creator_key`, `custodian_key`, `custodian_box_key` and `recipient_key`; `options` can contain recipient secret, retained anchors, test time or a base64url snapshot plus expected challenge/elapsed context. The harness wrapper is not a signed protocol message. Output is the locally derived verification result. An archive is never trusted merely because its own declared keys are internally consistent.

Successful malicious-custodian early decryption and individually valid signed forks without contradictory anchors are explicit limitation experiments. A valid public authorization claim may still accompany malformed encrypted content; recipient decryption must detect that separately. Passing these experiments does not prove operator restraint, objective UTC, physical power-loss durability, indefinite continuity or production security.
