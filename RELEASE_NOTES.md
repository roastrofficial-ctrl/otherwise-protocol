# v0.1.0-alpha.1 — Otherwise Protocol Solo

First standalone public alpha release candidate, prepared 5 November 2026. Publication remains pending maintainer approval.

## Capabilities

- One creator, one encrypted synthetic Capsule, one recipient and one explicitly trusted custodian.
- Immutable standing instruction; acceptance-based rolling participation and inclusive grace.
- Durable signed receipts, exact-request retry, fresh inspection and portable evidence.
- A precise disarm/release race: one durable terminal event wins.
- Exact committed release archive/ciphertext recovery after tested crashes, restarts and lost replies.
- Standalone Python engine/CLI, independently authored PHP verifier, two transport adapters and schema aids.
- A complete runnable synthetic lifecycle, explicit export, offline Python/PHP verification and backup restoration.
- 88 fixed verifier fixtures, four portable lifecycle scenarios, full-history boundary tests and adversarial crash experiments.

## Compatibility

Git tag `v0.1.0-alpha.1` maps to Python package version `0.1.0a1`. Spec remains `0.1-draft.2`; wire/profile remains `otherwise.solo.v1`, `v=1`; suite remains `ed25519-sha256-aes256gcm-sodiumseal-v1`; corpus identifiers remain `solo-0.1.0` and `solo-lifecycle-0.1.0`. Existing fixture bytes and runtime protocol logic are preserved; the package version marker is the only reference-runtime source change in this release-engineering pass. No new cryptographic feature, custody model or authorization path is added.

Unknown profile/version/suite is refused. Armed policy, recipient, keys and content cannot be silently amended. Experimental alpha status is not a promise of future wire compatibility: any later semantic change requires an explicit reviewed version decision.

## Known attacks and limits

A malicious custodian can decrypt early using its retained key, fabricate recorded time, suppress acceptance, sign conflicting histories, refuse release or delete storage. Signed release evidence proves a recorded decision under a pinned key; it does not prove honesty or lack of earlier disclosure. Independently retained contradictory evidence can expose some forks; it cannot guarantee global completeness.

Creator-device compromise permits authentic participation/cancellation. Recipient-key compromise permits decryption of available packages. Key loss is not repairable by account reset. Censorship of otherwise valid attempted participation can lead to release under the recorded instruction. Capacity exhaustion is not a release predicate, but it can prevent further renewal and leave the existing deadline unchanged. There are 10,000 journal slots, and no indefinite-continuity or rollover guarantee.

The reference's fixed-message admission guard is a laboratory restriction before activation. There is no real destination, arbitrary-message ingestion, production vault, rotation, trustee recovery, hosted infrastructure or SaaS integration. Clock qualification, hardware durability, client distribution, operator continuity and external review remain production work. Python/PHP share the Sodium family; PHP requires FFI and 64-bit integers. File transport and HTTPS have different operational assumptions.

## Reproduction and audit

Run `./scripts/check.sh` and `./scripts/demo.sh` from this repository alone. Build inputs use pinned base digests and hash-checked Python/Debian downloads; upstream availability and the limits of binary reproducibility are documented in [BUILDING.md](docs/BUILDING.md). See [the release report](docs/RELEASE_REPORT.md) for commands actually executed, exact versions, outcomes, failures and scope. Secret/history inspection and dependency licence provenance are documented there and in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

No independent external security audit or unexecuted platform test is implied by this alpha. No public push, GitHub release, package-index upload or deployment was performed during local preparation.
