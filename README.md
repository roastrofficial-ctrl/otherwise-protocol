# Otherwise Protocol

**v0.1.0-alpha.1 · Solo v0.1 · synthetic data only**

Otherwise lets someone leave an encrypted message under a standing instruction: keep it in custody while they check in; make it available to a chosen recipient after check-ins stop and a grace period passes.

This repository contains an independently usable protocol specification, a Python reference engine and CLI, an independently written PHP verifier, and portable conformance fixtures. You can build and demonstrate it with Docker. No account, hosted service, parent repository or project-specific setup is required.

## Trust comes first

Solo has **one creator, one recipient and one explicitly trusted custodian**. The custodian receives the content key. **It can decrypt early**, conceal an accepted check-in, fork its history, refuse release or disappear if malicious. Signatures let a verifier examine its recorded decisions; they **do not prove the custodian was honest**, its clock accurate, the creator physically present, or that no earlier disclosure occurred.

This alpha is a protocol/reference implementation for synthetic experiments. It is not reviewed production custody software. There is no real email, SMS or public disclosure destination, arbitrary-message creation UI, production vault, key rotation or account-reset authority. The reference creates and accepts one fixed synthetic message.

## Quick start

You need Git, Docker with Linux containers, a POSIX shell, internet access during image builds, and enough Docker memory for the full-history tests (2 GiB recommended). Runtime containers use disabled networking, read-only root filesystems and temporary state. Linux arm64 and amd64 dependency locks are included; the release report identifies which platforms were actually exercised.

After this repository is published:

```sh
git clone https://github.com/roastrofficial-ctrl/otherwise-protocol.git
cd otherwise-protocol
git checkout v0.1.0-alpha.1
./scripts/check.sh
./scripts/demo.sh
```

The same commands work from an unpacked source archive. Builds download only committed, hash-checked dependency versions. `check.sh` runs the complete Python suite and the independent PHP-only image. `demo.sh` demonstrates actual creation, activation, accepted participation, expiry, release, explicit export, Python verification and PHP verification. It also demonstrates disarming a separate Capsule and restoring synthetic key backups. You should see `VALID`, `COMMITTED` and `DECRYPTED` for the released Capsule, and `DISARMED` for the cancelled one. A failed assertion exits nonzero.

To force fresh image layers:

```sh
CLEAN_BUILD=1 ./scripts/check.sh
```

The demo's `--synthetic-now` values are an explicit test clock; it does not wait real minutes. Generated private keys, TLS certificates and databases live only in temporary container storage and are removed afterward. Nothing is sent to a disclosure destination.

## The lifecycle

```text
create → ARM → accepted CHECKIN → renewed deadline
                       ↓ missed deadline
                     GRACE → ELIGIBLE → durable RELEASE → export → recipient verification
                       └──────── DISARM before RELEASE commitment ───────→ DISARMED
```

For an acceptance time `a`, interval `I` and grace `G`, the deadline is `a + I`. Check-in can renew through the inclusive last second `a + I + G`. Release becomes eligible only after that second. Eligibility alone authorizes no export: the custodian must atomically commit RELEASE with the exact recoverable recipient package and ciphertext. Disarm can win until that durable terminal commitment. A lost response means uncertainty; it does not undo accepted participation or commitment. Only a verified receipt for the exact request supports an acknowledgement.

The journal has 10,000 event slots; the final slot is reserved for DISARM or a policy-eligible RELEASE. Clients warn when at most 100 ordinary check-ins remain. Capacity exhaustion rejects further renewal without changing the existing deadline or independently authorizing release. **Solo v0.1 offers no indefinite-continuity guarantee.**

## Python reference

`reference/python/otherwise_solo` separates encoding, crypto, deterministic replay, custody persistence, clocks, client, transport and backup helpers. It can be installed as `otherwise-solo-reference==0.1.0a1` from this source tree; no package-index publication is implied. Docker installs and tests the package outside the checkout import path.

```sh
docker run --rm --network none otherwise-solo:reference otherwise-solo --help
```

CLI commands include `init-custodian`, `init-identities`, `create`, `act arm|checkin|status|disarm|release|export`, and `verify`. See the runnable [demo](examples/solo.sh) and [implementation guide](docs/IMPLEMENTATION.md). The real-clock adapter starts unqualified; the demonstration deliberately uses a controlled clock. SQLite is a reference persistence choice, not protocol truth defined by a particular database product.

## Independent PHP verifier

`reference/php/verifier.php` independently parses/canonicalizes objects, checks signatures and commitments, replays lifecycle, and verifies/decrypts recipient material. It does not call Python. It requires 64-bit PHP, ext-sodium, OpenSSL, and CLI FFI access to Sodium's point-validation API; the supplied image configures these.

```sh
docker run --rm --network none --read-only otherwise-solo:php
```

This verifies the fixed corpus and refuses to run if a Python interpreter or reference implementation is present. Both languages use the Sodium implementation family; this is independent protocol logic, not independent cryptographic-library assurance. The [demo](examples/solo.sh) also submits its newly generated export to the PHP verifier, rather than verifying only a prebuilt fixture.

## Specification and conformance

The alpha implements spec revision `0.1-draft.2`, profile `otherwise.solo.v1` and the existing v1 suite. Package, spec, wire, suite and corpus versions are distinct. The alpha does not change the approved wire bytes or policy rules. Unknown versions are refused without downgrade. Activated instructions are immutable; changing keys, content or policy requires a new Capsule and separately disarming the old one.

Start at [SPEC.md](SPEC.md). [CONFORMANCE.md](CONFORMANCE.md) describes the 88 fixed verifier fixtures, four stateful scenarios (30 operations), deterministic fixture generation and adversarial experiments. The suites cover grace boundaries, replay, false acknowledgements, races, process death, torn uncommitted persistence, exact release recovery, the real history limit, key restoration, transport substitution, and offline verification. Schema checks validate the published JSON Schema against positive artifacts; schemas alone cannot authorize release.

| Read next | Purpose |
|---|---|
| [Release notes](RELEASE_NOTES.md) | Capabilities, compatibility, known attacks and limits |
| [Release report](docs/RELEASE_REPORT.md) | Exact executed commands, versions, results and failures |
| [Threat model](docs/SOLO-THREAT-MODEL.md) | What the trusted-custodian assumption means |
| [Security policy](SECURITY.md) | Supported scope and private reporting |
| [Dependency provenance](THIRD_PARTY_NOTICES.md) | Licence sources, hashes and build inputs |
| [Release checklist / publishing](docs/RELEASING.md) | Local verification and explicit publication commands |

Historical design rationale is retained under `docs`; it is optional reading. Every build, demo, test, normative specification and security-reporting path belongs to this repository. No research checkout, Laravel application, PorterNet integration or SaaS code is needed.

[Apache-2.0](LICENSE). Copyright 2026 Levi Godolphin. Third-party components retain their own licences; see [NOTICE](NOTICE).
