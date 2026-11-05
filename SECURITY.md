# Security policy

## Supported scope

`v0.1.0-alpha.1` is an experimental, synthetic-only protocol reference. It is not approved for real sensitive content or production custody. There is no security audit, service availability promise, response-time guarantee or bounty. Use the latest reviewed alpha when reproducing reports; protocol compatibility remains exactly as documented in [SPEC.md](SPEC.md).

## Report privately

Once this repository is published and its maintainer enables GitHub private vulnerability reporting, use this repository's **Security → Advisories → Report a vulnerability** action:

[Private vulnerability report](https://github.com/roastrofficial-ctrl/otherwise-protocol/security/advisories/new)

If that action is unavailable, open an issue titled **Private security contact requested** with contact instructions only. Do not include vulnerability details, personal information, plaintext, private keys or live credentials. This policy does not depend on another project's reporting channel. Enabling private reporting is part of the publication checklist, not something this local preparation has already done.

Include release tag/commit, platform, exact command, affected verification stage, expected versus actual behavior, and a minimal synthetic reproducer. Do not submit real customer data. Confirmed security fixes should preserve protocol compatibility or explicitly document a new version.

## Deliberate limitations

The custodian has the content key and can decrypt early. It can censor participation, sign incompatible histories, lie about time, withhold a release or lose indispensable state. Signatures prove that a key signed a recorded claim, not that the operator behaved honestly. An undetected complete-looking fork is possible without a surviving contradictory anchor.

Attempted participation is not accepted participation. Network censorship or exhausted capacity can leave an unchanged lease eligible later. There is no indefinite continuity, automatic rollover, key rotation, trustee recovery or product-account authority substitution. Lost creator keys prevent new check-in/disarm; stolen copies retain that authority. Lost recipient keys prevent normal recipient decryption; stolen copies can decrypt available release packages.

Process-crash tests do not establish physical power-loss durability, truthful UTC, independent administration, long-term operations or supply-chain security. Backups and fixture keys are labelled, unencrypted test material. Tests generate disposable TLS material in temporary directories; no generated development certificate or private key belongs in a release.
