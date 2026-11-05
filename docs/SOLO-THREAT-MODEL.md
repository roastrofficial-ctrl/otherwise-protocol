# Solo threat model

Release status: Solo v0.1 as specified by `0.1-draft.2`, included in `v0.1.0-alpha.1`. See [SPEC](../SPEC.md). Historical design/approval notes below are rationale; they add no build or runtime dependency.
Alpha threat model. The claim is accountable conditional custody by a **trusted single custodian**, not cryptographic enforcement against that custodian.

## Principals and assumptions

The creator trusts an independently obtained client, its OS/randomness, authenticated public-key pins and local backup handling. The recipient similarly trusts its own client, secret key and authenticated expected identities. A browser delivered by a malicious SaaS cannot protect a signing seed or plaintext from that SaaS. A locally installed CLI is a proposed independent path, not automatic supply-chain security.

The custodian is trusted to obey acceptance/lifecycle rules, retain protected keys and complete durable history, serialize operations, use its declared healthy clock, avoid early disclosure and make promised services available. A shared SaaS/custodian administrator collapses the separation. TLS endpoint authentication, protocol key authentication and operator honesty are separate assumptions. An encrypted database backup does not prove complete retained order or prevent an authorized administrator reading it.

The network and SaaS may drop, delay, replay, reorder, replace and censor all messages and UI status. They cannot forge uncompromised creator/custodian signatures or decrypt sealed boxes/content without keys under the primitives' assumptions. Denial of service can cause real release under the recorded absence policy: attempted presence is not accepted presence. The protocol cannot prove a person is alive, dead, incapacitated, acting voluntarily or reading a message.

## Claims and boundaries

| Claim under stated honest-custodian assumptions | What is not established |
|---|---|
| Accepted creator participation renews the exact bound Capsule | Physical presence or objective truth of an attestation |
| Durable receipt survives a lost reply and is independently verifiable | A malicious custodian cannot later deny or fork the fact |
| Disarm and release cannot both occur in one valid history | A malicious custodian cannot sign two conflicting histories |
| Honest provider refuses release before policy/grace and after disarm | Administrator cannot decrypt early or ignore the provider |
| Portable recipient package binds policy, ciphertext and recorded authorization | Complete global history, accurate UTC, no earlier decrypt or disclosure |
| SaaS loss does not change custodian facts | Custodian availability, restored keys, alternative network routes or recipient key survival |
| Replay and substitution fail verification | Account recovery can revoke a stolen creator seed |

## Concrete adversarial expectations

| Attack | Expected handling / remaining limit |
|---|---|
| SaaS displays forged “check-in succeeded” | Trusted client requires verified retained receipt; an untrusted page can still lie to its viewer |
| Ciphertext, policy, recipient, creator or custodian substituted | Independently pinned identity, descriptor signature, hD, event scope and AEAD checks reject |
| Old accepted CHECKIN replayed | Same committed event returned; deadline does not move again |
| Previously unseen stale CHECKIN delivered | Wrong basis or expired grace rejects; signing time does not backdate |
| Old DISARM delivered before terminal release | Intentionally remains authentic cancellation authority for that Capsule |
| Two release workers race or restart | One durable terminal append and the same persisted release material |
| Custodian accepts check-in but response disappears | Check-in remains effective; client reports uncertainty and retries/inspects |
| Cached signed status replayed | Fresh random challenge plus client timeout rejects it as current evidence |
| Custodian omits a known accepted event | Retained anchor detects conflict; no release can be verified against that conflicting snapshot |
| Custodian omits an event nobody else retained | A locally valid alternate history may be undetectable; no witness or transparency log exists |
| Custodian forges its time or directly exports DEK | Violates trust model and succeeds; signatures cannot prevent it |
| Creator device stolen | Attacker may check in indefinitely or disarm; no per-command revocation or recovery administrator |
| Recipient key lost/stolen | Loss blocks recovery; theft enables decryption of retained release packages |
| Entire custodian state/keys lost | No hidden SaaS truth or reconstructed authority; service may be unrecoverable |

The future test suite must retain successful malicious-custodian early decryption as a limitation demonstration, not an expected rejection. A threat-model exception must not be reported as a fixed vulnerability.

## Disappearing SaaS and replacement clients

An independently retained creator recovery set comprises creator key, signed descriptor, ciphertext or an independently retained copy, custodian endpoint/trust configuration, accepted commands and receipts/anchors. Creator key material must never require Cloud login to unlock by protocol definition. Custodian APIs must expose signed receipt recovery, inspection, mutation and archive export directly. Product metadata may disappear completely.

With SaaS and its database unavailable, a standalone client must recover the accepted head, create a fresh head-bound check-in, verify/retain its receipt, and submit cancellation. A public worker with only descriptor/ciphertext and custodian reachability can ask the custodian to evaluate release; it has no creator authority. Recipient verifies the resulting archive offline with its private key and independent trust pins.

This depends on surviving custodian state/key/time, reachable alternative transport, authentic endpoint configuration and creator/recipient capabilities. If the custodian disappears too, receipt verification remains possible locally, but accepting a new check-in/disarm or autonomously creating an honest new release commitment is impossible in this profile. A SaaS administrator cannot fill that missing authority. No witness availability or operator-resistant custody guarantee is claimed.

## Deployment and review limits

All first implementation examples and experiments must use synthetic messages, fixture-only identities and simulated export destinations. Real public disclosure, email, SMS, production content, audited key management, long-lived organizational continuity and production hosting are outside this authorization. Docker isolation on one host is laboratory convenience, not independent administration.

External cryptographic/protocol review, independently authenticated client distribution, backup/restore drills, durable-storage testing and defensible clock operations remain necessary before production claims. These are known engineering dependencies, not proof that this proposal is secure merely because it names established primitives.

## Approved amendment boundaries

Durable release recovery includes ciphertext and the exact committed archive, not just a terminal flag. It assumes surviving storage within the provider's declared durability model; all-copy loss or malicious deletion can still make recovery impossible. Capacity exhaustion refuses renewal and must be made visible before it occurs. It is not a new release predicate, but subsequent passage of the unchanged grace deadline can still make release eligible. There is no indefinite-continuity guarantee. Synthetic key backup/restore demonstrates retained authority only; missing keys cannot be substituted by product accounts, and stolen backups retain signing/decryption capabilities.
