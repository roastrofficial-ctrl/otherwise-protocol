# Solo Profile Proposal

Release status: Solo v0.1 as specified by `0.1-draft.2`, included in `v0.1.0-alpha.1`. See [SPEC](../SPEC.md). Historical design/approval notes below are rationale; they add no build or runtime dependency.
Status: alpha profile, spec `0.1-draft.2`, 2026-10-29. Architecture approved for the bounded synthetic reference implementation. This document, [Lifecycle](LIFECYCLE.md), [Cryptography](CRYPTOGRAPHY-PROPOSAL.md) and [Interoperability](INTEROPERABILITY.md) together define the complete candidate. If a conflict is found, report it as a specification defect; an implementation cannot silently redefine the protocol.

## Purpose and trust

One creator entrusts an encrypted message to one custodian, under a standing signed instruction: release to one pinned recipient after the creator stops renewing a lease and its grace period ends. A standalone creator client can create, activate, check in, inspect, disarm and request evaluation without a SaaS. A recipient can verify a release offline.

The custodian is trusted with the content key, authoritative acceptance, durable order and time. It **can decrypt early**, omit evidence, fork records and refuse service if malicious. A signed receipt is the custodian's accountable attestation, not proof of physical life, death, UTC accuracy or cryptographic restraint. See [Threat model](SOLO-THREAT-MODEL.md).

There is one immutable policy, not a generic contract interpreter: `rolling-presence`, with interval `I` and grace `G`. Activation or a subsequent timely accepted check-in sets deadline `D = accepted_at + I`; release becomes eligible only when trusted `now > D + G`. A check-in may renew during grace, including its last second. Once grace has passed, only disarm can prevent an otherwise eligible release before commitment. No creator-supplied timestamp backdates acceptance.

## Object conventions

The exact codec, digest and signature operations below are defined in [Interoperability](INTEROPERABILITY.md). All named fields are required unless explicitly stated otherwise. No unknown fields, optional metadata bags or extension fields are permitted. `B(n)` means canonical unpadded base64url encoding of exactly `n` bytes. `U` is an integer in `0..9007199254740991`. Byte arrays are never JSON integer arrays.

Every wire body has these fields, collectively `H`:

| Field | Exact value |
|---|---|
| `profile` | `otherwise.solo.v1` |
| `v` | integer `1` |
| `suite` | `ed25519-sha256-aes256gcm-sodiumseal-v1` |
| `kind` | Object-specific string below |

A signed envelope has exactly `{body, signature}`, with signature `B(64)`. Signatures cover the entire body using the domain specified in Interoperability. The descriptor supplies pinned keys; there are no lookup URLs or unsigned key identifiers. Request and event hashes include their signatures. A Capsule identifier is random `B(16)`, never a user account ID. The descriptor commitment `hD` is the domain-separated hash of its body, not its envelope.

## 1. Descriptor: immutable standing instruction

Body fields: `H`, with `kind = descriptor`, plus:

| Field | Type and meaning |
|---|---|
| `capsule_id` | `B(16)`, freshly generated per Capsule |
| `creator_key` | `B(32)`, Ed25519 public key |
| `custodian_key` | `B(32)`, independently authenticated Ed25519 public key |
| `custodian_box_key` | `B(32)`, independently authenticated Sodium box public key |
| `recipient_key` | `B(32)`, independently authenticated Sodium box public key |
| `interval` | Integer `60..31536000` seconds |
| `grace` | Integer `1..2592000` seconds |
| `nonce` | `B(12)`, content encryption nonce |
| `ciphertext_hash` | `B(32)`, SHA-256 of raw ciphertext including GCM tag |
| `ciphertext_size` | Integer `16..1048592`, ciphertext bytes |

The creator signs it. Purpose: bind creator authority, custodian, recipient, policy and encrypted payload into a single immutable instruction. AES associated data is formed from this body with only `ciphertext_hash` and `ciphertext_size` removed; there is no circular commitment. Payload maximum is 1 MiB plaintext. Labels and filenames are local product metadata, not protocol input. There is no public plaintext hash that would aid guessing small messages.

Before activation the creator may discard the draft and generate another descriptor. An existing Capsule ID cannot name a different descriptor at the same custodian. After activation, changing any policy, key, recipient or content requires disarming the old Capsule and creating a new ID. Draft signing alone does not activate custody. Verify exact field set, ranges, keys, signature, expected independently authenticated identities and ciphertext commitment. Conformance: descriptor substitution, wrong authority, nonce/size/range failures, immutable-ID conflicts and authenticated encryption.

## 2. Creator command: activation, participation or disarm

Body fields: `H`, `kind = command`, `capsule_id`, `descriptor_hash` (`B(32)`), `request_id` (fresh random `B(16)`), `action` and `basis`. Creator signs every command.

| `action` | `basis` | Additional fields | Meaning |
|---|---|---|---|
| `ARM` | JSON `null` | `enrollment_box`: `B(112)` | Request activation and custody of the content key |
| `CHECKIN` | `B(32)`, current event hash | None | Renew the currently observed lease |
| `DISARM` | JSON `null` | None | Unconditionally cancel this Capsule if release is not committed |

An ARM box encrypts `raw(hD) || DEK` to the descriptor's custodian box key. It is not a bearer permission; the creator signature covers it. ARM submission includes the descriptor and ciphertext as attachments. Custodian checks the decrypted binding, ciphertext commitment and AEAD before activation. It must not acknowledge custody of unrecoverable content. The custodian receives the complete DEK and can inspect plaintext.

A CHECKIN is an attestation by the creator key, not independent proof of a human's presence. `basis` must equal the head at acceptance; a new command built against a stale head is rejected. This prevents an old unseen command from being used to extend a later lease. Identical accepted retries return the original event, never another extension. DISARM deliberately needs no fresh head: an authentic signed cancellation remains usable until terminal release. Signing an undelivered cancellation grants that standing authority; revoking individual commands is outside this profile.

Requests are scoped by `(capsule_id, descriptor_hash, request_id)`. A previously accepted exact envelope returns the exact original event bytes, even after terminal state. A different envelope with that request ID is `REQUEST_ID_CONFLICT`. Accepted IDs are retained for the Capsule's entire lifetime. Rejected requests do not reserve IDs or create lifecycle events. A client must use a fresh ID for a changed command. Acceptance and idempotency lookup occur under the same authoritative serialization boundary. Pending/conflicting retries must not race the lookup. A signature is neither an acceptance nor a reservation.

Conformance: lost acknowledgement, replay, delayed unseen command, duplicate racing workers, scope mismatch, stale basis and late disarm. Credential rotation and account recovery cannot substitute a new creator key.

## 3. Custodian event: durable receipt and authoritative order

One event type combines participation receipts, activation receipts, disarm acknowledgements and release decisions. Body fields: `H`, `kind = event`, `capsule_id`, `descriptor_hash`, `seq` (integer `1..10000`), `previous` (`null` at sequence 1, otherwise `B(32)`), `at` (`U`, authoritative Unix seconds), `clock` (`trusted` or `held`), `action`, `command` and `release_box`.

Custodian signs the complete body. `command` is the exact signed creator command for ARM/CHECKIN/DISARM; for RELEASE it is `null`. `release_box` is `B(112)` only for RELEASE, otherwise `null`. The event hash is the domain-separated hash of its complete envelope. A sequence has no gaps, no duplicate events and no order derived from arrival timestamps or database row IDs. `at` is nondecreasing. Identical times are ordered by sequence.

| Action | Permitted predecessor | Conditions and resulting fact |
|---|---|---|
| `ARM` | None | Sequence 1, valid ARM and verified custody; `clock=trusted`; initial deadline `at+I` |
| `CHECKIN` | Nonterminal ARM/CHECKIN | Current basis; `clock=trusted`; `at <= old D+G`; new deadline `at+I` |
| `DISARM` | Any nonterminal head | Valid creator cancellation; permanent terminal disarm |
| `RELEASE` | Nonterminal ARM/CHECKIN | `clock=trusted`; `at > D+G`; recipient box durably stored; permanent terminal release |

Only DISARM may use `clock=held`, with `at` exactly the preceding event's `at`; it carries no new trusted time assertion. No event follows a terminal event. At the event capacity limit, ordinary CHECKIN is rejected before consuming the last slot: sequence 10000 is reserved for DISARM or RELEASE. Applications must warn well before exhaustion. This operational bound does not silently release or expire a Capsule.

Durable acceptance means descriptor, ciphertext, key custody, relevant command, signed event bytes, idempotency mapping and new authoritative head have crossed the provider's declared durable storage boundary as one recoverable operation. The provider must not emit a signed event before that boundary. A prepared internal signature is never externally published. After restart it returns the original committed bytes. Storage may be SQLite, another database or a log; those choices are not wire semantics.

RELEASE is an atomic compare-and-append against the current head and time. A worker's previous policy evaluation is insufficient. Authorization and irreversible protocol commitment coincide at that durable append. `release_box = seal(recipient_key, raw(hD)||DEK)` is generated internally and persisted with the terminal event before any release export. A crash must never produce an export without a committed event. A disarm winner forbids export. A release winner rejects new disarm. Honest-provider commitment is irreversible even if notification and delivery have not happened.

Verify all signatures, scope, embedded commands, hash chain, sequence, time and lifecycle rules, not just the last signature. Retained conflicting signed heads can expose equivocation; no external witness prevents it. Conformance: competing workers, both disarm orders, stale evaluated snapshot, crash at persistence boundaries, fork, truncation, wrong recipient and premature release.

## 4. Inspection exchange: fresh sampled status

A query body has exactly `H`, `kind = inspect`, `capsule_id`, `descriptor_hash`, `challenge` (`B(32)` freshly random). It is unsigned and read-only; no authority derives from it. A custodian response is a signed envelope whose body has `H`, `kind = snapshot`, `capsule_id`, `descriptor_hash`, the echoed `challenge`, `head` (`B(32)` or `null`), `sampled_at` (`U` or `null`), `clock` (`trusted` or `unavailable`), and `events` (complete ordered envelope array, possibly empty).

At a consistent serialized read, the custodian samples its committed head and complete prefix. `head` must equal the last event hash, or null for an empty prefix. `sampled_at` is trusted current time when `clock=trusted`, otherwise null. It cannot precede event times. A fresh challenge and a bounded local request timeout prevent a cached signed response satisfying this read; they do not prevent the custodian lying, or events committed just after sampling. The default client deadline is 10 monotonic seconds; exceeding it produces unknown status. A terminal proof remains valid historically without a fresh query.

Verify expected challenge, signatures, descriptor binding, history, and all locally retained anchors. A known accepted event missing from the supplied prefix is a conflict, not absence. An empty prefix is a signed nonactivation claim, not permission to change a retained descriptor. Disclosure of metadata to callers is a transport/privacy deployment concern; no secret key or plaintext appears in this exchange. Conformance: replayed snapshot, changed challenge, withheld accepted event, incomplete prefix and status timeout.

## 5. Portable archive and release package

An unsigned container has exactly `H`, `kind = archive`, `descriptor` (signed envelope), `ciphertext` (base64url raw bytes), `events` (complete ordered array). It contains no remote URLs, account references, external key resolution or mandatory network fetch. Root bytes must themselves be canonical. A release package is this same object ending in a valid RELEASE event; the sealed key is already bound by that terminal signature. A disarm archive ends in DISARM. No new signature or separate release-certificate dialect is needed.

Recipient verifies using independently authenticated expected creator/custodian/recipient keys and optionally expected descriptor commitment and retained anchors. Keys merely self-declared inside an archive are not authenticated trust roots. Complete replay establishes that **the custodian's recorded facts** authorize release. Decrypt the terminal box, verify its exact 64-byte length and descriptor binding, then AEAD-decrypt and check the payload length/commitment. This demonstrates content integrity; it does not demonstrate lack of previous disclosure.

Incomplete history is `INCOMPLETE`, not valid release. Missing recipient private key permits public authorization verification, not a claim of successful content decryption. A complete-looking operator fork may be undetectable without an independently retained contradictory anchor. A creator who was censored may truly be present while the recorded instruction still authorizes release.

Conformance: offline package verification, content/key/recipient substitution, omitted/reordered entries, false terminal proof, no-network verification, wrong trust pins and unavailable recipient key.

## 6. Verifier result

A local result is unsigned and has exactly `H`, `kind = verification`, `descriptor_hash` (`B(32)` or null if unparseable), `verdict` (`VALID`, `INVALID`, `INCOMPLETE`, `UNSUPPORTED`), `state` (`UNARMED`, `ARMED`, `GRACE`, `ELIGIBLE`, `DISARMED`, `COMMITTED`, `UNKNOWN`), `head` (`B(32)` or null), `authorization` (`true`, `false` or null), `content` (`NOT_ATTEMPTED`, `DECRYPTED`, `FAILED`), `freshness` (`HISTORICAL`, `SAMPLED`, `UNKNOWN`), and `code` (one error/result token from Interoperability).

Results are derived locally, never taken from a SaaS JSON boolean. An invalid/incomplete/unsupported object yields `state=UNKNOWN`, `head=null`, `authorization=null`, `content=NOT_ATTEMPTED`, `freshness=UNKNOWN`. A valid terminal RELEASE yields `COMMITTED`, authorization true. A valid nonterminal history alone yields `UNKNOWN` and authorization null: a trusted evaluation time is needed to classify its current lease. A fresh validated snapshot can supply that sampled time; eligibility still is not authorization. A content decryption failure after valid public authorization yields `INVALID`, `UNKNOWN`, head null, authorization null, content `FAILED`, freshness UNKNOWN, code `CONTENT_AUTHENTICATION`. An implementation may additionally show the independently verified public decision separately; it must not report the whole package valid.

## Boundaries and compatibility

This profile has no multi-party policies, witnesses, consensus, threshold crypto, DKG, custody federation, membership succession, SaaS login, billing, scheduling platform, PorterNet or real delivery integration. Other future profiles may add such capabilities under different identifiers; they cannot silently strengthen or weaken this one. No real user content or external disclosure is authorized for the Phase B laboratory.

The spec release, wire/profile version, cryptographic suite, reference package version and conformance corpus version are separate axes. Research `wire4`, v6/v7/v8 and generation numbers are not compatible with these candidate messages. Unknown profile/version/suite is rejected, never downgraded. Changes to an activated policy always require a new Capsule. See [Open questions](OPEN-QUESTIONS.md) for the historical approval record and remaining production questions.

## Approved amendments — 29 October 2026

**Release recoverability invariant.** A RELEASE may commit only if its exact canonical recipient-bound archive, complete prefix and required ciphertext cross the same recoverable durable boundary. The archive is immutable once committed. After crashes, restart, lost acknowledgements or interrupted export, export must return those exact bytes. Regenerating the recipient box, reconstructing a different package or depending on a delivery worker's volatile memory is forbidden. Failure to persist the archive aborts commitment. Known missing/corrupt committed material is a storage-integrity failure: refuse to claim successful recoverable release; do not reopen disarm or silently invent another terminal event. Durable recoverability assumes the declared storage survives; destruction of every copy remains outside that assumption. Commitment does not establish successful export, recipient decryption or reading.

**Capacity.** From a verified nonterminal head sequence s, derive remaining ordinary check-ins as `9999-s` (zero at s=9999). Clients must prominently report impending exhaustion when this count is at most 100, and report zero as “no further check-ins can be accepted; disarm before release commitment or provision a replacement Capsule”. This is a local projection of signed history, not an added wire field or authority. At sequence 9999 a new CHECKIN returns CAPACITY without an append, ID reservation, renewal or deadline change. Exact accepted retries still recover their receipts. The final slot remains exclusively for DISARM or a policy-eligible RELEASE. Capacity alone is never an authorizing predicate; existing time/absence rules still apply, so inability to renew can eventually leave the unchanged lease eligible. The user must not be told continued presence is protected indefinitely. Solo v0.1 provides no indefinite-continuity guarantee, rollover or automatic policy extension.

**Synthetic backup demonstration.** Phase B must demonstrate independent export/restore of creator and recipient private keys, descriptor, independently authenticated pins, ciphertext and retained receipts. Restored creator authority must sign a fresh check-in and disarm without a product account; restored recipient authority must decrypt the same retained committed package offline. Compare fingerprints to the original pins. Losing every creator-key copy prevents new participation/disarm; theft permits them. Losing every recipient-key copy prevents decryption; theft enables it when release material is available. Backups clone authority and do not revoke original copies. The demonstration uses labelled synthetic keys and protected local files only, with no account-reset substitution, key rotation, trustees or production vault.
