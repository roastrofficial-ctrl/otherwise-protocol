# Conformance plan

Release status: Solo v0.1 as specified by `0.1-draft.2`, included in `v0.1.0-alpha.1`. See [SPEC](../SPEC.md). Historical design/approval notes below are rationale; they add no build or runtime dependency.
This records the original conformance plan. Current executable fixtures and release results are described in [CONFORMANCE.md](../CONFORMANCE.md) and [the release report](RELEASE_REPORT.md). Earlier research results are provenance, not alpha conformance evidence.

## Deliverables after architectural approval

The approved public protocol repository should contain normative spec/docs, versioned schema aids, portable byte fixtures, `reference/python`, an independently authored PHP verifier, `conformance`, synthetic `examples`, Dockerfiles and a concise runbook. Schemas assist field validation; text-defined encoding, signature and lifecycle semantics remain normative. No runtime dependency may point to research, Cloud, Laravel, PostgreSQL telemetry or PorterNet.

Fixture records must contain exact input bytes, profile/spec/suite/corpus IDs, independently authenticated expected trust pins, optional retained anchors/recipient secret, injected time and expected result/error. Expected signatures, digests, envelope bytes and parsed values must be supplied where relevant. Negative fixtures must preserve why rejection is required. Fixed private material is clearly synthetic and forbidden for real deployment. Generation of the final corpus begins only in Phase B.

## Portable cases

| Group | Required cases and expected behavior |
|---|---|
| Descriptor | Valid encrypted synthetic Capsule; wrong signer; wrong pinned custodian/recipient; ciphertext size/hash substitution; policy/nonce/key substitution; bad interval/grace; overflow; same ID with different descriptor |
| Activation | Valid custody verification and ARM; wrong enrollment recipient; wrong inner hD; invalid DEK/AEAD; incomplete payload; missing custody persistence; lost activation response; identical ARM retry returns same event |
| Check-in | Normal renewal; renewed during grace; last included second accepted; first late second rejected; correct signature but stale basis; cross-Capsule/descriptor replay; invalid creator signature; stolen creator key succeeds within its authority as an explicit limitation |
| Idempotency | Same accepted envelope before/after terminal returns identical bytes with no renewal; altered body/signature with reused accepted ID conflicts; two simultaneous identical requests append once; previously rejected command has no accepted receipt |
| Time | Exact D, D+1, E, E+1 boundaries; forward jump; backward step; monotonic discrepancy; overflow; unchanged time and two ordered commands; unavailable-clock snapshot; held-time disarm; process pause; restart without qualified time; trusted elapsed downtime |
| Race | DISARM then attempted RELEASE; RELEASE then attempted DISARM; CHECKIN updates head while worker holds stale eligible snapshot; multiple release workers; deadline elapsed without worker leaves disarm possible; no window-finalization cancellation fence |
| Commitment | No precommit export; exact stored recipient box on all retries; disarm prevents honest export; lost release reply recovers committed package; delivery failure does not reopen cancellation; downloading twice is permitted |
| History | Missing first event; gap; duplicate/reordered event; wrong previous hash; decreasing timestamp; wrong embedded action; wrong signer; command reuse; post-terminal event; incomplete prefix; known-anchor omission; signed fork detected with both branches retained |
| Snapshot | Fresh challenge accepted; old challenge, wrong challenge or out-of-time reply rejected as current evidence; correct terminal history remains historically valid; new concurrent event after sample does not falsify sampled status; healthy vs unavailable clock semantics |
| Archive | Offline public authorization verification; offline recipient decrypt; wrong recipient secret; altered release box; wrong inner hD; wrong ciphertext/tag/AAD; missing prefix; self-declared trust pins rejected; valid archive with no recipient key reports no decryption attempt |
| Encoding | Duplicate members at every depth; escaped duplicate names; noncanonical order/spacing/escapes; UTF-8/BOM/surrogates/non-ASCII; floats/exponents/-0; booleans in integer fields; safe-integer overflow; padded/noncanonical base64; unknown fields/null misuse; every resource bound |
| Version/crypto | Unknown profile/version/suite rejects without fallback; wrong signature domain; envelope-vs-body hashing mistake; Ed25519 S>=L, noncanonical points, small-order and mixed-subgroup inputs; suite cannot be downgraded |
| Capacity | Reserve last journal slot for terminal action; ordinary check-in at capacity refuses without changing deadline; no truncation; signed disarm/release remains possible; size-limit rejection does not alter accepted state |

For multidefect objects, both implementations must follow the documented error precedence. At minimum all cases must agree on verdict, state, authorization, content status and freshness; the planned fixed corpus also requires matching code and commitments. A local display string may differ.

## Crash and recovery experiments

Use actual subprocess termination at explicit persistence boundaries: before key/payload persistence; after staged files but before atomic head publication; before signed event commit; after commit but before response; after terminal commit but before export; during export retry. Reopen storage and inspect independently. Assertions must distinguish “never accepted” from “accepted but reply lost”. Repeat using competing independent worker processes, not just threads sharing one memory lock.

Test restoring an old database with a retained creator receipt: verification must flag conflict and release must not continue from a known uncertain prefix. Test a total rollback with no external anchors separately: document that the missing history may be undetectable. Do not turn this expected limitation into a passing claim of rollback resistance. Process-kill tests are not power-loss tests; storage claims require separate fsync/filesystem/device evidence.

## Executable independence experiments

1. Copy only the protocol directory to an isolated build context. Build and run reference lifecycle/conformance images without research files or network fetches to research.
2. Complete create/activate/check-in/status/disarm through the independent CLI with no Laravel, account, billing or Cloud database. Use a separate Capsule for the missed-check-in/release/offline-recipient path.
3. Remove the optional product process and database after ARM. Recover the latest accepted receipt via the custodian, perform/verify a new check-in through the direct client, and disarm. In another armed synthetic Capsule, run an independent public release worker while the product remains absent.
4. Carry the same canonical commands, snapshots and archives through independently implemented HTTPS and file/stdin adapters. Compare exact bytes and verifier results. File transport requires a runner to feed commands to the live custodian; an offline verifier cannot accept participation by itself. Report transport delay/authentication/privacy differences instead of asserting equal availability.
5. Reject a provider incompatible with the required profile/suite/order/custody capabilities. Explicitly request operator-resistant cryptographic policy enforcement and verify that the Solo provider refuses it. No silent downgrade.
6. Run the PHP verifier in a separate Docker image with no Python interpreter, research modules or reference service/network access. Verify an exported release archive and the portable corpus. Reverse fixture production/checking for selected cases to avoid Python being the only source of expected bytes.
7. Test malformed inputs and resource exhaustion at both transport boundaries. No stack trace, logged DEK, private signing seed or plaintext may become a normal protocol response.

## Negative results that must remain visible

Deliberately compromised Solo custodian decrypts before eligibility using its retained key; forges a plausible history without an available contradictory anchor; suppresses a submitted but unaccepted check-in; refuses an otherwise eligible release; and loses indispensable state. Demonstrate what receipts can expose and what cannot be detected. No imported distributed-custody guarantee may appear in the result labels.

## Completion criteria and evidence

One command should build/run the approved Python and PHP conformance in Docker using isolated synthetic state. Record exact image/dependency versions and corpus hash, disagreements, reproducible minimized failures, timings and tested persistence boundaries. Keep research regression runs separate from new-profile conformance. Transport agreement is evidence about message semantics, not a proof of clock accuracy, operator honesty, production availability or cryptographic security.

A Phase B completion report must reconcile every proposal requirement with spec location, positive/negative fixture and actual execution evidence. Any unresolved signature-backend discrepancy, lifecycle ambiguity or missing required fixture blocks a claim of conformance. Security review and production release are further decisions, not automatic effects of passing tests.

## Approved targeted amendment experiments

- Assert recoverability as an invariant after every committed RELEASE: exact archive bytes, terminal box and ciphertext survive reopening. Kill between tentative event and archive writes, before commit, after commit/before reply, and after export response construction/before transmission. Simulate a torn uncommitted transaction and truncate/corrupt a copied database separately. A recoverable precommit transaction rolls back; known committed corruption fails closed and is not silently rebuilt. Record SQLite/process-crash evidence separately from physical power-loss guarantees.
- Drop the first export response, retry export repeatedly and restart between retries; compare complete archive bytes and ciphertext digest, with one terminal event and no regenerated box. Recipient verifies/decrypts each retained export offline. No “delivered” assertion follows merely from commit.
- Build deterministic full histories through sequences 9899, 9998, 9999 and terminal 10000. Check the warning threshold, last accepted renewal, rejected new renewal, identical accepted retry, unchanged deadline and rejected request nonreservation. At full capacity, release before E+1 must fail; disarm must still succeed; a separate Capsule may release after E+1 under the unchanged policy. Post-terminal attempts cannot append.
- Backup synthetic creator and recipient keys/pins/receipts, delete working copies, restore into an independent client path, check fingerprints, accept/verify a new check-in and disarm, and decrypt a separately committed release after recipient restore. Missing/wrong backups fail rather than gaining account-reset authority. Stolen creator-key participation and stolen recipient-key decryption are retained limitation demonstrations. No production key vault, rotation or recovery trustees are added.
