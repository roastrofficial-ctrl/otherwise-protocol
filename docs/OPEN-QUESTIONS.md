# Open questions and architectural approval

Release status: Solo v0.1 as specified by `0.1-draft.2`, included in `v0.1.0-alpha.1`. See [SPEC](../SPEC.md). Historical design/approval notes below are rationale; they add no build or runtime dependency.
Historical Phase A approval request (superseded by the approval record below). The assignment requires: “Do not implement the new protocol, generate its final cryptographic vectors, or create the publishable reference runtime until we have reviewed and accepted the proposed specification.” No silence or general enthusiasm is implementation approval.

## Decisions requested

| Decision | Recommended candidate | Other meaningful choice / cost |
|---|---|---|
| Trust and membership | Exactly one trusted custodian, creator and recipient; custodian holds DEK | Stronger operator resistance requires a separate researched profile, not hidden extra machinery |
| Participation rule | Rolling acceptance-based interval, renew through inclusive grace; late renewal rejected after grace, disarm still permitted | Fixed slots change UX and lifecycle; accepting late renewal until worker commit makes effective deadline depend on worker latency |
| Irreversible boundary | Durable terminal RELEASE append; DISARM can win until then | Decryption/notification boundaries cannot reliably support recall or durable race resolution |
| Cipher suite | Ed25519/SHA-256/AES-256-GCM/Sodium sealed box, pinned recipient key | HPKE is an alternative before identifiers freeze; needs language-provider selection and a different suite |
| Time and recovery | Trusted custodian UTC with health gating; fail closed on uncertainty, held-time disarm available | Mandatory independent time attestations would add another protocol authority; pretending server time is objective evidence is unacceptable |
| Minimal limits | 1 MiB payload, 10000 events, interval 60s..1 year, grace 1s..30 days | Different explicit limits can be chosen before approval; journal rollover is not silently automatic |
| Policy/key amendments | Disarm and create a new Capsule; no lost-key administrative bypass | In-place succession is a separate protocol design with authorization and irrevocability consequences |
| Implementation boundary | After acceptance: standalone public Apache-2.0 protocol repo, Python reference, independent PHP verifier, Docker tests | No private Cloud code, production content or deployment authorized by Phase A |

The journal limit supports roughly 27 years of daily renewals, fewer with frequent renewals. That is a resource bound, not a decades-long service guarantee. Users need warning and planned migration before exhaustion. Full-prefix portability also exposes timing/participation metadata to archive holders; encrypted messages do not conceal lifecycle metadata. Approving the minimal profile accepts that trade-off.

## Engineering questions to close before claiming Phase B conformance

- Which maintained Python/PHP crypto backends enforce the specified strict Ed25519 subset? Verify adversarial point/scalar fixtures; do not weaken the rule merely to match a permissive API. If no suitable reviewed backend exists, return for a specification decision.
- Which concrete durable store, file-commit discipline, fault-injection boundaries and supported operating systems will the reference claim? Wire semantics are fixed; storage evidence must substantiate them.
- Which provider clock source and startup revalidation procedure are used in the laboratory, and which assumptions remain untested? A health flag is not authenticated UTC.
- How will creator/recipient/custodian pins be authenticated in the demo, and how are independently encrypted backups provisioned without sending private keys to Cloud? Local synthetic provisioning is acceptable laboratory evidence, not a production identity system.
- What metadata access/rate-limit controls will the conventional transport use? Such controls can limit availability; they cannot mint creator authority or alter the meaning of an accepted command. A production reader-authentication system is outside this profile.
- Is the proposed conventional binding's archive-size budget usable in the target PHP/runtime environment? Test resource boundaries before performance claims, while preserving identical normative limits across implementations.

These are required implementation investigations within the proposed boundaries, not permission to change normative behavior silently. Material changes return for review. They do not justify writing a runtime before approval.

## Three largest remaining risks

1. **Trust concentration:** the custodian can decrypt early, censor, fork or disappear. Receipts do not cryptographically prevent those acts.
2. **Irrecoverable human capability and timing failures:** lost/stolen creator or recipient keys, censored traffic and an unqualified custodian clock can cause unwanted release or permanent unavailability. Product accounts cannot repair that authority loss.
3. **A new unreviewed protocol composition:** strict encoding, crypto-backend edge cases, atomic storage and recovery semantics need independent implementations, adversarial experiments and external review. This proposal has not demonstrated them.

## Deliberate exclusions

No multi-recipient fan-out, generalized contract expressions, trustees, witness committee, BFT consensus, threshold custody, DKG, DLEQ, membership/key succession, account recovery, Laravel, Cloud accounts, PorterNet, production notification/disclosure or sensitive user data. The larger conditional-obligations research remains valid context; it is not a requirement to implement every possibility in Solo.

## Approval choices

**A — Accept the candidate architecture and authorize Phase B** with the boundaries and trust claims above. Resolve engineering questions through implementation/conformance without silent semantic changes.

**B — Accept subject to named changes.** Revise the Phase A documents first; confirm the changed architecture before implementation.

**C — Continue Phase A investigation.** Identify the alternatives or risks that need more analysis; no implementation starts.

Approval of architecture does not authorize publishing a repository, deploying a production service or introducing real disclosure destinations. Those actions need their own concrete reviewable result and authorization.

## Approval received — 29 October 2026

Decision B approved the architecture subject to release recoverability, explicit capacity exhaustion and synthetic creator/recipient backup/restore. These amendments are now incorporated in the profile, lifecycle, interoperability, crypto, threat model and conformance plan. No signed object, authority, policy predicate or terminal boundary changes. No material architectural conflict identified. The user explicitly permits Phase B once these amendments are complete; a second approval is not required. Material semantic changes still require review. Publish/deploy/private SaaS imports and real sensitive content remain prohibited.

## Phase B investigation outcomes

| Earlier implementation question | Resolution for this bounded reference |
|---|---|
| Strict Ed25519 backends | PyNaCl and PHP Sodium/FFI, with Sodium's published main-subgroup workaround; direct point tests and both verifier corpora pass |
| Durable storage | SQLite FULL-synchronous WAL, transactional state/archive BLOBs, corruption checks and actual process/torn-WAL experiments; no physical device guarantee |
| Clock qualification | Explicit injected synthetic clock in the demo; real-clock adapter starts unqualified and detects tested discontinuities. Production time-source/revalidation assurance remains outside this laboratory |
| Pins and backups | Locally provisioned synthetic pins, independent temporary backups and restored original keys; production identity distribution/vault design remains out of scope |
| Reader privacy / rate control | Loopback HTTPS test service and local file dispatcher only; no hosted metadata-privacy or Internet availability claim |
| PHP resources / interoperability | 64-bit CLI PHP with FFI; actual 10000-event terminal history verified in Python/PHP; shared Sodium-family dependency disclosed |

These findings introduce no new protocol authority, policy predicate, amendment path or signed field. The remaining production questions do not become hidden laboratory guarantees. Executed outcomes and exact limits are in [Results](RESULTS.md).
