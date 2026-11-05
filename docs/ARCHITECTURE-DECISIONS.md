# Architecture decisions

Release status: Solo v0.1 as specified by `0.1-draft.2`, included in `v0.1.0-alpha.1`. See [SPEC](../SPEC.md). Historical design/approval notes below are rationale; they add no build or runtime dependency.
Approved architectural decisions, including the targeted amendments below. Research references and preserved negative results are indexed in [Traceability](RESEARCH-TRACEABILITY.md).

## D1 — Explicit single-custodian trust

**Propose:** one creator, one recipient, one custodian with the full DEK and authoritative durable order. The provider enforces instructions in software. Its operator can decrypt early.

**Alternatives:** copy the latest two-domain threshold construction, require a witness committee, or imply that encrypting a database restrains its operator. The first two introduce distributed availability/provisioning/consensus requirements; the third is false. The Solo brief explicitly permits a trusted custodian.

**Consequence:** much smaller implementable protocol, but no Byzantine safety, independent observation, collusion resistance or operator-resistant early-decryption guarantee. The 0.6 raw partial-decryption attack and 0.7 related-dealer attack U are reasons to make the boundary explicit, not reasons to import more bespoke crypto.

## D2 — One renewable lease, immutable instruction

**Propose:** interval plus grace; accepted check-in resets the deadline, including during grace. After grace, check-in cannot revive the lease, but disarm remains available until commitment. One recipient and one payload are immutable.

**Alternatives:** fixed finite observation slots, calendar recurrence, generic AND/OR/THRESHOLD contracts or accepting late presence until a worker happens to run. Fixed slots worked in the research but impose finite scheduling and historical-window semantics. Generic expressions are foundational research concepts, yet unnecessary for this initial profile. Late renewal after grace makes the meaning of a missed obligation depend on worker latency.

**Consequence:** unambiguous arithmetic and a human-sized interaction. This is an intentional new proposed semantic profile, not wire compatibility with historical absence contracts. No migration in place; amendments require disarm/new Capsule. Operator clock and network censorship remain consequential. Bounds, late-check-in policy and key replacement need explicit approval.

## D3 — Commitment, not deadline passage, ends cancellation

**Propose:** atomic durable terminal append decides DISARM versus RELEASE. Policy eligibility is a derivation; it is not final authorization. Terminal RELEASE is both authorization and irreversible protocol commitment. No prepared export may escape earlier.

**Alternatives:** first expired window freezes disarm; front-end click wins; latest arrival timestamp wins; recipient's first decrypt is the commitment point. Historical 0.7 attack V disproves the first model's usefulness. The next two cannot establish durable order; the last cannot be observed reliably or used to recall exported capability.

**Consequence:** a precise implementable race with honest-provider assumptions. Eligible Capsules can still be disarmed before commitment, but a submitted request is not cancellation success. Unlike 0.8, no distributed prepared-lock or quorum protocol is necessary in Solo.

## D4 — Signed durable history and independently retained receipts

**Propose:** creator-signed commands and custodian-signed chained events; exact idempotent retries; complete portable prefix; fresh challenge-bound inspection and local anchors. Participation becomes effective at durable acceptance, not receipt download. CHECKIN binds the observed current head; DISARM intentionally does not.

**Alternatives:** product rows as authority, signature-only latest status, unsigned database timestamps, mandatory blockchain/transparency service or treating every lost reply as rejected. The research shows false-success UI, censorship, stale signed status, rollback and recoverable lost acknowledgements. Extra infrastructure would change the smallest profile and still need its own assumptions.

**Consequence:** independent verification and some detectable equivocation, at a storage/export cost. A complete-looking fork remains possible for a malicious custodian without surviving external anchors. A hash chain does not prove the absence of omitted facts. Read-only inspection needs deployment privacy controls; these must not become authorization inputs.

## D5 — A text-defined interoperable protocol, not a Python export

**Propose:** constrained RFC 8785 JCS, exact domains and field sets, safe integer seconds, one explicit crypto suite, standalone offline archive and independent PHP verifier. Select established AES-GCM/Ed25519/SHA-256/Sodium sealed boxes, not historical custom threshold arithmetic. Version spec, wire, suite, runtime and corpus separately.

**Alternatives:** copy the research's restricted JSON and call it full JCS; define behavior through Python functions; introduce protobuf/CBOR and a schema compiler; add cryptographic negotiation. Research cross-language corpora motivate exact bytes. JCS plus an ASCII/integer subset minimizes serialization ambiguity. Other encodings are viable but bring unnecessary first-profile decisions. Negotiation can hide downgraded trust.

**Consequence:** a second implementation can be built from text and vectors. PHP/Python using Sodium still share a crypto backend; strict signature edge cases must be verified explicitly. Changing the sealed-box choice to HPKE remains an approval option before wire identifiers are frozen.

## Supporting decisions

- **Transport:** core operations consume/produce canonical bytes without sockets or HTTP dependencies. The conventional binding uses certificate-verifying HTTPS with independently authenticated endpoints. A file/stdin adapter exercises identical message verification, not equivalent live latency or confidentiality. No PorterNet integration is included.
- **Time:** a trusted health-qualified custodian clock; fail closed for time-dependent actions, but permit head-ordered disarm during clock failure. Durable sequence is the ordering source, not a timestamp. Restart requires re-established trusted time and storage continuity. There is no protocol power to repair lost authority.
- **Custody substitution:** explicit capability requirements reject providers claiming incompatible enforcement. A conventional trusted-key provider cannot satisfy a requirement for cryptographic restraint. Interfaces separate lifecycle evaluation from storage and key-delivery mechanics; stronger custody is another reviewed profile, not an implementation switch that changes this profile's truth.
- **Scope and resource limits:** synthetic-only Phase B, 1 MiB plaintext, bounded journal and message sizes, no unknown fields, no key migration or re-arm. Limits are disclosed and checked, never implicit release conditions. They are proposal decisions requiring review.
- **Repository boundary:** new sources live entirely inside `Otherwise-protocol`; after approval they can become their own public Apache-2.0 repository. Research paths are provenance links only. Private Cloud code, accounts, billing, Laravel, root `.env` files and lab credentials are not copied. There is no nested Git repository or publication step in Phase A.

For all five decisions the trade-off is intentional: reduce machinery without borrowing the research's stronger conditional claims. A commercial client can use the protocol, but commercial readiness is not established by architecture approval.

## Approval record and amendment assessment

On 29 October 2026 the user approved direction B with three targeted amendments and explicitly authorized Phase B after they are complete, provided no material semantic change is introduced. Release recoverability now includes exact canonical archive and ciphertext in the terminal durable boundary; capacity reporting/last-slot behavior is explicit; synthetic creator/recipient backup demonstrations are mandatory. These strengthen existing persistence, bounded-journal and key-ownership requirements without changing policy, signed fields, trust roots, eligibility or terminal ordering. No new architectural conflict was identified. There is no publication, deployment, private SaaS import or real-content authorization.
