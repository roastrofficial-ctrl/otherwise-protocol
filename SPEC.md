# Otherwise Solo v0.1 specification

Spec revision **0.1-draft.2**, included unchanged in release `v0.1.0-alpha.1`. Architecture approved with the 29 October 2026 recoverability, capacity and synthetic-backup amendments. Reference/conformance work is experimental and is not production security review.

The normative specification consists of:

1. [Objects, trust and policy](docs/SOLO-PROFILE-PROPOSAL.md)
2. [Lifecycle, time and durable finality](docs/LIFECYCLE.md)
3. [Cryptography and key ownership](docs/CRYPTOGRAPHY-PROPOSAL.md)
4. [Exact encoding, domains, transport binding and verification](docs/INTEROPERABILITY.md)

The approved-amendment sections supplement the earlier Phase A text. They do not change signed fields, eligibility, authority or the terminal ordering boundary. Historical requests to stop for approval are superseded by the approval record in [Open questions](docs/OPEN-QUESTIONS.md).

A conforming honest custodian commits RELEASE only together with the exact recoverable archive/ciphertext. Capacity does not itself authorize release. Creator and recipient backups preserve original key authority; product account reset cannot substitute it. Solo offers no indefinite continuity and no operator-resistant early-decryption guarantee.

Schemas are validation aids; they cannot override these documents. A program's behavior is not normative if it differs from the text. Research generations and their wire versions are unrelated to this profile's compatibility identifiers.
