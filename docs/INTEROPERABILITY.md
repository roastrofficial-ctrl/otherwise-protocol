# Interoperability and portable verification

Release status: Solo v0.1 as specified by `0.1-draft.2`, included in `v0.1.0-alpha.1`. See [SPEC](../SPEC.md). Historical design/approval notes below are rationale; they add no build or runtime dependency.
Implementations derive behavior from these documents and the portable corpus. The Python reference is not the normative oracle.

## Canonical encoding

Adopt [RFC 8785 JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785), with a deliberately narrower data model:

- UTF-8 bytes, no BOM, comments, trailing bytes or insignificant whitespace. Every wire container/envelope is required to equal its own JCS serialization byte for byte. HTTP framing whitespace is not part of a protocol object.
- Keys and decoded string values contain only printable ASCII `U+0020..U+007E`; object schemas constrain actual strings further. Unicode names/text belong inside encrypted payload bytes or local metadata. No normalization operation is performed. Non-ASCII and lone surrogates are rejected rather than normalized.
- Numbers are unsigned safe integers `0..9007199254740991`. Boolean is a distinct type, never an integer. Reject negative numbers, `-0`, fractions, exponent notation, NaN and infinities. A permissive parser followed by numeric coercion is insufficient.
- Object member names are unique at every nesting level. Detect duplicates during parsing, before a map can overwrite them. Sort keys by JCS UTF-16 ordering, equivalent to ASCII byte ordering for the permitted alphabet. Preserve array order.
- Use JCS string escaping. Alternative equivalent escapes such as `\u0061` for `a` fail the canonical byte comparison. There are no permitted decoded control characters. Do not use language-default JSON formatting as an implicit definition.
- Every object has an exact field set. Missing fields, unexpected `null`, unknown members and wrong scalar types are invalid. The explicit nullable fields described in the profile must be present even when null. Unknown versions/profile/suite are unsupported, not coerced to a known version.
- Binary is canonical URL-safe base64 without `=` padding, using `A-Z a-z 0-9 - _` only. Decode to the exact specified length and require re-encoding to reproduce the original; nonzero spare bits and alternate alphabets are rejected. Ciphertext has the variable length committed in its descriptor.

Candidate limits: maximum JSON nesting depth 16, maximum event array length 10000, maximum canonical archive/snapshot bytes 33554432 (32 MiB), maximum standalone descriptor/command/event/query bytes 8192. Parsers must enforce bounds before unbounded allocations. This profile uses only its shallow known object shapes, not recursive policies. Larger histories require a new approved profile or a new Capsule, not silent truncation. The same limits apply to both verifiers and transports.

An archive is a single canonical JSON object. Every nested signed body is independently JCS-serialized for signature verification; an envelope embedded in an archive must have exactly the same value and canonical bytes as when issued. No transport may re-sign, add a JSON wrapper to a signed body or reinterpret a number. An HTTP transport may carry the exact canonical object as a body, and a file/stdin transport may carry the identical bytes. Timing, authentication and durability of these channels are distinct even when object verification agrees.

## Transport operation boundary

The core exposes `submit(descriptor_bytes, ciphertext_bytes, command_bytes) -> event_bytes`, `inspect(query_bytes) -> snapshot_bytes`, `evaluate(capsule_id, descriptor_hash) -> archive_bytes`, and `export(capsule_id, descriptor_hash) -> archive_bytes`. These are byte-oriented operations, not a required programming-language API. Evaluation may append RELEASE only under the atomic lifecycle rules; export never changes lifecycle state. It is possible to call evaluation without creator secrets: the standing signed instruction supplies release authority. Rate limits or access controls must not be confused with that authority.

The proposed default binding uses certificate-verified HTTPS. `POST /solo/v1/submit` carries multipart/form-data with exactly three parts named `descriptor` (canonical signed JSON), `ciphertext` (raw binary), and `command` (canonical signed JSON); filenames are ignored and duplicate/additional parts rejected. The other routes are `POST /solo/v1/inspect` with the canonical query, and `POST /solo/v1/evaluate/{capsule_id}/{descriptor_hash}` or `GET /solo/v1/export/{capsule_id}/{descriptor_hash}` with empty bodies. Path IDs use the exact canonical base64url forms. Successful responses contain the unmodified canonical event, snapshot or archive, as appropriate, with `application/json`. Multipart framing is transport syntax only and is not signed; all three part values are independently bound by protocol verification. Resubmitting immutable descriptor/ciphertext with each command is intentionally simple and can later be optimized by a separately specified transport binding without changing signed messages.

Mutation rejections use HTTP 409 with a small unsigned JSON object `{ "code": token }`, malformed submissions 400, exceeded limits 413 and unavailable dependencies 503; an unsupported profile/version/suite is 400 with its specific token. Such error responses are transport diagnostics, not protocol artifacts or evidence of nonacceptance after an interrupted connection. No receipt is fabricated from an HTTP status. Direct client endpoints and TLS trust roots must be authenticated independently of Cloud. Secrets other than the sealed enrollment box never enter these requests. Phase B tests must exercise this binding and a separately implemented file/stdin dispatcher carrying the same object/attachment bytes.

## Domains and exact bytes

For a body `b`, `type = b.kind`:

```text
signature_input(b) = ASCII("otherwise/solo/1/sign/" + type + "\n") || JCS(b)
signature = Ed25519.Sign(signing_key, signature_input(b))
descriptor_hash = SHA256(ASCII("otherwise/solo/1/descriptor\n") || JCS(descriptor.body))
command_hash = SHA256(ASCII("otherwise/solo/1/command\n") || JCS(command_envelope))
event_hash = SHA256(ASCII("otherwise/solo/1/event\n") || JCS(event_envelope))
ciphertext_hash = SHA256(raw_ciphertext)
```

`||` means byte concatenation. Each `\n` above means one LF byte `0x0A`, not backslash and letter n. SHA-256 digests are encoded as B(32) in JSON. The payload AAD domain and sealed-box plaintext are defined in [Cryptography](CRYPTOGRAPHY-PROPOSAL.md). No generic “hash JSON” helper may accidentally hash a signature instead of a body or omit an envelope signature.

Signature domains permitted here are `descriptor`, `command`, `event` and `snapshot`. Queries, archives and verifier results have no protocol signature of their own. Ed25519 uses the pure scheme, not Ed25519ph or Ed25519ctx. For deterministic acceptance across libraries, require canonical compressed encodings of A and R, nonidentity prime-order A and R, scalar `0 <= S < L`, and the uncofactored equation `[S]B = R + [SHA512(R || A || M) mod L]A`. Reject small-order, noncanonical and mixed-subgroup inputs. Library acceptance of a more permissive verification mode does not override these rules. Phase B must establish that both selected backends enforce this subset; if not, choose a reviewed enforcing backend before claiming conformance. No hand-written production group arithmetic is proposed.

## Verification algorithm

1. Enforce size/depth limits and strict canonical parsing; inspect the header before dispatching. Refuse unsupported identifiers.
2. Validate the descriptor exact shape, value ranges and Ed25519 signature, and authenticate creator/custodian/recipient against caller-supplied trust pins before accepting its signature. A self-consistent self-signed identity is insufficient. Recompute hD and ciphertext size/hash.
3. Replay all supplied events from sequence 1. Verify each custodian signature, scope, predecessor, nondecreasing time, allowed clock mode and embedded creator command. Check accepted request-ID uniqueness and exact-basis rules. Perform checked arithmetic for every deadline. Apply lifecycle transitions exactly; reject any post-terminal event.
4. Compare every supplied independently retained anchor to the prefix. A matching event hash establishes that exact prefix through that event. A mismatching hash or a known accepted event omitted from a claimed complete snapshot is `HISTORY_CONFLICT`. An anchor beyond an explicitly partial archive is `INCOMPLETE_HISTORY`, not proof of erasure by itself.
5. For a snapshot, verify the custodian's enclosing signature, expected fresh challenge, local monotonic timeout, head, complete prefix, clock and sampled time. It is a sampled observation, not a lease guaranteeing no later concurrent mutation. Terminal events do not need a fresh clock to remain historical terminal proofs.
6. For a release, require a complete terminal RELEASE chain and verify eligibility using the immediately preceding accepted renewal and the event's signed `at`. Optionally open the terminal box with the pinned recipient secret; check hD and decrypt the payload. Do not contact the SaaS, discover keys from an endpoint, or accept a server's asserted evaluation result.
7. Produce the local result object. A fresh nonterminal snapshot can yield ARMED/GRACE/ELIGIBLE and `authorization=false`; it cannot turn eligibility into authorization. An empty verified snapshot is UNARMED with authorization false. A complete nonterminal archive without a current trusted evaluation time yields UNKNOWN and authorization null. A terminal DISARM yields DISARMED/false; RELEASE yields COMMITTED/true.

An evaluator supplied an explicit trusted test time may classify a nonterminal archive at that time, with `freshness=HISTORICAL`; the caller must not advertise that as a fresh live observation. Public release verification with no recipient secret is valid with `content=NOT_ATTEMPTED`. Only successful authenticated decryption yields `content=DECRYPTED`.

## Results and failures

Use this ordered failure precedence when multiple defects exist: resource limit; parse/canonical violation; unsupported identifiers; schema/range/type; unauthenticated trust pins; bad signature; scope/content commitment; history/link/ordering; lifecycle/time; recipient decryption. Within a step traverse the descriptor before events and events in supplied array order. If an input is otherwise valid but lacks a required prefix, return INCOMPLETE rather than guessing. Raw unauthenticated malformed objects do not establish forks.

| Result code | Meaning |
|---|---|
| `OK_HISTORY`, `OK_SNAPSHOT`, `OK_RELEASE`, `OK_DISARM` | Valid artifact in the indicated context |
| `LIMIT`, `MALFORMED`, `NONCANONICAL` | Size/depth, invalid JSON/duplicate keys, or noncanonical representation |
| `UNSUPPORTED_PROFILE`, `UNSUPPORTED_VERSION`, `UNSUPPORTED_SUITE` | Unsupported identifier; verdict UNSUPPORTED |
| `SCHEMA`, `RANGE`, `UNTRUSTED_IDENTITY`, `BAD_SIGNATURE` | Field/type, bounds, trust or signature failure |
| `SCOPE`, `CONTENT_COMMITMENT` | Wrong Capsule/descriptor or payload size/digest |
| `INCOMPLETE_HISTORY` | Missing prefix or unavailable necessary proof; verdict INCOMPLETE |
| `HISTORY_CONFLICT`, `HISTORY_ORDER` | Contradictory retained proof or invalid chain/order |
| `LIFECYCLE`, `TIME`, `CONTENT_AUTHENTICATION` | Invalid transition, time semantics or authenticated decryption |

All other failures above have verdict INVALID. Operational submission rejections additionally use `REQUEST_ID_CONFLICT`, `STALE_BASIS`, `TOO_LATE`, `TERMINAL`, `CLOCK_UNAVAILABLE`, `CAPACITY`, or `INVALID_COMMAND`; they are not signed lifecycle facts. Query transport errors/timeout return no verified snapshot and leave current state unknown. Product code must not turn such errors into an authorizing result.

## Version axes and independent implementation

| Axis | Candidate value | Change rule |
|---|---|---|
| Specification document | `0.1-draft.2` | Editorial changes may leave wire behavior unchanged; semantic changes need review |
| Profile / object wire version | `otherwise.solo.v1` / `v=1` | Any accepted-byte or lifecycle change needs explicit compatibility decision, normally a new wire profile/version |
| Suite | Named v1 suite above | Algorithms/parameters/verification behavior cannot silently change |
| Reference package | `0.1.0a1` (Git tag `v0.1.0-alpha.1`) | Implementation version cannot redefine normative behavior |
| Conformance corpus | `solo-0.1.0` | Future corpus records spec/profile/suite and its own version/hash |

Unknown fields are not a covert extensibility mechanism. Future multiparty/stronger custody profiles must make their trust differences explicit. This alpha freezes its published identifiers and artifacts; it does not claim an external registry registration.

Phase B should have independent PHP parsing, canonical serialization, signature invocation, hash computation and lifecycle replay. PHP may use ext-sodium for crypto; it must not shell out to Python or import generated Python state decisions. Both tools must verify the same canonical fixture bytes and emit comparable structured results. Fixed positive and negative cases must constrain strict Ed25519 behavior, not just ordinary valid signatures. Shared library dependencies and untested security properties must be reported.

## Approved amendment compatibility

Recoverable export must return the exact committed canonical archive bytes, including the original ciphertext and release_box, after retry/restart. Capacity warnings are locally derived from verified sequence (`9999-s`, warning <=100); no new signed field, policy predicate or compatibility identifier is introduced. Synthetic backup formats are reference-demo artifacts, not normative protocol messages. These amendments leave v1 signed-byte formats unchanged.
