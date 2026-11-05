# Cryptography proposal

Release status: Solo v0.1 as specified by `0.1-draft.2`, included in `v0.1.0-alpha.1`. See [SPEC](../SPEC.md). Historical design/approval notes below are rationale; they add no build or runtime dependency.
This alpha uses the specified existing primitives. Their selection does not constitute independent review of the protocol composition.

## Selected single suite

Candidate suite ID: `ed25519-sha256-aes256gcm-sodiumseal-v1`.

| Function | Selection | Public specification |
|---|---|---|
| Signatures | Pure Ed25519; 32-byte public keys, 64-byte signatures | [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) |
| Commitments | SHA-256 with explicit object domains | [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final) |
| Content | AES-256-GCM; fresh 32-byte key, 12-byte nonce, full 16-byte tag | [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final) |
| Key delivery | Sodium `crypto_box_seal`, X25519/XSalsa20-Poly1305 | [Sodium sealed boxes](https://libsodium.gitbook.io/doc/public-key_cryptography/sealed_boxes) |

Use audited library primitives, not locally implemented curve arithmetic or invented key wrapping. Sodium sealed boxes have an existing fixed construction and format, rather than an Otherwise-specific DH/KDF/AEAD composition. They do not authenticate a sender by themselves; the creator's ARM signature or custodian's RELEASE signature supplies that binding. This selection favors available [PHP Sodium](https://www.php.net/manual/en/function.sodium-crypto-box-seal.php) and [PyNaCl SealedBox](https://pynacl.readthedocs.io/en/latest/public/) interfaces. Those bindings share a cryptographic implementation family; a Python/PHP comparison demonstrates independent protocol parsing/evaluation, not independent cryptographic-library assurance.

HPKE (RFC 9180) is a credible standardized alternative. It was not selected for the smallest first Python/PHP profile because Sodium supplies both required language interfaces without assembling another cryptographic adapter. Approval may select HPKE instead, but that changes the suite and demands its own byte-level tests before implementation. AES-GCM is retained from the research's established content-encryption primitive; the distributed P-256 proof machinery is not retained.

## Keys and ownership

| Material | Generated and retained by | Exposure and loss |
|---|---|---|
| Creator Ed25519 seed | Independently trusted local creator client, using OS CSPRNG | Loss of all copies prevents new check-in/disarm. Theft enables both until terminal state. SaaS password reset cannot recover it. |
| Capsule DEK | Creator client, independently random per Capsule | Creator and custodian know it; both can decrypt early. Never reuse across Capsules or put in logs, product storage or public artifacts. |
| Custodian Ed25519 key | Custodian outside SaaS; authenticated public fingerprint supplied independently | Theft allows forged receipts and forks. No in-place replacement is defined. |
| Custodian box secret | Custodian, distinct from signing key | Compromise may decrypt retained enrollment boxes. No forward-secrecy claim for archived enrollment. |
| Recipient box secret | Recipient's independently trusted client; public key authenticated to creator | Loss prevents recipient recovery. Theft plus a retained release package permits decryption. No recipient account-reset bypass. |
| Capsule ID, request IDs, challenges, GCM nonce | OS CSPRNG in the actor creating them | IDs are not passwords. Challenges are never reused. Nonce/key reuse is forbidden. |

Private key generation/storage are local provider/client responsibilities. Encrypted private storage, access control and backed-up recovery are required operational concerns, but a particular password KDF/vault file is not a wire primitive. A vault format needs separate review in Phase B. Software memory deletion is not guaranteed. Backups and cloned creator devices retain authority; “logging out” cannot revoke a copied signing seed. Local client authenticity, OS and dependency trust remain assumptions.

## Content construction and bindings

1. Generate independent Capsule ID, DEK and nonce. Authenticate all three parties' public keys out of band.
2. Form descriptor core `C` by taking the exact descriptor body and omitting only `ciphertext_hash` and `ciphertext_size`.
3. Set `AAD = ASCII("otherwise/solo/1/content\n") || JCS(C)`.
4. Encrypt raw plaintext bytes once with AES-256-GCM(DEK, nonce, AAD). Ciphertext is encrypted bytes followed immediately by the 16-byte tag. The nonce is in the descriptor, not prepended to ciphertext.
5. Add SHA-256(raw ciphertext) and byte size to form the complete descriptor body; sign it. This commits the policy, recipient and payload without a hash cycle.
6. Compute `hD` from the complete body. Seal the exact 64 bytes `raw(hD)||DEK` to the pinned custodian box public key. Include the resulting 112-byte `enrollment_box` in the signed ARM command.
7. Before durable activation, custodian opens the box, verifies hD, verifies ciphertext digest/size and successfully AEAD-decrypts. It retains protected DEK and ciphertext. It must not return plaintext to a SaaS caller.
8. When release wins, custodian seals the same 64-byte binding/key tuple to the recipient box public key. Commit the exact 112-byte `release_box` in the signed terminal event before exporting it.
9. Recipient verifies complete authorization first, opens the box, compares hD, then decrypts content using the original AAD/nonce. Abort on any mismatch or AEAD failure; do not expose unauthenticated plaintext.

The sealed-box format is Sodium's ephemeral 32-byte public key followed by the authenticated `crypto_box` ciphertext, with 48 bytes total overhead. Its nonce is the 24-byte BLAKE2b output over ephemeral public key concatenated with recipient public key, as specified by Sodium. There is no caller-selected nonce, raw X25519 output, custom HKDF step or Ed25519-to-X25519 key conversion in this profile. The 64-byte inside binding is protocol context, not a new encryption primitive.

Use fresh ephemeral randomness for real boxes. A box regenerated on retry would change the signed command or terminal event; retain and resend the original instead. Fixture-only deterministic key generation may be used in the future corpus, isolated from real code paths. No final vectors are generated in Phase A.

## What custody does and does not enforce

The custodian has the content key at ARM. Its software follows policy; its administrator can bypass that software, decrypt early, hand plaintext to another party, forge its own time/history or leak an internally prepared release box. Encryption to the recipient protects exported material from unrelated readers; it does not constrain the custodian's prior access. A creator can retain or send plaintext independently. Disarm stops the honest provider's future release path; it does not erase previous knowledge or revoke a package already exported.

There is no Shamir sharing, threshold DH, DLEQ proof, DKG, HSM claim, secure erasure claim, cryptographic release predicate, long-term forward secrecy or resistance to combined administrative control. A future custody profile must declare different capabilities and evidence; it cannot merely relabel this provider.

## Provider capabilities

Before ARM, an adapter must require: this exact profile/version/suite; per-Capsule atomic durable ordering; exact receipt recovery; independent inspection and release export; no admin creator substitution; terminal disarm enforcement in the honest implementation; protected payload/key persistence; and a health-qualified clock. The provider must explicitly advertise `operator_can_decrypt_early=true`, `cryptographic_policy_enforcement=false`, `single_custodian=true` in deployment documentation. These are capability declarations checked against client requirements, not proof that the operator tells the truth.

An application requiring operator-resistant early-decryption prevention must reject this profile. It must not infer that property from transport TLS, a “commercial” label, signatures or compliance metadata. Phase B must test that such a requirement is refused, not silently downgraded.

## Approved synthetic backup scope

The reference demonstration will use labelled synthetic private-key files with restrictive file permissions, copied to an independent temporary backup directory and restored without Cloud. Backup files are laboratory capabilities, not a production vault format, password recovery system or promise of encrypted-at-rest key protection. Restore validates the original public fingerprints and proves creator signing or recipient package decryption. Wrong/missing keys cannot be replaced by an account administrator. Never use demonstration identities or backups for real data. A stolen backup has the same authority as the original key; deleting a working file does not revoke another copy.
