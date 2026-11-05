"""Existing primitives. Strict-point check includes Sodium's published workaround."""
from nacl import bindings as sodium
from nacl.public import PrivateKey, PublicKey, SealedBox
from nacl.signing import SigningKey, VerifyKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .codec import b64, unb64, canonical, need, Fault

L = 2**252 + 27742317777372353535851937790883648493
IDENTITY = b'\x01' + b'\0' * 31

def point_valid(p):
    try:
        # <=1.0.20 is_valid_point alone accepted some mixed-subgroup points.
        return (sodium.crypto_core_ed25519_is_valid_point(p) and
                sodium.crypto_core_ed25519_add(
                    sodium.crypto_scalarmult_ed25519_noclamp((L-1).to_bytes(32, 'little'), p), p) == IDENTITY)
    except Exception:
        return False

def sign(seed, body):
    msg = ('otherwise/solo/1/sign/' + body['kind'] + '\n').encode() + canonical(body)
    return {'body': body, 'signature': b64(SigningKey(seed).sign(msg).signature)}

def verify_signature(key, envelope):
    pk, sig = unb64(key, 32), unb64(envelope['signature'], 64)
    need(point_valid(pk) and point_valid(sig[:32]) and int.from_bytes(sig[32:], 'little') < L, 'BAD_SIGNATURE')
    msg = ('otherwise/solo/1/sign/' + envelope['body']['kind'] + '\n').encode() + canonical(envelope['body'])
    try:
        VerifyKey(pk).verify(msg, sig)
    except Exception:
        raise Fault('BAD_SIGNATURE') from None

def public(seed):
    return b64(bytes(SigningKey(seed).verify_key))

def box_public(secret):
    return b64(bytes(PrivateKey(secret).public_key))

def seal(key, data):
    return b64(SealedBox(PublicKey(unb64(key, 32))).encrypt(data))

def open_box(secret, box):
    try:
        return SealedBox(PrivateKey(secret)).decrypt(unb64(box, 112))
    except Exception:
        raise Fault('CONTENT_AUTHENTICATION') from None

def aad(body):
    core = {k: v for k, v in body.items() if k not in ('ciphertext_hash', 'ciphertext_size')}
    return b'otherwise/solo/1/content\n' + canonical(core)

def decrypt_content(body, ciphertext, dek):
    try:
        return AESGCM(dek).decrypt(unb64(body['nonce'], 12), ciphertext, aad(body))
    except Exception:
        raise Fault('CONTENT_AUTHENTICATION') from None
