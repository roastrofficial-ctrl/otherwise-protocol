"""Synthetic creator helpers. No user-content ingestion or account authority."""
import os
from .codec import *
from .crypto import *
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SYNTHETIC = b'OTHERWISE SYNTHETIC CAPSULE - laboratory content only.'

def create(creator,custodian,custodian_box,recipient,*,interval=60,grace=10,random=os.urandom):
    dek=random(32)
    b=dict(header('descriptor'),capsule_id=b64(random(16)),creator_key=public(creator),
           custodian_key=custodian,custodian_box_key=custodian_box,recipient_key=recipient,
           interval=interval,grace=grace,nonce=b64(random(12)))
    ct=AESGCM(dek).encrypt(unb64(b['nonce'],12),SYNTHETIC,aad(b))
    b.update(ciphertext_hash=rawhash(ct),ciphertext_size=len(ct))
    return sign(creator,b),ct,dek

def command(seed,d,action,*,basis=None,dek=None,request_id=None):
    b=dict(header('command'),capsule_id=d['body']['capsule_id'],descriptor_hash=digest(d['body'],'descriptor'),
           request_id=request_id or b64(os.urandom(16)),action=action,basis=basis)
    if action=='ARM': b['enrollment_box']=seal(d['body']['custodian_box_key'],unb64(b['descriptor_hash'])+dek)
    return sign(seed,b)

def capacity(events):
    s=events[-1]['body']['seq'] if events else 0
    remaining=max(0,9999-s)
    return {'remaining_checkins':remaining,'warning':remaining<=100,
            'exhausted':remaining==0,'indefinite_continuity':False}

def compatible(requirements):
    capabilities={'profile':PROFILE,'suite':SUITE,'single_custodian':True,
                  'operator_can_decrypt_early':True,'cryptographic_policy_enforcement':False,
                  'durable_order':True,'receipt_recovery':True,'recoverable_release':True}
    need(all(k in capabilities and capabilities[k]==v for k,v in requirements.items()),'UNSUPPORTED_PROFILE')
    return capabilities
