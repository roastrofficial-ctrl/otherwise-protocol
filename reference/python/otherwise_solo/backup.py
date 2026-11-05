"""Unencrypted, synthetic-only backup demonstration; deliberately not a vault."""
import os
from pathlib import Path
from .codec import *
from .crypto import public,box_public

def write(path,role,secret):
    need(role in ('creator','recipient'))
    value={'synthetic_only':True,'role':role,'secret':b64(secret),
           'public':public(secret) if role=='creator' else box_public(secret)}
    raw=canonical(value)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as f: f.write(raw); f.flush(); os.fsync(f.fileno())

def restore(path,role,expected):
    value=parse(Path(path).read_bytes()); fields(value,{'synthetic_only','role','secret','public'})
    need(value['synthetic_only'] is True and value['role']==role and value['public']==expected,'UNTRUSTED_IDENTITY')
    secret=unb64(value['secret'],32)
    need((public(secret) if role=='creator' else box_public(secret))==expected,'UNTRUSTED_IDENTITY')
    return secret
