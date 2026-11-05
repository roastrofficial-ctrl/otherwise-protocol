"""Deterministic, fixture-only corpus. Expected decisions are declared, not queried."""
import copy
import hashlib
import json
import subprocess
from pathlib import Path
from nacl.bindings import crypto_box,crypto_box_keypair
from nacl.public import PrivateKey
from otherwise_solo.codec import *
from otherwise_solo.crypto import *
from otherwise_solo.client import create,command

ROOT=Path(__file__).resolve().parent
OWNER=hashlib.sha256(b'fixture-owner').digest()
CUST=hashlib.sha256(b'fixture-custodian').digest()
BOX=hashlib.sha256(b'fixture-box').digest()
RECIP=hashlib.sha256(b'fixture-recipient').digest()
def fixed(s,n=32): return hashlib.sha256(s.encode()).digest()[:n]
def fixture_seal(pk,msg,label):
    sk=fixed('ephemeral-'+label+'-'+rawhash(msg)); epk=bytes(PrivateKey(sk).public_key); pk=unb64(pk,32)
    nonce=hashlib.blake2b(epk+pk,digest_size=24).digest()
    return b64(epk+crypto_box(msg,nonce,pk,sk))

counter=0
def random(n):
    global counter
    counter+=1
    return fixed('fixture-random-'+str(counter),n)
D,CT,DEK=create(OWNER,public(CUST),box_public(BOX),box_public(RECIP),random=random)
HD=digest(D['body'],'descriptor')
PINS={k:D['body'][k] for k in ('creator_key','custodian_key','custodian_box_key','recipient_key')}
ARM=command(OWNER,D,'ARM',dek=DEK,request_id=b64(fixed('arm-request',16)))
ARM['body']['enrollment_box']=fixture_seal(D['body']['custodian_box_key'],unb64(HD)+DEK,'enroll')
ARM=sign(OWNER,ARM['body'])
def event(action,at,previous=None,cmd=None,seq=1,clock='trusted',box=None):
    return sign(CUST,dict(header('event'),capsule_id=D['body']['capsule_id'],descriptor_hash=HD,seq=seq,previous=previous,
                         at=at,clock=clock,action=action,command=cmd,release_box=box))
E1=event('ARM',1000,cmd=ARM)
HEAD=digest(E1,'event')
CHECK=command(OWNER,D,'CHECKIN',basis=HEAD,request_id=b64(fixed('check-request',16)))
E2=event('CHECKIN',1070,HEAD,CHECK,2)
DIS=command(OWNER,D,'DISARM',request_id=b64(fixed('disarm-request',16)))
ED=event('DISARM',1071,HEAD,DIS,2)
RB=fixture_seal(D['body']['recipient_key'],unb64(HD)+DEK,'release')
ER=event('RELEASE',1071,HEAD,None,2,box=RB)
def arch(events,d=None,ct=None): return dict(header('archive'),descriptor=d or D,ciphertext=b64(CT if ct is None else ct),events=events)
CASES=[]
def add(name,a,*,state='UNKNOWN',code='OK_HISTORY',verdict='VALID',options=None,pins=None,hash_present=True,content='NOT_ATTEMPTED',freshness='HISTORICAL'):
    raw=a if isinstance(a,bytes) else canonical(a)
    desc=(a.get('descriptor',D) if isinstance(a,dict) else D)
    hd=digest(desc['body'],'descriptor') if hash_present else None
    ev=a.get('events',[]) if isinstance(a,dict) else []
    valid=verdict=='VALID'
    expected=dict(header('verification'),descriptor_hash=hd,verdict=verdict,state=state if valid else 'UNKNOWN',
                  head=digest(ev[-1],'event') if valid and ev else None,
                  authorization=(state=='COMMITTED') if valid and state!='UNKNOWN' else None,
                  content=content,freshness=freshness if valid else 'UNKNOWN',code=code)
    CASES.append(dict(name=name,input=b64(raw),pins=pins or PINS,options=options or {},expected=expected))
def bad(name,a,code,**kw): add(name,a,code=code,verdict='UNSUPPORTED' if code.startswith('UNSUPPORTED_') else 'INCOMPLETE' if code=='INCOMPLETE_HISTORY' else 'INVALID',**kw)
def revent(e,**changes):
    b=copy.deepcopy(e['body']); b.update(changes); return sign(CUST,b)

def generate(output=None):
    CASES.clear()
    add('unarmed-recorded-prefix',arch([]),state='UNARMED')
    add('activated-history',arch([E1]))
    for t,s in [(1000,'ARMED'),(1060,'ARMED'),(1061,'GRACE'),(1070,'GRACE'),(1071,'ELIGIBLE')]:
        add('boundary-'+str(t),arch([E1]),state=s,options={'at':t})
    add('grace-renewal',arch([E1,E2]),state='ARMED',options={'at':1070})
    add('public-release',arch([E1,ER]),state='COMMITTED',code='OK_RELEASE')
    add('recipient-release',arch([E1,ER]),state='COMMITTED',code='OK_RELEASE',content='DECRYPTED',options={'recipient':b64(RECIP)})
    add('disarm-after-eligibility',arch([E1,ED]),state='DISARMED',code='OK_DISARM')
    add('held-clock-disarm',arch([E1,revent(ED,at=1000,clock='held')]),state='DISARMED',code='OK_DISARM')
    bad('release-at-inclusive-grace',arch([E1,revent(ER,at=1070)]),'TIME')
    bad('late-checkin',arch([E1,revent(E2,at=1071)]),'TIME')
    bad('held-release',arch([E1,revent(ER,clock='held')]),'TIME')
    bad('held-disarm-changed-time',arch([E1,revent(ED,clock='held')]),'TIME')
    bad('decreasing-event-time',arch([E1,revent(ED,at=999)]),'TIME')
    bad('missing-activation-prefix',arch([ER]),'INCOMPLETE_HISTORY')
    bad('wrong-previous',arch([E1,revent(ER,previous=b64(b'z'*32))]),'HISTORY_ORDER')
    bad('sequence-gap',arch([E1,revent(ER,seq=3)]),'HISTORY_ORDER')
    bad('reordered-events',arch([ER,E1]),'INCOMPLETE_HISTORY')
    extra=revent(ED,seq=3,previous=digest(ER,'event'))
    bad('post-release-disarm',arch([E1,ER,extra]),'LIFECYCLE')
    bad('post-disarm-release',arch([E1,ED,revent(ER,seq=3,previous=digest(ED,'event'))]),'LIFECYCLE')
    bad('event-scope',arch([E1,revent(ER,descriptor_hash=b64(b'z'*32))]),'SCOPE')
    stale=command(OWNER,D,'CHECKIN',basis=b64(b'z'*32),request_id=b64(fixed('stale',16)))
    bad('checkin-stale-basis',arch([E1,revent(E2,command=stale)]),'HISTORY_ORDER')
    bad('request-id-reused',arch([E1,E2,revent(E2,seq=3,previous=digest(E2,'event'))]),'HISTORY_ORDER')
    x=arch([E1,ER],ct=bytes([CT[0]^1])+CT[1:]); bad('payload-substitution',x,'CONTENT_COMMITMENT')
    x=copy.deepcopy(arch([E1,ER])); x['descriptor']['body']['interval']=61; bad('policy-substitution',x,'BAD_SIGNATURE')
    pins=dict(PINS,recipient_key=b64(b'z'*32)); bad('recipient-pin-substitution',arch([E1,ER]),'UNTRUSTED_IDENTITY',pins=pins)
    x=copy.deepcopy(arch([E1,ER])); x['events'][1]['signature']=b64(b'z'*64); bad('invalid-event-signature',x,'BAD_SIGNATURE')
    wrong_domain=copy.deepcopy(ER); wrong_domain['signature']=sign(CUST,dict(ER['body'],kind='snapshot'))['signature']
    bad('signature-domain-confusion',arch([E1,wrong_domain]),'BAD_SIGNATURE')
    sig=unb64(ER['signature']); noncanonical=dict(ER,signature=b64(sig[:32]+L.to_bytes(32,'little')))
    bad('ed25519-S-equals-L',arch([E1,noncanonical]),'BAD_SIGNATURE')
    for label,p in [('identity',IDENTITY),('noncanonical',b'\xff'*32),('small-order',b'\0'*32),('mixed-subgroup',sodium.crypto_core_ed25519_add(unb64(public(CUST)),b'\0'*32))]:
        e=dict(ER,signature=b64(p+sig[32:])); bad('ed25519-R-'+label,arch([E1,e]),'BAD_SIGNATURE')
        d=copy.deepcopy(D); d['body']['creator_key']=b64(p); pins=dict(PINS,creator_key=b64(p))
        bad('ed25519-A-'+label,arch([E1],d=d),'BAD_SIGNATURE',pins=pins)
    bad('wrong-recipient-secret',arch([E1,ER]),'CONTENT_AUTHENTICATION',content='FAILED',options={'recipient':b64(b'x'*32)})
    bad('corrupt-key-box',arch([E1,revent(ER,release_box=b64(b'x'*112))]),'CONTENT_AUTHENTICATION',content='FAILED',options={'recipient':b64(RECIP)})
    bad('retained-anchor-conflict',arch([E1,ER]),'HISTORY_CONFLICT',options={'anchors':{'1':b64(b'x'*32)}})
    bad('retained-later-anchor',arch([E1]),'INCOMPLETE_HISTORY',options={'anchors':{'2':digest(ER,'event')}})
    add('retained-anchor-matches',arch([E1,ER]),state='COMMITTED',code='OK_RELEASE',options={'anchors':{'1':HEAD}})
    for key,value,code in [('profile','other','UNSUPPORTED_PROFILE'),('v',2,'UNSUPPORTED_VERSION'),('suite','other','UNSUPPORTED_SUITE')]:
        x=arch([E1]); x[key]=value; bad('unknown-'+key,x,code,hash_present=False)
    x=copy.deepcopy(arch([E1])); x['descriptor']['body']['extra']='x'; bad('unknown-descriptor-member',x,'SCHEMA',hash_present=False)
    x=copy.deepcopy(arch([E1])); x['descriptor']['body']['interval']=True; bad('boolean-interval',x,'SCHEMA',hash_present=False)
    for key,value in [('interval',59),('grace',0),('ciphertext_size',1048593)]:
        x=copy.deepcopy(arch([E1])); x['descriptor']['body'][key]=value; bad('range-'+key,x,'RANGE',hash_present=False)
    raw=canonical(arch([E1]))
    for label,invalid,code in [('whitespace',b' '+raw,'NONCANONICAL'),('duplicate',b'{"v":1,"v":1}','MALFORMED'),('escaped-duplicate',b'{"v":1,"\\u0076":1}','MALFORMED'),
                              ('exponent',raw.replace(b'"v":1',b'"v":1e0',1),'NONCANONICAL'),('negative-zero',raw.replace(b'"v":1',b'"v":-0',1),'NONCANONICAL'),
                              ('float',raw.replace(b'"v":1',b'"v":1.0',1),'NONCANONICAL'),('integer-overflow',raw.replace(b'"v":1',b'"v":9007199254740992',1),'RANGE'),
                              ('unicode',raw.replace(b'"archive"',b'"archiv\xc3\xa9"',1),'SCHEMA'),('escaped-ascii',raw.replace(b'"archive"',b'"\\u0061rchive"',1),'NONCANONICAL'),
                              ('NaN',raw.replace(b'\"v\":1',b'\"v\":NaN',1),'NONCANONICAL'),('Infinity',raw.replace(b'\"v\":1',b'\"v\":Infinity',1),'NONCANONICAL'),('surrogate',raw.replace(b'\"archive\"',b'\"\\ud800\"',1),'SCHEMA'),('nested-duplicate',raw.replace(b'\"seq\":1',b'\"seq\":1,\"seq\":1',1),'MALFORMED'),('BOM',b'\xef\xbb\xbf'+raw,'MALFORMED'),('trailing',raw+b'x','MALFORMED'),('depth',b'['*17+b'0'+b']'*17,'LIMIT')]:
        bad('encoding-'+label,invalid,code,hash_present=False)
    x=arch([E1]); x['ciphertext']+='='; bad('padded-base64',x,'SCHEMA',hash_present=False)
    bad('known-signed-terminal-fork',arch([E1,ER]),'HISTORY_CONFLICT',options={'anchors':{'2':digest(ED,'event')}})
    # Authenticated claims cannot make a malformed content key/tag/AAD objectively correct.
    for label,change_policy,corrupt_tag in [('bad-tag',False,True),('wrong-content-AAD',True,False)]:
        ct=CT[:-1]+bytes([CT[-1]^1]) if corrupt_tag else CT
        db=copy.deepcopy(D['body'])
        if change_policy: db['interval']=61
        db['ciphertext_hash']=rawhash(ct); dd=sign(OWNER,db); hh=digest(db,'descriptor')
        cb=copy.deepcopy(ARM['body']); cb['descriptor_hash']=hh
        cb['enrollment_box']=fixture_seal(db['custodian_box_key'],unb64(hh)+DEK,label+'-enroll')
        cc=sign(OWNER,cb)
        eb=dict(E1['body'],descriptor_hash=hh,command=cc); ee=sign(CUST,eb)
        rr=sign(CUST,dict(ER['body'],descriptor_hash=hh,at=1072,previous=digest(ee,'event'),
                         release_box=fixture_seal(db['recipient_key'],unb64(hh)+DEK,label+'-release')))
        aa=arch([ee,rr],d=dd,ct=ct)
        add(label+'-public-claim',aa,state='COMMITTED',code='OK_RELEASE')
        bad(label+'-recipient-rejects',aa,'CONTENT_AUTHENTICATION',content='FAILED',options={'recipient':b64(RECIP)})
    # Schema and numeric bounds in the complete signed object graph.
    x=copy.deepcopy(arch([E1])); x['events'][0]['body']['at']=MAXINT
    x['events'][0]=sign(CUST,x['events'][0]['body']); bad('deadline-overflow',x,'RANGE')
    x=copy.deepcopy(arch([E1])); x['descriptor']['body']['creator_key']=x['descriptor']['body']['creator_key'][:-1]+'B'
    bad('base64-nonzero-spare-bits',x,'SCHEMA',hash_present=False)
    x=copy.deepcopy(arch([E1])); x['events'][0]['body']['extra']=True; bad('unknown-event-member',x,'SCHEMA')
    x=copy.deepcopy(arch([E1])); x['events'][0]['body']['command']['body']['basis']='not-null'; bad('null-required',x,'SCHEMA')
    x=copy.deepcopy(arch([E1])); x['events'][0]['body']['v']=2; bad('nested-unknown-version',x,'UNSUPPORTED_VERSION',hash_present=False)
    x=copy.deepcopy(arch([E1])); x['events'][0]['signature']=b64(b'z'*64); x['v']=2
    bad('precedence-version-before-signature',x,'UNSUPPORTED_VERSION',hash_present=False)
    x=copy.deepcopy(arch([E1])); x['events'][0]['signature']=b64(b'z'*64)
    bad('precedence-trust-before-signature',x,'UNTRUSTED_IDENTITY',pins=dict(PINS,creator_key=b64(b'z'*32)))
    x=arch([{}]*10001); bad('event-count-limit',x,'LIMIT',hash_present=False)
    # Snapshot fixtures: sampled times are historical claims, challenge context supplied independently.
    q=b64(fixed('query')); sb=dict(header('snapshot'),capsule_id=D['body']['capsule_id'],descriptor_hash=HD,challenge=q,head=HEAD,sampled_at=1061,clock='trusted',events=[E1])
    snap=sign(CUST,sb); opts={'snapshot':b64(canonical(snap)),'challenge':q,'elapsed':1}
    add('fresh-snapshot',arch([E1]),state='GRACE',code='OK_SNAPSHOT',freshness='SAMPLED',options=opts)
    bad('cached-snapshot-challenge',arch([E1]),'TIME',options=dict(opts,challenge=b64(fixed('other-query'))))
    bad('snapshot-timeout',arch([E1]),'TIME',options=dict(opts,elapsed=11))
    unavailable=sign(CUST,dict(sb,clock='unavailable',sampled_at=None))
    add('unavailable-clock-snapshot',arch([E1]),code='OK_SNAPSHOT',freshness='SAMPLED',options=dict(opts,snapshot=b64(canonical(unavailable))))
    # Independent PHP-produced bytes, checked against text-derived expected outcome in both languages.
    produced=json.loads(subprocess.check_output(['php','-d','ffi.enable=true',str(ROOT/'produce.php')]))
    pa=parse(unb64(produced['input']))
    add('php-produced-offline-release',pa,state='COMMITTED',code='OK_RELEASE',content='DECRYPTED',pins=produced['pins'],options=produced['options'])
    target=Path(output) if output is not None else ROOT/'vectors.json'
    output={'corpus':'solo-0.1.0','spec':'0.1-draft.2','profile':PROFILE,'suite':SUITE,'fixture_only':True,'cases':CASES}
    target.write_bytes(canonical(output)+b'\n')
    print('Wrote',len(CASES),'declared-result fixtures; deterministic keys are TEST ONLY.')
if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(); parser.add_argument('--out'); generate(parser.parse_args().out)
