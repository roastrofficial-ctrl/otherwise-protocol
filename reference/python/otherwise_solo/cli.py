"""Synthetic-only standalone client. No accounts, SaaS, message input or delivery."""
import argparse
import os
import sys
import time
from pathlib import Path
from .codec import *
from .crypto import *
from .client import create,command,capacity
from .backup import write,restore
from .protocol import archive,verify
from .store import initialize,Custodian
from .transport import FileTransport,HTTPSTransport

def save(path,value):
    raw=canonical(value); tmp=Path(str(path)+'.tmp')
    fd=os.open(tmp,os.O_CREAT|os.O_TRUNC|os.O_WRONLY,0o600)
    with os.fdopen(fd,'wb') as f: f.write(raw); f.flush(); os.fsync(f.fileno())
    os.replace(tmp,path)

def main():
    os.umask(0o077)
    p=argparse.ArgumentParser(description=__doc__); sub=p.add_subparsers(dest='operation',required=True)
    init=sub.add_parser('init-custodian'); init.add_argument('--db',required=True)
    ids=sub.add_parser('init-identities'); ids.add_argument('--directory',required=True)
    draft=sub.add_parser('create'); draft.add_argument('--identities',required=True); draft.add_argument('--custodian-public',required=True); draft.add_argument('--out',required=True)
    act=sub.add_parser('act'); act.add_argument('action',choices=['arm','checkin','status','disarm','release','export']); act.add_argument('--file',required=True); act.add_argument('--creator'); act.add_argument('--endpoint',required=True); act.add_argument('--ca'); act.add_argument('--synthetic-now',type=int,default=1000)
    verify_cmd=sub.add_parser('verify'); verify_cmd.add_argument('--file',required=True); verify_cmd.add_argument('--pins',required=True); verify_cmd.add_argument('--recipient')
    args=p.parse_args()
    try:
        if args.operation=='init-custodian':
            initialize(args.db); sys.stdout.buffer.write(canonical(Custodian(args.db).keys)); return 0
        if args.operation=='init-identities':
            directory=Path(args.directory); directory.mkdir(mode=0o700)
            owner,recipient=os.urandom(32),os.urandom(32)
            write(directory/'creator.json','creator',owner); write(directory/'recipient.json','recipient',recipient)
            save(directory/'public.json',{'creator_key':public(owner),'recipient_key':box_public(recipient),'synthetic_only':True}); return 0
        if args.operation=='create':
            ids=Path(args.identities); pins=parse((ids/'public.json').read_bytes()); owner=restore(ids/'creator.json','creator',pins['creator_key'])
            cust=parse(Path(args.custodian_public).read_bytes())
            d,ct,dek=create(owner,cust['custodian_key'],cust['custodian_box_key'],pins['recipient_key'])
            expected={k:d['body'][k] for k in ('creator_key','custodian_key','custodian_box_key','recipient_key')}
            save(args.out,{'synthetic_only':True,'archive':archive(d,ct,[]),'arm':command(owner,d,'ARM',dek=dek),'pins':expected})
            print('Synthetic Capsule created; not armed.'); return 0
        if args.operation=='verify':
            a=parse(Path(args.file).read_bytes()); pins=parse(Path(args.pins).read_bytes()); secret=None
            if args.recipient: secret=restore(args.recipient,'recipient',pins['recipient_key'])
            result=verify(canonical(a),pins,recipient=secret); print(canonical(result).decode()); return 0 if result['verdict']=='VALID' else 1
        state=parse(Path(args.file).read_bytes()); need(state['synthetic_only'] is True,'SYNTHETIC_ONLY')
        a=state['archive']; d=a['descriptor']; cid=d['body']['capsule_id']; hd=digest(d['body'],'descriptor'); ct=unb64(a['ciphertext'])
        transport=FileTransport(args.endpoint[5:],args.synthetic_now) if args.endpoint.startswith('file:') else HTTPSTransport(args.endpoint,args.ca)
        anchors={str(e['body']['seq']):digest(e,'event') for e in a['events']}
        query=dict(header('inspect'),capsule_id=cid,descriptor_hash=hd,challenge=b64(os.urandom(32)))
        # Reconcile complete authoritative prefix before building a new head-bound command.
        started=time.monotonic(); snapshot=transport.inspect(canonical(query)); elapsed=time.monotonic()-started
        snap=parse(snapshot); recovered=archive(d,ct,snap['body']['events'])
        result=verify(canonical(recovered),state['pins'],anchors=anchors,snapshot=snapshot,challenge=query['challenge'],elapsed=elapsed)
        need(result['verdict']=='VALID',result['code']); a=recovered
        if args.action in ('arm','checkin','disarm'):
            need(args.creator is not None,'UNTRUSTED_IDENTITY')
            owner=restore(args.creator,'creator',state['pins']['creator_key'])
            pending=state.get('pending')
            if pending and pending['body']['action']=='CHECKIN' and pending['body']['basis']!=result['head']:
                if not any(e['body']['command']==pending for e in a['events']): pending=None
            c=pending if pending and pending['body']['action']==args.action.upper() else state['arm'] if args.action=='arm' else command(owner,d,args.action.upper(),basis=result['head'] if args.action=='checkin' else None)
            state['archive']=a; state['pending']=c; save(args.file,state)
            receipt=parse(transport.submit(canonical(d),ct,canonical(c)),8192)
            need(receipt.get('body',{}).get('command')==c,'SCOPE')
            # A duplicate ARM returns an older receipt; retain/recover the current prefix next time.
            if receipt['body']['seq']>len(a['events']): a['events'].append(receipt)
            else: need(a['events'][receipt['body']['seq']-1]==receipt,'HISTORY_CONFLICT')
            check=verify(canonical(a),state['pins'],anchors=anchors)
            need(check['verdict']=='VALID',check['code']); result=check
        elif args.action in ('release','export'):
            raw=getattr(transport,'evaluate' if args.action=='release' else 'export')(cid,hd)
            check=verify(raw,state['pins'],anchors=anchors); need(check['verdict']=='VALID',check['code']); a=parse(raw); result=check
        state['archive']=a; state.pop('pending',None); save(args.file,state)
        # Only acknowledge after independent verification AND local retention.
        print(canonical({'verification':result,'capacity':capacity(a['events']),'synthetic_only':True}).decode())
        return 0
    except (Fault,OSError,EOFError) as e:
        print(canonical({'code':e.code if isinstance(e,Fault) else 'LOCAL_OR_TRANSPORT_FAILURE','status':'unconfirmed'}).decode())
        return 1
if __name__=='__main__': sys.exit(main())
