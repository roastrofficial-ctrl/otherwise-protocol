"""Portable stateful command scenarios; harness operations are not wire objects."""
from pathlib import Path
from otherwise_solo.codec import *
from otherwise_solo.crypto import sign
from otherwise_solo.client import command
import generate as f

def submit(c,at,*,error=None,expect=None,remember=None,equals=None,healthy=True):
    return dict(op='submit',at=at,healthy=healthy,command=c,error=error,expect=expect,remember=remember,equals=equals)
def call(op,at,**kw): return dict(op=op,at=at,healthy=kw.pop('healthy',True),**kw)

def generate(out):
    late=command(f.OWNER,f.D,'CHECKIN',basis=digest(f.E2,'event'),request_id=b64(f.fixed('late-request',16)))
    conflict=sign(f.OWNER,dict(f.CHECK['body'],basis=digest(f.E2,'event')))
    post=command(f.OWNER,f.D,'CHECKIN',basis=digest(f.E2,'event'),request_id=b64(f.fixed('post-request',16)))
    scenarios=[
        dict(name='renew-duplicate-conflict-late-and-cancel',steps=[
            submit(f.ARM,1000,expect={'action':'ARM','seq':1,'at':1000},remember='arm'),
            submit(f.CHECK,1070,expect={'action':'CHECKIN','seq':2,'at':1070},remember='check'),
            submit(f.CHECK,1071,equals='check'),
            submit(conflict,1071,error='REQUEST_ID_CONFLICT'),
            submit(f.CHECK,1141,equals='check'),
            submit(late,1141,error='TOO_LATE'),
            submit(f.DIS,1141,expect={'action':'DISARM','seq':3,'at':1141},remember='disarm'),
            submit(f.DIS,1142,equals='disarm'),submit(post,1142,error='TERMINAL'),submit(f.ARM,1142,equals='arm'),call('export',1142,expect={'state':'DISARMED','authorization':False})]),
        dict(name='committed-export-survives-restart-and-retry',steps=[
            submit(f.ARM,1000),call('evaluate',1070,error='TOO_EARLY'),
            call('evaluate',1071,expect={'state':'COMMITTED','authorization':True,'content':'DECRYPTED'},remember='committed'),
            call('restart',1072,healthy=False),call('export',1072,healthy=False,equals='committed'),
            call('evaluate',1072,healthy=False,equals='committed'),call('export',2000,equals='committed'),
            submit(f.DIS,2000,error='TERMINAL')]),
        dict(name='unhealthy-clock-does-not-remove-cancellation',steps=[
            submit(f.ARM,1000,remember='arm'),submit(f.ARM,999,healthy=False,equals='arm'),
            submit(f.CHECK,1070,healthy=False,error='CLOCK_UNAVAILABLE'),
            call('evaluate',1071,healthy=False,error='CLOCK_UNAVAILABLE'),
            submit(f.DIS,999,healthy=False,expect={'action':'DISARM','seq':2,'at':1000,'clock':'held'}),call('export',999,healthy=False,expect={'state':'DISARMED','authorization':False})]),
        dict(name='stale-unaccepted-request-does-not-extend-new-lease',steps=[
            submit(f.ARM,1000),submit(f.CHECK,1060),
            submit(command(f.OWNER,f.D,'CHECKIN',basis=f.HEAD,request_id=b64(f.fixed('stale-unaccepted',16))),1061,error='STALE_BASIS'),
            call('evaluate',1130,error='TOO_EARLY'),call('evaluate',1131,expect={'state':'COMMITTED','authorization':True,'content':'DECRYPTED'})])]
    value={'harness':'solo-lifecycle-0.1.0','fixture_only':True,'profile':PROFILE,'suite':SUITE,'setup':{
        'custodian_seed':b64(f.CUST),'custodian_box_secret':b64(f.BOX),'recipient_secret':b64(f.RECIP),
        'descriptor':f.D,'ciphertext':b64(f.CT),'pins':f.PINS},'scenarios':scenarios}
    Path(out).write_bytes(canonical(value)+b'\n')
    print('Wrote',len(scenarios),'portable lifecycle scenarios;',sum(len(s['steps']) for s in scenarios),'steps.')
if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(); parser.add_argument('--out',default=str(Path(__file__).with_name('lifecycle.json')))
    generate(parser.parse_args().out)
