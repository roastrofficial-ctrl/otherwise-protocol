"""Synthetic file/stdin transport custodian endpoint; no network or SaaS."""
import argparse
import sys
from .codec import parse,unb64,Fault,canonical,need
from .store import Custodian,TestClock

def main():
    p=argparse.ArgumentParser(); p.add_argument('--db',required=True); p.add_argument('--synthetic-now',required=True,type=int)
    args=p.parse_args()
    try:
        q=parse(sys.stdin.buffer.read(33554433)); service=Custodian(args.db,TestClock(args.synthetic_now))
        op=q['operation']
        if op=='submit': out=service.submit(unb64(q['descriptor']),unb64(q['ciphertext']),unb64(q['command']))
        elif op=='inspect': out=service.inspect(unb64(q['query']))
        elif op in ('evaluate','export'): out=getattr(service,op)(q['capsule_id'],q['descriptor_hash'])
        else: raise Fault('TRANSPORT')
        sys.stdout.buffer.write(out)
    except (Fault,KeyError) as e:
        sys.stdout.buffer.write(canonical({'code':e.code if isinstance(e,Fault) else 'SCHEMA'})); return 1
    return 0
if __name__=='__main__': sys.exit(main())
