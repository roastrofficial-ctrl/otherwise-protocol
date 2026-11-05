"""Deterministic capacity-boundary recipe using fixture-only keys; no shortened limit."""
from otherwise_solo.codec import *
from otherwise_solo.crypto import sign
from generate import D,E1,OWNER,CUST

def prefix(count=9998):
    events=[E1]; head=digest(E1,'event'); hd=digest(D['body'],'descriptor')
    for seq in range(2,count+1):
        c=sign(OWNER,dict(header('command'),capsule_id=D['body']['capsule_id'],descriptor_hash=hd,
                         request_id=b64(seq.to_bytes(16,'big')),action='CHECKIN',basis=head))
        e=sign(CUST,dict(header('event'),capsule_id=D['body']['capsule_id'],descriptor_hash=hd,seq=seq,previous=head,
                        at=1000,clock='trusted',action='CHECKIN',command=c,release_box=None))
        events.append(e); head=digest(e,'event')
    return events
if __name__=='__main__':
    import sys
    from generate import CT
    from otherwise_solo.protocol import archive
    sys.stdout.buffer.write(canonical(archive(D,CT,prefix())))
