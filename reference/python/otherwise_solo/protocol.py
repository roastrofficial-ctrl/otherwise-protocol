"""Normative object validation and deterministic replay; no persistence or sockets."""
from .codec import *
from .crypto import verify_signature, open_box, decrypt_content

DESC = H | {'capsule_id','creator_key','custodian_key','custodian_box_key','recipient_key','interval','grace','nonce','ciphertext_hash','ciphertext_size'}
CMD = H | {'capsule_id','descriptor_hash','request_id','action','basis'}
EVENT = H | {'capsule_id','descriptor_hash','seq','previous','at','clock','action','command','release_box'}
SNAP = H | {'capsule_id','descriptor_hash','challenge','head','sampled_at','clock','events'}
ARCHIVE = H | {'descriptor','ciphertext','events'}
KEYS = ('creator_key','custodian_key','custodian_box_key','recipient_key')

def envelope(e):
    fields(e, {'body','signature'})
    unb64(e['signature'],64)
    need(type(e['body']) is dict)

def scope_shape(b):
    unb64(b['capsule_id'],16)
    if 'descriptor_hash' in b: unb64(b['descriptor_hash'],32)

def descriptor_shape(e):
    envelope(e); b=e['body']; check_header(b,'descriptor'); fields(b,DESC)
    scope_shape(b)
    for k in KEYS: unb64(b[k],32)
    unb64(b['nonce'],12); unb64(b['ciphertext_hash'],32)
    uint(b['interval'],60,31536000); uint(b['grace'],1,2592000)
    uint(b['ciphertext_size'],16,1048592)

def command_shape(e):
    envelope(e); b=e['body']; check_header(b,'command')
    need(b.get('action') in ('ARM','CHECKIN','DISARM'))
    fields(b, CMD | ({'enrollment_box'} if b['action']=='ARM' else set()))
    scope_shape(b); unb64(b['request_id'],16)
    if b['action']=='CHECKIN': unb64(b['basis'],32)
    else: need(b['basis'] is None)
    if b['action']=='ARM': unb64(b['enrollment_box'],112)

def event_shape(e):
    envelope(e); b=e['body']; check_header(b,'event'); fields(b,EVENT)
    scope_shape(b); uint(b['seq'],1,MAXEVENTS); uint(b['at'])
    if b['previous'] is not None: unb64(b['previous'],32)
    need(b['clock'] in ('trusted','held'))
    need(b['action'] in ('ARM','CHECKIN','DISARM','RELEASE'))
    if b['action']=='RELEASE':
        need(b['command'] is None); unb64(b['release_box'],112)
    else:
        need(b['release_box'] is None); command_shape(b['command'])

def scope(b,d):
    need(b['capsule_id']==d['body']['capsule_id'] and b['descriptor_hash']==digest(d['body'],'descriptor'),'SCOPE')

def trust(d,pins):
    need(type(pins) is dict and all(pins.get(k)==d['body'][k] for k in KEYS), 'UNTRUSTED_IDENTITY')
    if 'descriptor_hash' in pins:
        need(pins['descriptor_hash']==digest(d['body'],'descriptor'),'SCOPE')

def replay(d,events,anchors=None,complete=False):
    """Caller has validated shape/signatures/scope. Chain before lifecycle."""
    need(type(events) is list and len(events)<=MAXEVENTS,'LIMIT')
    head=None; previous_at=0
    for i,e in enumerate(events,1):
        b=e['body']
        if i==1 and b['seq']>1: raise Fault('INCOMPLETE_HISTORY')
        need(b['seq']==i and b['previous']==head,'HISTORY_ORDER')
        need(b['at']>=previous_at,'TIME')
        head=digest(e,'event'); previous_at=b['at']
    for seq,h in (anchors or {}).items():
        n=int(seq)
        need(n>=1,'SCHEMA'); unb64(h,32)
        if n>len(events): raise Fault('HISTORY_CONFLICT' if complete else 'INCOMPLETE_HISTORY')
        need(digest(events[n-1],'event')==h,'HISTORY_CONFLICT')
    head=None; deadline=None; last_at=0; terminal=None; ids=set()
    policy=d['body']
    for i,e in enumerate(events,1):
        b=e['body']; a=b['action']; at=b['at']; c=b['command']
        need(terminal is None,'LIFECYCLE')
        need(b['clock']=='trusted' or (a=='DISARM' and at==last_at),'TIME')
        if a!='RELEASE':
            cb=c['body']; need(cb['action']==a,'LIFECYCLE')
            need(cb['request_id'] not in ids,'HISTORY_ORDER'); ids.add(cb['request_id'])
        if i==1: need(a=='ARM','LIFECYCLE')
        else: need(a!='ARM','LIFECYCLE')
        if a=='CHECKIN':
            need(i<MAXEVENTS,'LIFECYCLE')
            need(c['body']['basis']==head,'HISTORY_ORDER')
            need(at<=deadline+policy['grace'],'TIME')
        if a in ('ARM','CHECKIN'):
            deadline=at+policy['interval']
            need(deadline+policy['grace']<=MAXINT,'RANGE')
        if a=='RELEASE':
            need(deadline is not None and at>deadline+policy['grace'],'TIME')
            terminal='COMMITTED'
        elif a=='DISARM': terminal='DISARMED'
        head=digest(e,'event'); last_at=at
    return dict(head=head,deadline=deadline,last_at=last_at,terminal=terminal)

def classify(d,state,at):
    if state['terminal']: return state['terminal']
    if state['head'] is None: return 'UNARMED'
    if at is None: return 'UNKNOWN'
    uint(at); need(at>=state['last_at'],'TIME')
    if at<=state['deadline']: return 'ARMED'
    if at<=state['deadline']+d['body']['grace']: return 'GRACE'
    return 'ELIGIBLE'

def validate_history(d,ct,events,pins,anchors=None,complete=False,snapshot=None):
    descriptor_shape(d)
    need(type(events) is list and len(events)<=MAXEVENTS,'LIMIT')
    for e in events: event_shape(e)
    trust(d,pins)
    verify_signature(d['body']['creator_key'],d)
    for e in events:
        verify_signature(d['body']['custodian_key'],e)
        if e['body']['command'] is not None:
            verify_signature(d['body']['creator_key'],e['body']['command'])
    if snapshot is not None: verify_signature(d['body']['custodian_key'],snapshot)
    need(len(ct)==d['body']['ciphertext_size'] and rawhash(ct)==d['body']['ciphertext_hash'],'CONTENT_COMMITMENT')
    for e in events:
        scope(e['body'],d)
        if e['body']['command'] is not None: scope(e['body']['command']['body'],d)
    if snapshot is not None:
        scope(snapshot['body'],d)
        need(snapshot['body']['events']==events,'HISTORY_CONFLICT')
    return replay(d,events,anchors,complete)

def archive(d,ct,events):
    return dict(header('archive'),descriptor=d,ciphertext=b64(ct),events=events)

def verify(raw,pins,*,anchors=None,recipient=None,at=None,snapshot=None,challenge=None,elapsed=None):
    result=dict(header('verification'),descriptor_hash=None,verdict='INVALID',state='UNKNOWN',head=None,
                authorization=None,content='NOT_ATTEMPTED',freshness='UNKNOWN',code='MALFORMED')
    try:
        obj=parse(raw); check_header(obj,'archive'); fields(obj,ARCHIVE)
        d=obj['descriptor']; ct=unb64(obj['ciphertext']); events=obj['events']
        # Header dispatch precedes schema and signatures, including nested objects.
        if type(d) is dict and type(d.get('body')) is dict: check_header(d['body'],'descriptor')
        if type(events) is list:
            need(len(events)<=MAXEVENTS,'LIMIT')
            for e in events:
                if type(e) is dict and type(e.get('body')) is dict:
                    check_header(e['body'],'event')
                    c=e['body'].get('command')
                    if type(c) is dict and type(c.get('body')) is dict: check_header(c['body'],'command')
        descriptor_shape(d)
        result['descriptor_hash']=digest(d['body'],'descriptor')
        for e in events: event_shape(e)
        snap=None
        if snapshot is not None:
            snap=parse(snapshot); envelope(snap); sb=snap['body']; check_header(sb,'snapshot'); fields(sb,SNAP)
            scope_shape(sb); unb64(sb['challenge'],32)
            if sb['head'] is not None: unb64(sb['head'],32)
            need(sb['clock'] in ('trusted','unavailable'))
            if sb['clock']=='trusted': uint(sb['sampled_at'])
            else: need(sb['sampled_at'] is None)
        state=validate_history(d,ct,events,pins,anchors,snapshot is not None,snap)
        result['descriptor_hash']=digest(d['body'],'descriptor')
        fresh='HISTORICAL'
        if snapshot is not None:
            need(sb['challenge']==challenge and type(elapsed) in (int,float) and 0<=elapsed<=10,'TIME')
            need(sb['head']==state['head'],'HISTORY_ORDER')
            at=sb['sampled_at']; fresh='SAMPLED'
        status=classify(d,state,at)
        authorization=(status=='COMMITTED') if status!='UNKNOWN' else None
        code={'COMMITTED':'OK_RELEASE','DISARMED':'OK_DISARM'}.get(status,'OK_SNAPSHOT' if snapshot is not None else 'OK_HISTORY')
        if status=='COMMITTED' and recipient is not None:
            try:
                value=open_box(recipient,events[-1]['body']['release_box'])
                need(len(value)==64 and value[:32]==unb64(result['descriptor_hash'],32),'CONTENT_AUTHENTICATION')
                decrypt_content(d['body'],ct,value[32:])
                result['content']='DECRYPTED'
            except Fault:
                result['content']='FAILED'
                raise Fault('CONTENT_AUTHENTICATION') from None
        result.update(verdict='VALID',state=status,head=state['head'],authorization=authorization,freshness=fresh,code=code)
    except Fault as e:
        result.update(code=e.code,verdict=('UNSUPPORTED' if e.code.startswith('UNSUPPORTED_') else
                                         'INCOMPLETE' if e.code=='INCOMPLETE_HISTORY' else 'INVALID'))
    except (KeyError,TypeError,ValueError,IndexError):
        result['code']='SCHEMA'
    return result
