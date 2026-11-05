"""Synthetic SQLite custodian: FULL-synchronous WAL, one atomic terminal archive."""
import os
import sqlite3
import time
from pathlib import Path
from .codec import *
from .crypto import *
from .protocol import *
from .client import SYNTHETIC

class TestClock:
    __test__=False
    def __init__(self,now=1000,healthy=True): self.now,self.healthy=now,healthy
    def sample(self): return self.now,self.healthy

class Clock:
    """Qualification is an operator assumption, not an authenticated UTC proof."""
    def __init__(self,qualified=False,wall=time.time,mono=time.monotonic):
        self.healthy=qualified; self.wall=wall; self.mono=mono; self.last=None
    def sample(self):
        w,m=self.wall(),self.mono()
        if self.last and (w<self.last[0] or m<self.last[1] or abs((w-self.last[0])-(m-self.last[1]))>5):
            self.healthy=False
        self.last=(w,m)
        return int(w),self.healthy

def initialize(path,signing=None,boxing=None):
    """Explicit laboratory bootstrap, never implicitly recreate missing authority."""
    need(not Path(path).exists(),'STORAGE_EXISTS')
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600); os.close(fd)
    db=sqlite3.connect(path)
    db.execute('PRAGMA journal_mode=WAL'); db.execute('PRAGMA synchronous=FULL')
    db.execute('CREATE TABLE identity (seed BLOB NOT NULL, box BLOB NOT NULL, synthetic INTEGER NOT NULL)')
    db.execute('INSERT INTO identity VALUES (?,?,1)',(signing or os.urandom(32),boxing or os.urandom(32)))
    db.execute('CREATE TABLE capsules (id TEXT PRIMARY KEY, state BLOB NOT NULL, checksum TEXT NOT NULL, release BLOB, release_hash TEXT)')
    db.commit(); db.close()
    # Protect WAL/SHM as well as the main file through the calling process umask.

def _state(d,ct,dek,events):
    return dict(descriptor=d,ciphertext=b64(ct),dek=b64(dek),events=events)

class Custodian:
    def __init__(self,path,clock=None,hook=None):
        need(Path(path).is_file(),'STORAGE_UNAVAILABLE')
        self.path=str(path); self.clock=clock or Clock(); self.hook=hook or (lambda point:None)
        try:
            db=self.connect(); row=db.execute('SELECT seed,box,synthetic FROM identity').fetchone(); db.close()
            need(row is not None and row[2]==1 and len(row[0])==len(row[1])==32,'STORAGE_INTEGRITY')
            self.seed,self.box=row[:2]
        except sqlite3.DatabaseError: raise Fault('STORAGE_INTEGRITY') from None
    def connect(self):
        db=sqlite3.connect(self.path,timeout=30,isolation_level=None)
        db.execute('PRAGMA journal_mode=WAL'); db.execute('PRAGMA synchronous=FULL')
        return db
    @property
    def keys(self): return dict(custodian_key=public(self.seed),custodian_box_key=box_public(self.box))
    def load(self,db,cid):
        row=db.execute('SELECT state,checksum,release,release_hash FROM capsules WHERE id=?',(cid,)).fetchone()
        if row is None: return None,None
        need(rawhash(row[0])==row[1],'STORAGE_INTEGRITY')
        try: s=parse(row[0])
        except Fault: raise Fault('STORAGE_INTEGRITY') from None
        need(all(s['descriptor']['body'][k]==v for k,v in self.keys.items()),'STORAGE_INTEGRITY')
        terminal=s['events'][-1]['body']['action']=='RELEASE'
        need(terminal==(row[2] is not None),'STORAGE_INTEGRITY')
        if terminal:
            need(rawhash(row[2])==row[3] and row[2]==canonical(archive(s['descriptor'],unb64(s['ciphertext']),s['events'])),'STORAGE_INTEGRITY')
        return s,row[2]
    def transaction(self,operation):
        db=self.connect()
        try:
            db.execute('BEGIN IMMEDIATE')
            value=operation(db)
            self.hook('before_commit'); db.execute('COMMIT'); self.hook('after_commit')
            return value
        except sqlite3.DatabaseError:
            raise Fault('STORAGE_INTEGRITY') from None
        finally:
            db.close()
    def persist(self,db,s,release=None):
        raw=canonical(s)
        db.execute('INSERT INTO capsules(id,state,checksum,release,release_hash) VALUES (?,?,?,NULL,NULL) '
                   'ON CONFLICT(id) DO UPDATE SET state=excluded.state,checksum=excluded.checksum',
                   (s['descriptor']['body']['capsule_id'],raw,rawhash(raw)))
        self.hook('after_event_write')
        if release is not None:
            db.execute('UPDATE capsules SET release=?,release_hash=? WHERE id=?',
                       (release,rawhash(release),s['descriptor']['body']['capsule_id']))
            self.hook('after_archive_write')
    def timed(self,events,allow_held=False):
        now,healthy=self.clock.sample(); uint(now)
        last=events[-1]['body']['at'] if events else 0
        if not healthy or now<last:
            need(allow_held and bool(events),'CLOCK_UNAVAILABLE')
            return last,'held'
        return now,'trusted'
    def submit(self,descriptor_bytes,ciphertext,command_bytes):
        d=parse(descriptor_bytes,8192); c=parse(command_bytes,8192)
        descriptor_shape(d); command_shape(c)
        need(all(d['body'][k]==v for k,v in self.keys.items()),'UNTRUSTED_IDENTITY')
        verify_signature(d['body']['creator_key'],d); verify_signature(d['body']['creator_key'],c)
        scope(c['body'],d)
        need(len(ciphertext)==d['body']['ciphertext_size'] and rawhash(ciphertext)==d['body']['ciphertext_hash'],'CONTENT_COMMITMENT')
        def operation(db):
            s,_=self.load(db,d['body']['capsule_id']); cb=c['body']; action=cb['action']
            if s:
                need(s['descriptor']==d and s['ciphertext']==b64(ciphertext),'SCOPE')
                for e in s['events']:
                    old=e['body']['command']
                    if old and old['body']['request_id']==cb['request_id']:
                        need(old==c,'REQUEST_ID_CONFLICT'); return canonical(e)
                need(s['events'][-1]['body']['action'] not in ('RELEASE','DISARM'),'TERMINAL')
                need(action!='ARM','INVALID_COMMAND')
            else:
                need(action=='ARM','INVALID_COMMAND')
                value=open_box(self.box,cb['enrollment_box'])
                need(len(value)==64 and value[:32]==unb64(cb['descriptor_hash']),'SCOPE')
                need(decrypt_content(d['body'],ciphertext,value[32:])==SYNTHETIC,'SYNTHETIC_ONLY')
                # Validate recipient box usability without releasing the content key.
                seal(d['body']['recipient_key'],b'\0'*64)
                s=_state(d,ciphertext,value[32:],[])
            events=s['events']; seq=len(events)+1
            if action=='CHECKIN': need(seq<MAXEVENTS,'CAPACITY')
            at,clock=self.timed(events,action=='DISARM')
            head=digest(events[-1],'event') if events else None
            if action=='CHECKIN':
                need(cb['basis']==head,'STALE_BASIS')
                deadline=events[-1]['body']['at']+d['body']['interval']+d['body']['grace']
                need(at<=deadline,'TOO_LATE')
            if action in ('ARM','CHECKIN'): uint(at+d['body']['interval']+d['body']['grace'])
            event=sign(self.seed,dict(header('event'),capsule_id=cb['capsule_id'],descriptor_hash=cb['descriptor_hash'],
                         seq=seq,previous=head,at=at,clock=clock,action=action,command=c,release_box=None))
            events.append(event); self.persist(db,s)
            return canonical(event)
        return self.transaction(operation)
    def export(self,cid,hd):
        def operation(db):
            s,release=self.load(db,cid); need(s is not None,'NOT_FOUND')
            need(digest(s['descriptor']['body'],'descriptor')==hd,'SCOPE')
            raw=release if release is not None else canonical(archive(s['descriptor'],unb64(s['ciphertext']),s['events']))
            self.hook('before_export_response')
            return raw
        return self.transaction(operation)
    def evaluate(self,cid,hd):
        def operation(db):
            s,release=self.load(db,cid); need(s is not None,'NOT_FOUND')
            d=s['descriptor']; events=s['events']; need(digest(d['body'],'descriptor')==hd,'SCOPE')
            if release is not None: return release
            need(events[-1]['body']['action']!='DISARM','TERMINAL')
            at,clock=self.timed(events)
            need(at>events[-1]['body']['at']+d['body']['interval']+d['body']['grace'],'TOO_EARLY')
            event=sign(self.seed,dict(header('event'),capsule_id=cid,descriptor_hash=hd,seq=len(events)+1,
                       previous=digest(events[-1],'event'),at=at,clock=clock,action='RELEASE',command=None,
                       release_box=seal(d['body']['recipient_key'],unb64(hd)+unb64(s['dek'],32))))
            need(len(events)<MAXEVENTS,'CAPACITY'); events.append(event)
            raw=canonical(archive(d,unb64(s['ciphertext']),events))
            self.persist(db,s,raw)
            return raw
        return self.transaction(operation)
    def inspect(self,query_bytes):
        q=parse(query_bytes,8192); check_header(q,'inspect'); fields(q,H|{'capsule_id','descriptor_hash','challenge'})
        scope_shape(q); unb64(q['challenge'],32)
        def operation(db):
            s,_=self.load(db,q['capsule_id']); events=s['events'] if s else []
            if s: scope(q,s['descriptor'])
            now,healthy=self.clock.sample()
            if events and now<events[-1]['body']['at']: healthy=False
            b=dict(header('snapshot'),capsule_id=q['capsule_id'],descriptor_hash=q['descriptor_hash'],
                   challenge=q['challenge'],head=digest(events[-1],'event') if events else None,
                   sampled_at=now if healthy else None,clock='trusted' if healthy else 'unavailable',events=events)
            return canonical(sign(self.seed,b))
        return self.transaction(operation)
