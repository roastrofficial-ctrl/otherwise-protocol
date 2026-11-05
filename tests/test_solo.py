import copy
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from otherwise_solo.codec import *
from otherwise_solo.crypto import *
from otherwise_solo.protocol import *
from otherwise_solo.client import create,command,capacity,compatible,SYNTHETIC
from otherwise_solo.store import Custodian,TestClock,Clock,initialize,_state
from otherwise_solo.transport import FileTransport,HTTPSTransport
from otherwise_solo.backup import write,restore
from otherwise_solo.server import Server

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'conformance'))
import generate as fixtures
from capacity import prefix

def php(raw,pins,**options):
    request=json.dumps({'input':b64(raw),'pins':pins,'options':options}).encode()
    p=subprocess.run(['php','-d','ffi.enable=true','-d','memory_limit=512M',str(ROOT/'reference/php/verifier.php')],input=request,capture_output=True,timeout=120)
    if p.returncode: raise AssertionError(p.stderr.decode())
    return json.loads(p.stdout)

def crash_worker(path,point,op,args,torn=False):
    holder={}
    def hook(p):
        if p==point:
            if torn:
                db=holder['db']; db.execute('CREATE TABLE uncommitted_probe (x BLOB)')
                db.execute('INSERT INTO uncommitted_probe VALUES (zeroblob(131072))')
            os._exit(86)
    class CrashStore(Custodian):
        def connect(self):
            db=super().connect(); db.execute('PRAGMA cache_size=1'); return db
        def persist(self,db,s,release=None):
            holder['db']=db; super().persist(db,s,release)
    service=CrashStore(path,TestClock(1071),hook)
    getattr(service,op)(*args)

def race_worker(path,operation,d,ct,cmd,start,queue):
    service=Custodian(path,TestClock(1071)); start.wait()
    try:
        raw=service.evaluate(d['body']['capsule_id'],digest(d['body'],'descriptor')) if operation=='release' else service.submit(canonical(d),ct,canonical(cmd))
        queue.put(('ok',raw))
    except Fault as e: queue.put(('error',e.code))

def tls_files(directory):
    import datetime,ipaddress
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes,serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name=x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME,'localhost')])
    now=datetime.datetime.now(datetime.timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1)
          .not_valid_before(now-datetime.timedelta(days=1)).not_valid_after(now+datetime.timedelta(days=1))
          .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]),False)
          .add_extension(x509.BasicConstraints(ca=True,path_length=None),True).sign(key,hashes.SHA256()))
    cp=Path(directory)/'cert.pem'; kp=Path(directory)/'key.pem'
    cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM)); kp.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    return str(cp),str(kp)

class Solo(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.path=str(Path(self.tmp.name)/'custody.sqlite'); initialize(self.path)
        self.clock=TestClock(1000); self.service=Custodian(self.path,self.clock)
        self.owner=os.urandom(32); self.recipient=os.urandom(32)
        self.d,self.ct,self.dek=create(self.owner,**{'custodian':self.service.keys['custodian_key'],'custodian_box':self.service.keys['custodian_box_key'],'recipient':box_public(self.recipient)})
        self.pins={k:self.d['body'][k] for k in KEYS}; self.cid=self.d['body']['capsule_id']; self.hd=digest(self.d['body'],'descriptor')
        self.arm=command(self.owner,self.d,'ARM',dek=self.dek)
    def submit(self,c): return self.service.submit(canonical(self.d),self.ct,canonical(c))
    def activate(self): return parse(self.submit(self.arm))
    def release(self): self.clock.now=1071; return self.service.evaluate(self.cid,self.hd)
    def exported(self): return self.service.export(self.cid,self.hd)
    def assertCode(self,code,fn):
        with self.assertRaises(Fault) as e: fn()
        self.assertEqual(e.exception.code,code)
    def test_portable_corpus_matches_python_and_php(self):
        corpus=json.loads((ROOT/'conformance/vectors.json').read_bytes())
        for case in corpus['cases']:
            options=copy.deepcopy(case['options'])
            for k in ('recipient','snapshot'):
                if k in options: options[k]=unb64(options[k])
            with self.subTest(case=case['name']):
                self.assertEqual(verify(unb64(case['input']),case['pins'],**options),case['expected'])
        p=subprocess.run(['php','-d','ffi.enable=true',str(ROOT/'reference/php/verifier.php'),'--corpus',str(ROOT/'conformance/vectors.json')],capture_output=True)
        self.assertEqual(p.returncode,0,p.stdout.decode()+p.stderr.decode())
    def test_receipt_loss_duplicates_id_conflicts_and_stale_basis(self):
        e=self.activate(); c=command(self.owner,self.d,'CHECKIN',basis=digest(e,'event'))
        self.clock.now=1060; receipt=self.submit(c)  # Deliberately ignore the first response.
        self.clock.now=1070; self.assertEqual(self.submit(c),receipt)
        changed=sign(self.owner,dict(c['body'],basis=digest(parse(receipt),'event')))
        self.assertCode('REQUEST_ID_CONFLICT',lambda:self.submit(changed))
        stale=command(self.owner,self.d,'CHECKIN',basis=digest(e,'event'))
        self.assertCode('STALE_BASIS',lambda:self.submit(stale))
        self.assertEqual(len(parse(self.exported())['events']),2)
    def test_inclusive_grace_and_late_checkin(self):
        e=self.activate(); c=command(self.owner,self.d,'CHECKIN',basis=digest(e,'event'))
        self.clock.now=1070; self.submit(c); self.clock.now=1140
        self.assertCode('TOO_EARLY',lambda:self.service.evaluate(self.cid,self.hd))
        self.clock.now=1141
        self.assertCode('TOO_LATE',lambda:self.submit(command(self.owner,self.d,'CHECKIN',basis=digest(parse(self.exported())['events'][-1],'event'))))
        self.assertEqual(verify(self.service.evaluate(self.cid,self.hd),self.pins)['authorization'],True)
    def test_disarm_after_eligibility_and_after_commit(self):
        self.activate(); self.clock.now=1075
        self.submit(command(self.owner,self.d,'DISARM'))
        self.assertCode('TERMINAL',lambda:self.service.evaluate(self.cid,self.hd))
        self.assertEqual(verify(self.exported(),self.pins)['state'],'DISARMED')
    def test_release_terminal_and_exact_repeated_exports(self):
        self.activate(); raw=self.release()
        self.assertCode('TERMINAL',lambda:self.submit(command(self.owner,self.d,'DISARM')))
        restarted=Custodian(self.path,TestClock(2000,False))
        self.assertEqual(restarted.export(self.cid,self.hd),raw)
        self.assertEqual(restarted.evaluate(self.cid,self.hd),raw)
        self.assertEqual(php(raw,self.pins,recipient=b64(self.recipient)),verify(raw,self.pins,recipient=self.recipient))
        self.assertEqual(verify(raw,self.pins,recipient=self.recipient)['content'],'DECRYPTED')
        self.assertEqual(self.submit(self.arm),canonical(parse(raw)['events'][0]))
    def test_unhealthy_clock_allows_only_disarm_and_receipt_recovery(self):
        e=self.activate(); self.clock.healthy=False; self.clock.now=900
        self.assertEqual(self.submit(self.arm),canonical(e))
        self.assertCode('CLOCK_UNAVAILABLE',lambda:self.submit(command(self.owner,self.d,'CHECKIN',basis=digest(e,'event'))))
        self.assertCode('CLOCK_UNAVAILABLE',lambda:self.service.evaluate(self.cid,self.hd))
        receipt=parse(self.submit(command(self.owner,self.d,'DISARM')))
        self.assertEqual((receipt['body']['clock'],receipt['body']['at']),('held',1000))
        self.assertEqual(verify(self.exported(),self.pins)['state'],'DISARMED')
    def test_clock_forward_backward_and_restart_health(self):
        for values in [[(1000,0),(1010,1)],[(1000,0),(999,1)]]:
            iterator=iter(values); current=[None]
            def wall(): current[0]=next(iterator); return current[0][0]
            clock=Clock(True,wall,lambda:current[0][1]); self.assertTrue(clock.sample()[1]); self.assertFalse(clock.sample()[1])
        self.assertFalse(Clock().sample()[1])
    def test_stale_worker_snapshot_cannot_override_accepted_checkin(self):
        e=self.activate(); self.clock.now=1070
        self.submit(command(self.owner,self.d,'CHECKIN',basis=digest(e,'event')))
        self.clock.now=1071
        self.assertCode('TOO_EARLY',lambda:self.service.evaluate(self.cid,self.hd))
    def test_snapshot_challenge_anchors_and_clock_unavailability(self):
        e=self.activate(); query=dict(header('inspect'),capsule_id=self.cid,descriptor_hash=self.hd,challenge=b64(os.urandom(32)))
        self.clock.now=1061; snap=self.service.inspect(canonical(query)); raw=self.exported()
        opts=dict(snapshot=snap,challenge=query['challenge'],elapsed=1,anchors={'1':digest(e,'event')})
        self.assertEqual(verify(raw,self.pins,**opts)['state'],'GRACE')
        self.assertEqual(verify(raw,self.pins,**dict(opts,challenge=b64(os.urandom(32))))['code'],'TIME')
        self.assertEqual(php(raw,self.pins,**dict(opts,snapshot=b64(snap))),verify(raw,self.pins,**opts))
        self.clock.healthy=False; snap=self.service.inspect(canonical(query))
        self.assertEqual(verify(raw,self.pins,**dict(opts,snapshot=snap))['state'],'UNKNOWN')
    def test_before_and_after_commit_process_death(self):
        self.activate(); before=self.exported(); ctx=multiprocessing.get_context('spawn')
        for point in ('after_event_write','after_archive_write','before_commit','after_commit'):
            with self.subTest(point=point):
                p=ctx.Process(target=crash_worker,args=(self.path,point,'evaluate',(self.cid,self.hd))); p.start(); p.join(20)
                self.assertEqual(p.exitcode,86)
                raw=Custodian(self.path,TestClock(1071)).export(self.cid,self.hd)
                if point!='after_commit': self.assertEqual(raw,before)
                else:
                    self.assertEqual(verify(raw,self.pins,recipient=self.recipient)['content'],'DECRYPTED')
                    self.assertEqual(Custodian(self.path).export(self.cid,self.hd),raw)
    def test_lost_checkin_ack_after_process_commit_recovers_receipt(self):
        e=self.activate(); cmd=command(self.owner,self.d,'CHECKIN',basis=digest(e,'event'))
        ctx=multiprocessing.get_context('spawn')
        p=ctx.Process(target=checkin_crash,args=(self.path,self.d,self.ct,cmd)); p.start(); p.join(20); self.assertEqual(p.exitcode,86)
        received=self.submit(cmd); self.assertEqual(parse(received)['body']['at'],1070)
        self.assertEqual(len(parse(self.exported())['events']),2)
    def test_torn_uncommitted_wal_rolls_back_and_corrupt_commit_fails_closed(self):
        self.activate(); before=self.exported(); ctx=multiprocessing.get_context('spawn')
        p=ctx.Process(target=crash_worker,args=(self.path,'after_event_write','evaluate',(self.cid,self.hd),True)); p.start(); p.join(20); self.assertEqual(p.exitcode,86)
        wal=Path(self.path+'-wal'); self.assertTrue(wal.exists()); self.assertGreater(wal.stat().st_size,512)
        with wal.open('r+b') as f: f.truncate(wal.stat().st_size-512)
        self.assertEqual(Custodian(self.path).export(self.cid,self.hd),before)
        raw=self.release(); self.assertEqual(verify(raw,self.pins)['state'],'COMMITTED')
        db=sqlite3.connect(self.path); db.execute('UPDATE capsules SET release=?',(b'torn package',)); db.commit(); db.close()
        self.assertCode('STORAGE_INTEGRITY',lambda:Custodian(self.path).export(self.cid,self.hd))
        self.assertCode('STORAGE_INTEGRITY',lambda:self.submit(command(self.owner,self.d,'DISARM')))
    def test_competing_independent_release_workers(self):
        self.activate(); ctx=multiprocessing.get_context('spawn'); start=ctx.Event(); queue=ctx.Queue()
        ps=[ctx.Process(target=race_worker,args=(self.path,'release',self.d,self.ct,None,start,queue)) for _ in range(3)]
        for p in ps:p.start()
        start.set(); replies=[queue.get(timeout=30) for _ in ps]
        for p in ps:p.join(10); self.assertEqual(p.exitcode,0)
        self.assertTrue(all(r[0]=='ok' for r in replies)); self.assertEqual(len({r[1] for r in replies}),1)
        self.assertEqual(len(parse(replies[0][1])['events']),2)
    def test_competing_disarm_release_have_one_terminal_winner(self):
        self.activate(); ctx=multiprocessing.get_context('spawn'); start=ctx.Event(); queue=ctx.Queue(); cmd=command(self.owner,self.d,'DISARM')
        ps=[ctx.Process(target=race_worker,args=(self.path,op,self.d,self.ct,cmd,start,queue)) for op in ('release','disarm')]
        for p in ps:p.start()
        start.set(); replies=[queue.get(timeout=30) for _ in ps]
        for p in ps:p.join(10); self.assertEqual(p.exitcode,0)
        self.assertEqual(sum(r[0]=='ok' for r in replies),1); self.assertIn(('error','TERMINAL'),replies)
        self.assertIn(verify(self.exported(),self.pins)['state'],('COMMITTED','DISARMED'))
    def test_synthetic_backups_restore_original_creator_and_recipient(self):
        self.activate(); directory=Path(self.tmp.name); ck=directory/'creator.backup'; rk=directory/'recipient.backup'
        write(ck,'creator',self.owner); write(rk,'recipient',self.recipient)
        self.assertEqual(ck.stat().st_mode & 0o777,0o600)
        self.owner=None; self.recipient=None
        owner=restore(ck,'creator',self.pins['creator_key']); recipient=restore(rk,'recipient',self.pins['recipient_key'])
        e=parse(self.exported())['events'][-1]; self.clock.now=1060
        self.submit(command(owner,self.d,'CHECKIN',basis=digest(e,'event')))
        self.clock.now=1131; raw=self.service.evaluate(self.cid,self.hd)
        self.assertEqual(verify(raw,self.pins,recipient=recipient)['content'],'DECRYPTED')
        self.assertEqual(php(raw,self.pins,recipient=b64(recipient))['content'],'DECRYPTED')
        self.assertCode('UNTRUSTED_IDENTITY',lambda:restore(ck,'creator',public(os.urandom(32))))
        ck.unlink()
        with self.assertRaises(FileNotFoundError): restore(ck,'creator',self.pins['creator_key'])
    def test_wrong_creator_cannot_reset_and_stolen_key_retains_authority(self):
        e=self.activate(); wrong=command(os.urandom(32),self.d,'DISARM')
        self.assertCode('BAD_SIGNATURE',lambda:self.submit(wrong))
        # A copied legitimate seed is sufficient: no account-reset or clone revocation fiction.
        self.submit(command(bytes(self.owner),self.d,'DISARM'))
        self.assertEqual(verify(self.exported(),self.pins)['state'],'DISARMED')
    def test_strict_point_validation_rejects_mixed_subgroups_in_both_backends(self):
        good=unb64(public(self.owner)); mixed=sodium.crypto_core_ed25519_add(good,b'\0'*32)
        points=[good,IDENTITY,b'\0'*32,b'\xff'*32,mixed]
        self.assertEqual([point_valid(p) for p in points],[True,False,False,False,False])
        code='require $argv[1]; $p=json_decode(stream_get_contents(STDIN)); echo json_encode(array_map(fn($s)=>pointValid(ub($s,32)),$p));'
        p=subprocess.run(['php','-d','ffi.enable=true','-r',code,str(ROOT/'reference/php/verifier.php')],input=json.dumps([b64(x) for x in points]).encode(),capture_output=True)
        self.assertEqual(p.returncode,0,p.stderr.decode()); self.assertEqual(json.loads(p.stdout),[True,False,False,False,False])
    def test_missing_authority_is_not_implicitly_reinitialized(self):
        self.activate(); historical=self.exported(); os.unlink(self.path)
        self.assertCode('STORAGE_UNAVAILABLE',lambda:Custodian(self.path))
        self.assertFalse(Path(self.path).exists())
        self.assertEqual(verify(historical,self.pins)['verdict'],'VALID')
    def test_authenticated_forks_are_detectable_only_with_retained_anchors(self):
        release=canonical(fixtures.arch([fixtures.E1,fixtures.ER])); disarm=canonical(fixtures.arch([fixtures.E1,fixtures.ED]))
        self.assertEqual(verify(release,fixtures.PINS)['state'],'COMMITTED')
        self.assertEqual(verify(disarm,fixtures.PINS)['state'],'DISARMED')
        self.assertEqual(verify(release,fixtures.PINS,anchors={'2':digest(fixtures.ED,'event')})['code'],'HISTORY_CONFLICT')
    def test_capsule_policy_cannot_be_amended_at_existing_id(self):
        self.activate()
        def rng(n): return unb64(self.cid) if n==16 else os.urandom(n)
        d,ct,dek=create(self.owner,self.pins['custodian_key'],self.pins['custodian_box_key'],self.pins['recipient_key'],interval=120,random=rng)
        c=command(self.owner,d,'ARM',dek=dek)
        self.assertCode('SCOPE',lambda:self.service.submit(canonical(d),ct,canonical(c)))
        self.assertEqual(parse(self.exported())['descriptor'],self.d)
    def test_https_untrusted_certificate_cannot_supply_a_receipt(self):
        import urllib.error
        cert,key=tls_files(self.tmp.name); server=Server(('127.0.0.1',0),self.service,cert,key)
        threading.Thread(target=server.serve_forever,daemon=True).start(); self.addCleanup(server.server_close); self.addCleanup(server.shutdown)
        transport=HTTPSTransport('https://localhost:'+str(server.server_port),None)
        with self.assertRaises(urllib.error.URLError): transport.submit(canonical(self.d),self.ct,canonical(self.arm))
    def test_cli_rejects_valid_receipt_for_another_request(self):
        e=self.activate(); cp=Path(self.tmp.name)/'client.json'; backup=Path(self.tmp.name)/'creator.backup'
        write(backup,'creator',self.owner); cp.write_bytes(canonical({'synthetic_only':True,'archive':archive(self.d,self.ct,[e]),'arm':self.arm,'pins':self.pins}))
        class Replay:
            def inspect(inner,q): return self.service.inspect(q)
            def submit(inner,*args): return canonical(e)
        cert,key=tls_files(self.tmp.name); server=Server(('127.0.0.1',0),Replay(),cert,key)
        threading.Thread(target=server.serve_forever,daemon=True).start(); self.addCleanup(server.server_close); self.addCleanup(server.shutdown)
        p=subprocess.run([sys.executable,'-m','otherwise_solo.cli','act','checkin','--file',str(cp),'--creator',str(backup),'--endpoint','https://localhost:'+str(server.server_port),'--ca',cert],capture_output=True)
        self.assertEqual(p.returncode,1); self.assertEqual(json.loads(p.stdout)['code'],'SCOPE')
        self.assertEqual(len(parse(self.exported())['events']),1)
    def test_cli_lost_acceptance_response_retries_exact_pending_command(self):
        e=self.activate(); cp=Path(self.tmp.name)/'client.json'; backup=Path(self.tmp.name)/'creator.backup'
        write(backup,'creator',self.owner); cp.write_bytes(canonical({'synthetic_only':True,'archive':archive(self.d,self.ct,[e]),'arm':self.arm,'pins':self.pins}))
        changed=[False]; dropped=[False]
        def lose(point):
            if point=='after_event_write': changed[0]=True
            if point=='after_commit' and changed[0] and not dropped[0]: dropped[0]=True; raise ConnectionResetError()
        self.service.hook=lose; cert,key=tls_files(self.tmp.name); server=Server(('127.0.0.1',0),self.service,cert,key)
        threading.Thread(target=server.serve_forever,daemon=True).start(); self.addCleanup(server.server_close); self.addCleanup(server.shutdown)
        args=[sys.executable,'-m','otherwise_solo.cli','act','checkin','--file',str(cp),'--creator',str(backup),'--endpoint','https://localhost:'+str(server.server_port),'--ca',cert]
        first=subprocess.run(args,capture_output=True); self.assertEqual(first.returncode,1)
        pending=parse(cp.read_bytes())['pending']; self.assertEqual(len(parse(self.exported())['events']),2)
        second=subprocess.run(args,capture_output=True); self.assertEqual(second.returncode,0,second.stdout.decode()+second.stderr.decode())
        retained=parse(cp.read_bytes()); self.assertNotIn('pending',retained)
        self.assertEqual(retained['archive']['events'][-1]['body']['command'],pending)
        self.assertEqual(len(retained['archive']['events']),2)
    def test_operator_early_decryption_remains_successful(self):
        self.activate(); db=self.service.connect(); s,_=self.service.load(db,self.cid); db.close()
        self.assertEqual(decrypt_content(self.d['body'],self.ct,unb64(s['dek'])),SYNTHETIC)
        self.assertNotEqual(verify(self.exported(),self.pins)['authorization'],True)
    def test_provider_does_not_silently_claim_stronger_custody(self):
        self.assertFalse(compatible({'recoverable_release':True})['cryptographic_policy_enforcement'])
        self.assertCode('UNSUPPORTED_PROFILE',lambda:compatible({'cryptographic_policy_enforcement':True}))
    def test_https_and_file_transport_same_receipts_and_decision(self):
        cert,key=tls_files(self.tmp.name); server=Server(('127.0.0.1',0),self.service,cert,key)
        thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
        self.addCleanup(server.server_close); self.addCleanup(server.shutdown)
        https=HTTPSTransport('https://localhost:'+str(server.server_port),cert); file=FileTransport(self.path,1000)
        a=https.submit(canonical(self.d),self.ct,canonical(self.arm)); self.assertEqual(file.submit(canonical(self.d),self.ct,canonical(self.arm)),a)
        cmd=command(self.owner,self.d,'CHECKIN',basis=digest(parse(a),'event')); self.clock.now=1060; file.now=1060
        b=file.submit(canonical(self.d),self.ct,canonical(cmd)); self.assertEqual(https.submit(canonical(self.d),self.ct,canonical(cmd)),b)
        self.clock.now=1131; file.now=1131
        raw=https.evaluate(self.cid,self.hd); self.assertEqual(file.evaluate(self.cid,self.hd),raw); self.assertEqual(https.export(self.cid,self.hd),raw)
        self.assertEqual(verify(raw,self.pins,recipient=self.recipient),php(raw,self.pins,recipient=b64(self.recipient)))
    def test_lost_https_export_response_and_repeated_export(self):
        self.activate(); raw=self.release(); count=[0]
        def lose(point):
            if point=='before_export_response' and count[0]==0: count[0]+=1; raise ConnectionResetError()
        self.service.hook=lose; cert,key=tls_files(self.tmp.name); server=Server(('127.0.0.1',0),self.service,cert,key)
        threading.Thread(target=server.serve_forever,daemon=True).start(); self.addCleanup(server.server_close); self.addCleanup(server.shutdown)
        transport=HTTPSTransport('https://localhost:'+str(server.server_port),cert)
        with self.assertRaises(Exception): transport.export(self.cid,self.hd)
        for _ in range(3): self.assertEqual(transport.export(self.cid,self.hd),raw)
        self.assertEqual(Custodian(self.path).export(self.cid,self.hd),raw)

def checkin_crash(path,d,ct,cmd):
    def hook(point):
        if point=='after_commit': os._exit(86)
    Custodian(path,TestClock(1070),hook).submit(canonical(d),ct,canonical(cmd))

class Capacity(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.events=prefix(9998)
    def test_actual_limit_warning_rejection_last_terminal_slot(self):
        with tempfile.TemporaryDirectory() as directory:
            path=str(Path(directory)/'custody.sqlite'); initialize(path,fixtures.CUST,fixtures.BOX)
            clock=TestClock(1000); store=Custodian(path,clock)
            state=_state(fixtures.D,fixtures.CT,fixtures.DEK,copy.deepcopy(self.events))
            store.transaction(lambda db:store.persist(db,state))
            self.assertFalse(capacity(self.events[:9898])['warning'])
            self.assertTrue(capacity(self.events[:9899])['warning'])
            head=digest(self.events[-1],'event')
            c=command(fixtures.OWNER,fixtures.D,'CHECKIN',basis=head)
            receipt=store.submit(canonical(fixtures.D),fixtures.CT,canonical(c)); e=parse(receipt)
            self.assertEqual(e['body']['seq'],9999)
            cid=fixtures.D['body']['capsule_id']; hd=fixtures.HD
            full=store.export(cid,hd); count=len(parse(full)['events'])
            self.assertTrue(capacity(parse(full)['events'])['exhausted'])
            rejected=command(fixtures.OWNER,fixtures.D,'CHECKIN',basis=digest(e,'event'))
            for _ in range(2):
                with self.assertRaises(Fault) as err: store.submit(canonical(fixtures.D),fixtures.CT,canonical(rejected))
                self.assertEqual(err.exception.code,'CAPACITY')
            self.assertEqual(store.export(cid,hd),full); self.assertEqual(store.submit(canonical(fixtures.D),fixtures.CT,canonical(c)),receipt)
            clock.now=1070
            with self.assertRaises(Fault) as err: store.evaluate(cid,hd)
            self.assertEqual(err.exception.code,'TOO_EARLY')
            # Separate copies prove both terminal choices at the real limit, no reduced test setting.
            other=str(Path(directory)/'release.sqlite'); connection=store.connect(); target=sqlite3.connect(other); connection.backup(target); target.close(); connection.close()
            clock.healthy=False
            dis=command(fixtures.OWNER,fixtures.D,'DISARM'); out=store.submit(canonical(fixtures.D),fixtures.CT,canonical(dis)); self.assertEqual(parse(out)['body']['seq'],10000)
            terminal=store.export(cid,hd); self.assertEqual(verify(terminal,fixtures.PINS)['state'],'DISARMED')
            releasing=Custodian(other,TestClock(1071)); raw=releasing.evaluate(cid,hd)
            py=verify(raw,fixtures.PINS,recipient=fixtures.RECIP); self.assertEqual(py['state'],'COMMITTED'); self.assertEqual(len(parse(raw)['events']),10000)
            self.assertEqual(php(raw,fixtures.PINS,recipient=b64(fixtures.RECIP)),py)
            with self.assertRaises(Fault) as err: releasing.submit(canonical(fixtures.D),fixtures.CT,canonical(dis))
            self.assertEqual(err.exception.code,'TERMINAL')

if __name__=='__main__': unittest.main()
