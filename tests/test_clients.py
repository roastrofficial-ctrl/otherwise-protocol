"""Independent CLI lifecycle / disappearing-product and synthetic restore evidence."""
import ast
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from otherwise_solo.codec import canonical,parse,b64

ROOT=Path(__file__).resolve().parents[1]

class IndependentClient(unittest.TestCase):
    def run_cli(self,*args):
        p=subprocess.run([sys.executable,'-m','otherwise_solo.cli',*map(str,args)],capture_output=True,timeout=30)
        self.assertEqual(p.returncode,0,p.stdout.decode()+p.stderr.decode())
        return p.stdout
    def test_fixed_fixture_bytes_regenerate_deterministically(self):
        with tempfile.TemporaryDirectory() as directory:
            first=Path(directory)/'vectors.json'
            p=subprocess.run([sys.executable,str(ROOT/'conformance/generate.py'),'--out',str(first)],capture_output=True)
            self.assertEqual(p.returncode,0,p.stderr.decode())
            self.assertEqual(first.read_bytes(),(ROOT/'conformance/vectors.json').read_bytes())
    def test_installed_library_operates_without_checkout_on_python_path(self):
        with tempfile.TemporaryDirectory() as directory:
            code="import otherwise_solo; from otherwise_solo.codec import canonical; assert 'site-packages' in otherwise_solo.__file__; assert canonical({'x':1}).decode() == '{\"x\":1}'"
            p=subprocess.run([sys.executable,'-I','-c',code],cwd=directory,capture_output=True)
            self.assertEqual(p.returncode,0,p.stderr.decode())
    def test_no_research_saas_or_porternet_dependency(self):
        for name in ('Engine','Bounded','Available','Missing','LastWord','Consumer','Consumer05','vendor'):
            self.assertFalse((ROOT/name).exists(),name)
        for source in (ROOT/'reference/python/otherwise_solo').glob('*.py'):
            for node in ast.walk(ast.parse(source.read_text())):
                names=[node.module or ''] if isinstance(node,ast.ImportFrom) else [x.name for x in node.names] if isinstance(node,ast.Import) else []
                self.assertFalse(any(n.split('.')[0].lower() in ('laravel','porternet','engine','bounded','available','missing','lastword','consumer') for n in names),source.name)
    def test_cli_full_lifecycle_without_saas_with_independent_backups(self):
        with tempfile.TemporaryDirectory() as tmp:
            r=Path(tmp); db=r/'custody.sqlite'; cust=r/'custodian-public.json'; identities=r/'working-keys'
            cust.write_bytes(self.run_cli('init-custodian','--db',db))
            self.run_cli('init-identities','--directory',identities)
            backup=r/'independent-backup'; shutil.copytree(identities,backup)
            first=r/'cancel.json'; second=r/'release.json'
            for f in (first,second): self.run_cli('create','--identities',identities,'--custodian-public',cust,'--out',f)
            endpoint='file:'+str(db)
            def act(action,f,at,creator=None):
                args=['act',action,'--file',f,'--endpoint',endpoint,'--synthetic-now',at]
                if creator: args+=['--creator',creator]
                return json.loads(self.run_cli(*args))
            for f in (first,second): act('arm',f,1000,identities/'creator.json')
            # No application/database exists. Delete all working identity files and restore separately.
            shutil.rmtree(identities)
            restored=r/'restored-client'; shutil.copytree(backup,restored)
            acknowledged=act('checkin',first,1060,restored/'creator.json')
            self.assertEqual(acknowledged['verification']['verdict'],'VALID')
            status=act('status',first,1061)
            self.assertEqual(status['verification']['state'],'ARMED')
            result=act('disarm',first,1075,restored/'creator.json')
            self.assertEqual(result['verification']['state'],'DISARMED')
            result=act('release',second,1071)
            self.assertEqual(result['verification']['state'],'COMMITTED')
            committed=parse(second.read_bytes())
            archive=r/'archive.json'; archive.write_bytes(canonical(committed['archive']))
            pins=r/'pins.json'; pins.write_bytes(canonical(committed['pins']))
            result=json.loads(self.run_cli('verify','--file',archive,'--pins',pins,'--recipient',restored/'recipient.json'))
            self.assertEqual(result['content'],'DECRYPTED')
            # PHP verifies offline with only public pins/archive and its own recipient backup material.
            recipient=parse((restored/'recipient.json').read_bytes())['secret']
            req=json.dumps({'input':b64(archive.read_bytes()),'pins':committed['pins'],'options':{'recipient':recipient}}).encode()
            p=subprocess.run(['php','-d','ffi.enable=true',str(ROOT/'reference/php/verifier.php')],input=req,capture_output=True,timeout=30)
            self.assertEqual(p.returncode,0,p.stderr.decode()); self.assertEqual(json.loads(p.stdout)['content'],'DECRYPTED')
