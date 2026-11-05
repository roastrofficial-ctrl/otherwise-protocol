"""Stateful portable fixtures usable by another custodian implementation."""
import json
from pathlib import Path
import tempfile
import unittest
from otherwise_solo.codec import canonical,parse,unb64,digest,Fault
from otherwise_solo.crypto import verify_signature
from otherwise_solo.protocol import verify
from otherwise_solo.store import initialize,Custodian,TestClock

class PortableLifecycle(unittest.TestCase):
    def test_portable_command_and_restart_scenarios(self):
        corpus=json.loads((Path(__file__).resolve().parents[1]/'conformance/lifecycle.json').read_bytes())
        setup=corpus['setup']; d=setup['descriptor']; ct=unb64(setup['ciphertext'])
        cid=d['body']['capsule_id']; hd=digest(d['body'],'descriptor')
        for scenario in corpus['scenarios']:
            with self.subTest(scenario=scenario['name']),tempfile.TemporaryDirectory() as directory:
                path=str(Path(directory)/'custody.sqlite')
                initialize(path,unb64(setup['custodian_seed']),unb64(setup['custodian_box_secret']))
                clock=TestClock(); store=Custodian(path,clock); retained={}
                for step in scenario['steps']:
                    clock.now=step['at']; clock.healthy=step['healthy']
                    if step['op']=='restart': store=Custodian(path,clock); continue
                    def perform():
                        if step['op']=='submit': return store.submit(canonical(d),ct,canonical(step['command']))
                        return getattr(store,step['op'])(cid,hd)
                    if step.get('error'):
                        with self.assertRaises(Fault) as err: perform()
                        self.assertEqual(err.exception.code,step['error']); continue
                    raw=perform()
                    if step.get('remember'): retained[step['remember']]=raw
                    if step.get('equals'): self.assertEqual(raw,retained[step['equals']])
                    if step['op']=='submit':
                        receipt=parse(raw); verify_signature(d['body']['custodian_key'],receipt)
                        self.assertEqual(receipt['body']['command'],step['command'])
                    else: self.assertEqual(verify(raw,setup['pins'])['verdict'],'VALID')
                    expected=step.get('expect') or {}
                    actual=parse(raw)['body'] if step['op']=='submit' else verify(raw,setup['pins'],recipient=unb64(setup['recipient_secret']))
                    for k,v in expected.items(): self.assertEqual(actual[k],v,(scenario['name'],step['op'],k))
