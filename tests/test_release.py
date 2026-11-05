"""Release-engineering checks: compatibility bytes, schema aids and distribution identity."""
import hashlib,importlib.metadata,json,subprocess,sys,tempfile,unittest
from pathlib import Path
from jsonschema import Draft202012Validator
from otherwise_solo import __version__
from otherwise_solo.codec import unb64
ROOT=Path(__file__).resolve().parents[1]
class Release(unittest.TestCase):
 def test_approved_runtime_and_wire_artifacts_unchanged(self):
  baseline=json.loads((ROOT/'build/compatibility.json').read_bytes())['sha256']
  for name,expected in baseline.items():
   with self.subTest(path=name):self.assertEqual(hashlib.sha256((ROOT/name).read_bytes()).hexdigest(),expected)
 def test_public_schema_matches_valid_fixtures_and_verifier_results(self):
  schema=json.loads((ROOT/'schemas/solo-v1.schema.json').read_bytes());Draft202012Validator.check_schema(schema)
  validator=Draft202012Validator(schema);cases=json.loads((ROOT/'conformance/vectors.json').read_bytes())['cases']
  for case in cases:
   with self.subTest(case=case['name']):
    validator.validate(case['expected'])
    if case['expected']['verdict']=='VALID':
     validator.validate(json.loads(unb64(case['input'])))
     if 'snapshot' in case['options']:validator.validate(json.loads(unb64(case['options']['snapshot'])))
 def test_alpha_distribution_version_consistent(self):
  self.assertEqual(__version__,'0.1.0a1')
  self.assertEqual(importlib.metadata.version('otherwise-solo-reference'),__version__)
 def test_stateful_fixture_generator_reproduces_published_bytes(self):
  with tempfile.TemporaryDirectory() as directory:
   out=Path(directory)/'lifecycle.json'
   p=subprocess.run([sys.executable,str(ROOT/'conformance/generate_lifecycle.py'),'--out',str(out)],capture_output=True)
   self.assertEqual(p.returncode,0,p.stderr.decode());self.assertEqual(out.read_bytes(),(ROOT/'conformance/lifecycle.json').read_bytes())
