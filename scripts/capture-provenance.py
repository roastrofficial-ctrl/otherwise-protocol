"""Record installed public dependency identities and retain their supplied licence files."""
import hashlib,importlib.metadata,json,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
metadata=json.loads((ROOT/'build/python-provenance.json').read_bytes())
for p in metadata['packages']:
 dist=importlib.metadata.distribution(p['name']);assert dist.version==p['version']
 target=ROOT/'third_party/python'/p['name'];target.mkdir(parents=True,exist_ok=True)
 kept=[]
 for f in dist.files or []:
  if '.dist-info/' in str(f) and any(x in f.name.lower() for x in ('license','copying','notice')):
   data=dist.locate_file(f).read_bytes();name=f.name
   if (target/name).exists() and (target/name).read_bytes()!=data:name=hashlib.sha256(data).hexdigest()[:8]+'-'+name
   (target/name).write_bytes(data);kept.append({'path':str((target/name).relative_to(ROOT)),'sha256':hashlib.sha256(data).hexdigest()})
 p['installed_licence_files']=kept
 if not kept:raise RuntimeError('No supplied licence found: '+p['name'])
(ROOT/'build/python-provenance.json').write_text(json.dumps(metadata,sort_keys=True,indent=2)+'\n')
print('Retained supplied licence files for',len(metadata['packages']),'Python dependencies.')
