"""Maintenance helper: turn a pip resolution report into PyPI wheel hash locks."""
import hashlib,json,urllib.request
from pathlib import Path
r=Path(__file__).resolve().parents[1]
report=json.loads((r/'.dependency-resolution.json').read_bytes())
items={x['metadata']['name'].lower().replace('_','-'):x['metadata']['version'] for x in report['install']}
runtime={'cryptography','pynacl','cffi','pycparser'}
build={'setuptools','wheel'}
manifest=[]; entries={}
for name,version in sorted(items.items()):
    with urllib.request.urlopen(f'https://pypi.org/pypi/{name}/{version}/json',timeout=30) as response: meta=json.load(response)
    wheels=[x for x in meta['urls'] if x['packagetype']=='bdist_wheel']
    if not wheels: raise RuntimeError('No wheel: '+name)
    hashes=sorted({x['digests']['sha256'] for x in wheels})
    entries[name]=name+'=='+version+' \\\n'+''.join('    --hash=sha256:'+h+(' \\\n' if i<len(hashes)-1 else '\n') for i,h in enumerate(hashes))
    info=meta['info']
    manifest.append({'name':name,'version':version,'pypi':f'https://pypi.org/project/{name}/{version}/',
                     'license_expression':info.get('license_expression'),'license':info.get('license'),
                     'license_classifiers':[c for c in info.get('classifiers',[]) if c.startswith('License ::')],
                     'project_urls':info.get('project_urls'),
                     'wheels':[{'filename':w['filename'],'url':w['url'],'sha256':w['digests']['sha256']} for w in sorted(wheels,key=lambda x:x['filename'])]})
for filename,names in [('requirements.lock',runtime),('requirements-build.lock',build),('requirements-test.lock',set(items)-runtime-build)]:
    (r/filename).write_text('# Locked public PyPI wheels. Regenerate only as a reviewed dependency update.\n'+''.join(entries[n] for n in sorted(names)))
(r/'build/python-provenance.json').write_text(json.dumps({'source':'PyPI version JSON API; public metadata','packages':manifest},sort_keys=True,indent=2)+'\n')
print('Pinned',len(items),'Python packages across runtime/build/test locks.')
