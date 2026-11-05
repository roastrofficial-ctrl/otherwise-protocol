"""Offline release inventory: worktree plus every Git blob/commit/tag, including unreachable objects.
This is a scoped pattern/structure audit, not a universal secret-detection proof.
"""
import argparse,hashlib,json,re,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
PATTERNS={
 'private_key_pem':rb'-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----',
 'development_certificate':rb'-----BEGIN CERTIFICATE-----[\r\n]+[A-Za-z0-9+/=\r\n]{48,}-----END CERTIFICATE-----',
 'github_token':rb'(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{30,})',
 'aws_access_id':rb'AKIA[A-Z0-9]{16}',
 'slack_token':rb'xox[baprs]-[A-Za-z0-9-]{20,}',
 'private_home_path':rb'/(?:Users|home)/[A-Za-z0-9][^\s\"\'<>]*',
}
EMAIL=re.compile(rb'[A-Za-z0-9.!#$%&*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')
FORBIDDEN={'.pem','.key','.p12','.pfx','.sqlite','.sqlite3','.db','.ovault','.seed','.backup'}
PRIVATE_FIELDS={'secret','custodian_seed','custodian_box_secret','recipient'}
def git(*args): return subprocess.check_output(['git','-C',str(ROOT),*args])
def scan(data,label,findings,public_licence=False):
 for name,pattern in PATTERNS.items():
  if re.search(pattern,data): findings.append({'path':label,'kind':name})
 if not public_licence:
  emails=EMAIL.findall(data)
  if any(not e.endswith(b'@users.noreply.github.com') for e in emails): findings.append({'path':label,'kind':'contact_email_requires_review'})
def main():
 p=argparse.ArgumentParser();p.add_argument('--json');args=p.parse_args();findings=[];fixture_fields=0;licence_hashes=set()
 algorithm=git('rev-parse','--show-object-format').decode().strip()
 paths=sorted(set(git('ls-files','--cached','--others','--exclude-standard','-z').decode().split('\0'))-{''})
 for name in paths:
  path=ROOT/name
  if path.is_symlink() and not path.resolve().is_relative_to(ROOT): findings.append({'path':name,'kind':'escaping_symlink'});continue
  if not path.is_file(): continue
  if path.suffix.lower() in FORBIDDEN or (path.name.startswith('.env') and path.name!='.env.example'):
   findings.append({'path':name,'kind':'private_artifact_filename'})
  data=path.read_bytes();licence=name.startswith('third_party/') or name=='build/python-provenance.json'
  scan(data,name,findings,licence)
  if licence:licence_hashes.add(hashlib.new(algorithm,b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest())
  if path.suffix=='.json':
   try: value=json.loads(data)
   except (ValueError,UnicodeError): findings.append({'path':name,'kind':'invalid_json'});continue
   permitted=name in ('conformance/vectors.json','conformance/lifecycle.json') and value.get('fixture_only') is True
   def walk(x):
    nonlocal fixture_fields
    if isinstance(x,dict):
     for k,v in x.items():
      if k in PRIVATE_FIELDS and isinstance(v,str):
       if permitted: fixture_fields+=1
       else: findings.append({'path':name,'kind':'unexpected_private_key_field'})
      walk(v)
    elif isinstance(x,list):
     for v in x:walk(v)
   walk(value)
 objects=git('cat-file','--batch-all-objects','--batch-check=%(objectname) %(objecttype)').decode().splitlines()
 counts={'blob':0,'commit':0,'tag':0}
 # Blobs include copied third-party licence text. Its public author attribution is intentional;
 # worktree scanning above still reviews all first-party contact information separately.
 for item in objects:
  oid,typ=item.split()
  if typ not in counts:continue
  counts[typ]+=1;scan(git('cat-file',typ,oid),'git:'+oid,findings,oid in licence_hashes)
 report={'audit':'otherwise-alpha-offline-v1','worktree_files':len(paths),'git_objects':counts,
         'intentional_fixture_private_fields':fixture_fields,'findings':findings,
         'scope':'all included worktree files and all local Git objects; no external credential validation',
         'intentional_public_data':['Levi Godolphin copyright attribution','GitHub noreply commit identity','published third-party licence attribution','explicitly labelled deterministic fixture keys'],
         'limitations':'Pattern and structure review cannot prove absence of every possible secret; dependencies are separately inventoried.'}
 output=json.dumps(report,sort_keys=True,indent=2)+'\n'
 if args.json:Path(args.json).write_text(output)
 print(output,end='');return bool(findings)
if __name__=='__main__':raise SystemExit(main())
