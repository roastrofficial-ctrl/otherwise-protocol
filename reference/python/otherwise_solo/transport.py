"""Two transport implementations, preserving signed object bytes."""
import json
import os
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from .codec import canonical,b64,unb64,Fault,need

class FileTransport:
    """File endpoint dispatches to a separate custodian process over stdin/stdout."""
    def __init__(self,database,now=1000): self.database,self.now=database,now
    def call(self,operation,**args):
        wire=canonical(dict(operation=operation,**{k:b64(v) if isinstance(v,bytes) else v for k,v in args.items()}))
        p=subprocess.run([sys.executable,'-m','otherwise_solo.dispatch','--db',self.database,'--synthetic-now',str(self.now)],
                         input=wire,capture_output=True,timeout=30)
        if p.returncode:
            try: raise Fault(json.loads(p.stdout)['code'])
            except (ValueError,KeyError): raise Fault('TRANSPORT') from None
        return p.stdout
    def submit(self,d,ct,c): return self.call('submit',descriptor=d,ciphertext=ct,command=c)
    def inspect(self,q): return self.call('inspect',query=q)
    def evaluate(self,cid,hd): return self.call('evaluate',capsule_id=cid,descriptor_hash=hd)
    def export(self,cid,hd): return self.call('export',capsule_id=cid,descriptor_hash=hd)

class HTTPSTransport:
    def __init__(self,base,ca):
        need(base.startswith('https://'),'TRANSPORT')
        self.base=base.rstrip('/'); self.context=ssl.create_default_context(cafile=ca)
    def request(self,path,data=None,content_type='application/json'):
        r=urllib.request.Request(self.base+'/solo/v1/'+path,data=data,headers={'Content-Type':content_type})
        # Disable redirects: a pinned endpoint cannot silently forward commands elsewhere.
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self,*args,**kwargs): return None
        opener=urllib.request.build_opener(NoRedirect,urllib.request.HTTPSHandler(context=self.context))
        try:
            with opener.open(r,timeout=10) as response:
                raw=response.read(33554433); need(len(raw)<=33554432,'LIMIT'); return raw
        except urllib.error.HTTPError as e:
            try: raise Fault(json.loads(e.read(8192))['code'])
            except (ValueError,KeyError): raise Fault('TRANSPORT') from None
    def submit(self,d,ct,c):
        boundary='otherwise-'+os.urandom(16).hex(); parts=[]
        for name,value,typ in [('descriptor',d,'application/json'),('ciphertext',ct,'application/octet-stream'),('command',c,'application/json')]:
            parts.append((f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\nContent-Type: {typ}\r\n\r\n').encode()+value+b'\r\n')
        raw=b''.join(parts)+f'--{boundary}--\r\n'.encode()
        return self.request('submit',raw,'multipart/form-data; boundary='+boundary)
    def inspect(self,q): return self.request('inspect',q)
    def evaluate(self,cid,hd): return self.request('evaluate/'+cid+'/'+hd,b'')
    def export(self,cid,hd): return self.request('export/'+cid+'/'+hd)
