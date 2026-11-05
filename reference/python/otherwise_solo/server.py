"""Loopback-only synthetic HTTPS custodian. No production hosting configuration."""
from email.parser import BytesParser
from email.policy import default
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import ssl
from .codec import *

class Server(ThreadingHTTPServer):
    daemon_threads=True
    def __init__(self,address,service,cert,key):
        super().__init__(address,Handler); self.service=service
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.minimum_version=ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cert,key); self.socket=ctx.wrap_socket(self.socket,server_side=True)

class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def do_GET(self): self.handle_request('GET')
    def do_POST(self): self.handle_request('POST')
    def handle_request(self,method):
        try:
            self.connection.settimeout(10)
            length=self.headers.get('Content-Length','0'); need(length.isdecimal(),'MALFORMED')
            length=int(length); need(length<=33554432,'LIMIT')
            raw=self.rfile.read(length); need(len(raw)==length,'MALFORMED')
            path=self.path.split('/'); service=self.server.service
            need(path[:3]==['','solo','v1'],'MALFORMED')
            if path[3:]==['submit'] and method=='POST':
                typ=self.headers.get('Content-Type',''); need(typ.startswith('multipart/form-data;'),'MALFORMED')
                message=BytesParser(policy=default).parsebytes(('Content-Type: '+typ+'\r\nMIME-Version: 1.0\r\n\r\n').encode()+raw)
                need(message.is_multipart() and not message.defects,'MALFORMED'); parts={}
                for part in message.iter_parts():
                    name=part.get_param('name',header='content-disposition')
                    need(name in ('descriptor','ciphertext','command') and name not in parts and not part.is_multipart(),'MALFORMED')
                    parts[name]=part.get_payload(decode=True)
                need(set(parts)=={'descriptor','ciphertext','command'},'MALFORMED')
                out=service.submit(parts['descriptor'],parts['ciphertext'],parts['command'])
            elif path[3:]==['inspect'] and method=='POST': out=service.inspect(raw)
            elif len(path)==6 and ((path[3]=='evaluate' and method=='POST') or (path[3]=='export' and method=='GET')):
                need(raw==b'','MALFORMED'); unb64(path[4],16); unb64(path[5],32)
                out=getattr(service,path[3])(path[4],path[5])
            else: raise Fault('MALFORMED')
            self.send_response(200); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(out))); self.end_headers(); self.wfile.write(out)
        except Fault as e:
            status=413 if e.code=='LIMIT' else 503 if e.code in ('CLOCK_UNAVAILABLE','STORAGE_INTEGRITY','STORAGE_UNAVAILABLE') else 400 if e.code in ('MALFORMED','SCHEMA') or e.code.startswith('UNSUPPORTED_') else 409
            out=canonical({'code':e.code}); self.send_response(status); self.send_header('Content-Length',str(len(out))); self.end_headers(); self.wfile.write(out)
        except (BrokenPipeError,ConnectionResetError,TimeoutError): pass
