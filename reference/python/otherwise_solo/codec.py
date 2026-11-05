"""Printable-ASCII / unsigned-safe-integer subset of RFC 8785."""
import base64
import hashlib
import json
import re

PROFILE = 'otherwise.solo.v1'
SUITE = 'ed25519-sha256-aes256gcm-sodiumseal-v1'
MAXINT = 9007199254740991
MAXBYTES = 33554432
MAXEVENTS = 10000
H = {'profile', 'v', 'suite', 'kind'}

class Fault(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)

def need(condition, code='SCHEMA'):
    if not condition:
        raise Fault(code)

def header(kind):
    return dict(profile=PROFILE, v=1, suite=SUITE, kind=kind)

def canonical(obj):
    def walk(x, depth=1):
        need(depth <= 16, 'LIMIT')
        if x is None or type(x) is bool:
            return
        if type(x) is int:
            need(0 <= x <= MAXINT, 'RANGE')
        elif type(x) is str:
            need(all(32 <= ord(c) <= 126 for c in x), 'SCHEMA')
        elif type(x) is list:
            for v in x:
                walk(v, depth + 1)
        elif type(x) is dict:
            for k, v in x.items():
                need(type(k) is str)
                walk(k, depth + 1)
                walk(v, depth + 1)
        else:
            raise Fault('SCHEMA')
    walk(obj)
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')

def parse(raw, limit=MAXBYTES):
    need(isinstance(raw, bytes) and len(raw) <= limit, 'LIMIT')
    depth = 0
    quoted = escaped = False
    for c in raw:
        if quoted:
            if escaped: escaped = False
            elif c == 92: escaped = True
            elif c == 34: quoted = False
        elif c == 34: quoted = True
        elif c in (91, 123):
            depth += 1
            need(depth <= 16, 'LIMIT')
        elif c in (93, 125): depth -= 1
    def pairs(items):
        d = {}
        for k, v in items:
            need(k not in d, 'MALFORMED')
            d[k] = v
        return d
    def integer(s):
        need(bool(re.fullmatch(r'0|[1-9][0-9]*', s)), 'NONCANONICAL')
        need(len(s) <= 16 and int(s) <= MAXINT, 'RANGE')
        return int(s)
    def noninteger(s):
        raise Fault('NONCANONICAL')
    try:
        obj = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                         parse_int=integer, parse_float=noninteger, parse_constant=noninteger)
    except (ValueError, UnicodeError, RecursionError):
        raise Fault('MALFORMED') from None
    need(canonical(obj) == raw, 'NONCANONICAL')
    return obj

def b64(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip('=')

def unb64(s, length=None):
    need(type(s) is str and bool(re.fullmatch(r'[A-Za-z0-9_-]*', s)))
    try:
        out = base64.b64decode(s + '=' * (-len(s) % 4), altchars=b'-_', validate=True)
    except ValueError:
        raise Fault('SCHEMA') from None
    need(b64(out) == s and (length is None or len(out) == length))
    return out

def digest(obj, domain):
    return b64(hashlib.sha256(('otherwise/solo/1/' + domain + '\n').encode() + canonical(obj)).digest())

def rawhash(raw):
    return b64(hashlib.sha256(raw).digest())

def fields(obj, names):
    need(type(obj) is dict and set(obj) == set(names))

def uint(x, low=0, high=MAXINT):
    need(type(x) is int, 'SCHEMA')
    need(low <= x <= high, 'RANGE')

def check_header(obj, kind):
    need(type(obj) is dict and H <= obj.keys())
    need(obj['profile'] == PROFILE, 'UNSUPPORTED_PROFILE')
    need(type(obj['v']) is int and obj['v'] == 1, 'UNSUPPORTED_VERSION')
    need(obj['suite'] == SUITE, 'UNSUPPORTED_SUITE')
    need(obj['kind'] == kind)
