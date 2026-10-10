"""Strict, versioned node descriptors; no shell fragments or TLS bypass options."""
import base64
import ipaddress
import json
import re
import uuid


def node(value):
    if not isinstance(value, dict) or value.get('version') != 1:
        raise ValueError('Unsupported node descriptor')
    n = dict(value)
    for key in ('id', 'username', 'password'):
        if not isinstance(n.get(key), str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', n[key]):
            raise ValueError('Invalid ' + key)
    if not re.fullmatch(r'[a-z][a-z0-9]{0,15}', n['id']) or n['id'] in ('auto', 'api', 'blocked') or len(n['password']) < 24:
        raise ValueError('Node ID too long or password too short')
    ipaddress.ip_address(n['address'])
    domain = n.get('domain', '')
    if not isinstance(domain, str) or len(domain) > 253 or not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}', domain):
        raise ValueError('Invalid public DNS name')
    if type(n.get('port')) is not int or not 1 <= n['port'] <= 65535:
        raise ValueError('Invalid port')
    n['uuid'] = str(uuid.UUID(n['uuid']))
    for key in ('path', 'health_path'):
        if not isinstance(n.get(key), str) or not re.fullmatch(r'/[a-z0-9/_-]{16,128}', n[key]):
            raise ValueError('Invalid ' + key)
    if not re.fullmatch(r'[0-9a-f]{64}', n.get('health_sha256', '')):
        raise ValueError('Invalid health digest')
    allowed = ('version', 'id', 'address', 'domain', 'port', 'username', 'password', 'uuid', 'path', 'health_path', 'health_sha256')
    return {k: n[k] for k in allowed}


def encode(n):
    return 'NB1.' + base64.urlsafe_b64encode(json.dumps(node(n), separators=(',', ':')).encode()).decode()


def decode(text):
    text = text.strip()
    if len(text) > 8192 or not text.startswith(('NB1.', 'WB1.')):
        raise ValueError('Invalid pairing code')
    return node(json.loads(base64.b64decode(text[4:], altchars=b'-_', validate=True)))


def choose(nodes, healthy):
    """Ordered nodes; TCP prefers Naive, UDP never uses Naive; fail closed."""
    result = {}
    for n in nodes:
        ident = n['node']['id']
        for network in ('tcp', 'udp'):
            candidates = ['naive', 'xhttp'] if network == 'tcp' else ['udp']
            selected = next((ident + '-' + ('xhttp' if t == 'udp' else t)
                             for t in candidates if healthy.get(ident + '-' + t)), 'blocked')
            result[ident + '-' + network] = selected
    for network in ('tcp', 'udp'):
        result['auto-' + network] = next((result[n['node']['id'] + '-' + network] for n in nodes
                                         if result[n['node']['id'] + '-' + network] != 'blocked'), 'blocked')
    return result


class Health:
    def __init__(self):
        self.up = False
        self.good = self.bad = 0

    def record(self, ok):
        self.good, self.bad = (self.good + 1, 0) if ok else (0, self.bad + 1)
        if self.good >= 2:
            self.up = True
        if self.bad >= 2:
            self.up = False
        return self.up
