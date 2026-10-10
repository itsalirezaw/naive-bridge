"""Validate generated configs with the actual release engines on Linux; no live services changed."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from naivebridge import render
from test_core import NODE


def checked(args):
    result = subprocess.run([str(a) for a in args], capture_output=True, timeout=30)
    if result.returncode:
        raise RuntimeError(f'{Path(str(args[0])).name} validation failed: ' + result.stderr.decode(errors='replace')[-1000:])


with tempfile.TemporaryDirectory(prefix='naive-bridge-validate-') as directory:
    temp = Path(directory)
    cert, key = temp / 'cert.pem', temp / 'key.pem'
    checked(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
             '-subj', '/CN=node.example.com', '-addext', 'subjectAltName=DNS:node.example.com',
             '-keyout', key, '-out', cert])
    # A temporary self-signed certificate is used for parser validation only, not client connectivity.
    for name, config in [('iran', render.iran([{'node': NODE, 'slot': 0}, {'node': {**NODE, 'id': 'de1'}, 'slot': 1}])),
                         ('outside', render.outside(NODE, 20300))]:
        path = temp / (name + '.json')
        path.write_text(json.dumps(config))
        checked([ROOT / 'bin/xray', 'run', '-test', '-config', path])
    panel_config = {'outbounds': [{'tag': 'naive-bridge-auto', 'protocol': 'socks', 'settings': {
        'servers': [{'address': '127.0.0.1', 'port': 20080}]}}],
        'dns': {'tag': 'nb-dns', 'servers': ['1.1.1.1', '9.9.9.9']},
        'routing': {'rules': [{'type': 'field', 'inboundTag': ['test-in', 'nb-dns'], 'outboundTag': 'naive-bridge-auto'}]}}
    path = temp / 'panel.json'
    path.write_text(json.dumps(panel_config))
    checked([ROOT / 'bin/xray', 'run', '-test', '-config', path])
    for proxy in (False, True):
        path = temp / 'Caddyfile'
        path.write_text(render.caddy(NODE, 20300, str(cert), str(key), 24444, proxy))
        checked([ROOT / 'bin/caddy', 'validate', '--config', path, '--adapter', 'caddyfile'])
    checked([ROOT / 'bin/naive', '--version'])
print('Actual engines accepted Iran, outside, panel/DNS and both Caddy configurations.')
