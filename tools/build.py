"""Build once outside Iran; ship the same verified engines to every node."""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / '.build'
BIN = ROOT / 'bin'
CACHE.mkdir(exist_ok=True)
BIN.mkdir(exist_ok=True)
LICENSES = ROOT / 'licenses'
LICENSES.mkdir(exist_ok=True)


def fetch(url, name, digest):
    p = CACHE / name
    if not p.exists() or hashlib.sha256(p.read_bytes()).hexdigest() != digest:
        print('Downloading', name, flush=True)
        req = urllib.request.Request(url, headers={'User-Agent': 'naive-bridge-build/0.1'})
        with urllib.request.urlopen(req, timeout=180) as response, p.open('wb') as out:
            while chunk := response.read(1024 * 1024):
                out.write(chunk)
    if hashlib.sha256(p.read_bytes()).hexdigest() != digest:
        raise ValueError('SHA256 mismatch: ' + name)
    return p


def tar_member(archive, endswith, dest):
    with tarfile.open(archive) as tar:
        members = [m for m in tar.getmembers() if m.isfile() and (m.name == endswith or m.name.endswith('/' + endswith))]
        if len(members) != 1:
            raise ValueError('Unexpected archive layout')
        dest.write_bytes(tar.extractfile(members[0]).read())
        dest.chmod(0o755)


naive = fetch('https://github.com/klzgrad/naiveproxy/releases/download/v154.0.8037.49-4/naiveproxy-v154.0.8037.49-4-linux-x64.tar.xz', 'naive.tar.xz', '9d765620b90f7c60eb40c7c68b2f82537757cc52a8693dee7a00f8ba8b13dfd0')
tar_member(naive, 'naive', BIN / 'naive')
tar_member(naive, 'LICENSE', LICENSES / 'NaiveProxy-LICENSE')
xray = fetch('https://github.com/XTLS/Xray-core/releases/download/v26.9.30/Xray-linux-64.zip', 'xray.zip', 'f851110beaff16e78d643f0ccfd9524b4a44dfd59bae3e34bb52bba378f7690e')
with zipfile.ZipFile(xray) as z:
    (BIN / 'xray').write_bytes(z.read('xray'))
    (BIN / 'xray').chmod(0o755)
    (LICENSES / 'Xray-LICENSE').write_bytes(z.read('LICENSE'))
xcaddy = fetch('https://github.com/caddyserver/xcaddy/releases/download/v0.4.7/xcaddy_0.4.7_linux_amd64.tar.gz', 'xcaddy.tar.gz', 'e6d2882fb751b9697cdb73b0da8b8a7393f0d7f2cb47afa79a23982c4c61d2d4')
tar_member(xcaddy, 'xcaddy', CACHE / 'xcaddy')
releases = json.load(urllib.request.urlopen('https://go.dev/dl/?mode=json&include=all', timeout=30))
release = next(r for r in releases if r['version'] == 'go1.27.2')
go = next(f for f in release['files'] if f['os'] == 'linux' and f['arch'] == 'amd64' and f['kind'] == 'archive')
archive = fetch('https://go.dev/dl/' + go['filename'], go['filename'], go['sha256'])
# Extract only ordinary files/directories within the pinned Go archive.
with tarfile.open(archive) as tar:
    for member in tar.getmembers():
        target = (CACHE / member.name).resolve()
        if not target.is_relative_to(CACHE.resolve()) or member.issym() or member.islnk():
            raise ValueError('Unexpected Go archive member')
        if member.isdir():
            target.mkdir(parents=True, exist_ok=True)
        elif member.isfile():
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(tar.extractfile(member).read())
            target.chmod(member.mode & 0o777)
env = {**os.environ, 'PATH': str(CACHE / 'go/bin') + os.pathsep + os.environ['PATH'],
       'GOPATH': str(CACHE / 'gopath'), 'GOCACHE': str(CACHE / 'gocache')}
subprocess.run([str(CACHE / 'xcaddy'), 'build', 'v2.11.7', '--with',
                'github.com/caddyserver/forwardproxy=github.com/klzgrad/forwardproxy@c096d6a00cb28e019cc1995b04bdc6a9311d8024', '--output', str(BIN / 'caddy')], cwd=CACHE, env=env, check=True)
for name, url in [('Caddy-LICENSE', 'https://raw.githubusercontent.com/caddyserver/caddy/v2.11.7/LICENSE'),
                  ('ForwardProxy-LICENSE', 'https://raw.githubusercontent.com/klzgrad/forwardproxy/c096d6a00cb28e019cc1995b04bdc6a9311d8024/LICENSE')]:
    (LICENSES / name).write_bytes(urllib.request.urlopen(url, timeout=30).read())
(BIN / 'SHA256SUMS').write_text(''.join(hashlib.sha256((BIN / name).read_bytes()).hexdigest() + '  ' + name + '\n' for name in ('naive', 'xray', 'caddy')))
from package import build
build()
