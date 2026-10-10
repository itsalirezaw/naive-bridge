"""Build a release from an explicit allowlist; never include server state or evidence."""
import argparse
import hashlib
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parents[1]
FILES = ('README.md', 'README.fa.md', 'LICENSE', 'THIRD-PARTY.md', 'VERSION',
         'CHANGELOG.md', 'install.sh', 'install-local.sh', 'build-bundle.sh')
DIRS = {'naivebridge': '*.py', 'tools': '*.py', 'tests': '*.py', 'docs': '*.md', 'licenses': '*LICENSE'}


def sources(root):
    result = [root / name for name in FILES]
    for directory, pattern in DIRS.items():
        result += sorted((root / directory).glob(pattern))
    result += [root / 'bin' / name for name in ('naive', 'xray', 'caddy', 'SHA256SUMS')]
    for path in result:
        if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
            raise ValueError('Invalid release input: ' + str(path.relative_to(root)))
    return result


def build(root=ROOT):
    files = sources(root)
    lines = (root / 'bin/SHA256SUMS').read_text().splitlines()
    checksums = dict(line.split('  ', 1)[::-1] for line in lines)
    if set(checksums) != {'naive', 'xray', 'caddy'}:
        raise ValueError('Unexpected engine manifest')
    for name, digest in checksums.items():
        if hashlib.sha256((root / 'bin' / name).read_bytes()).hexdigest() != digest:
            raise ValueError('Engine checksum mismatch: ' + name)
    dest = root / 'dist'
    dest.mkdir(exist_ok=True)
    archive = dest / 'naive-bridge-linux-amd64.tar.gz'
    with tarfile.open(archive, 'w:gz') as tar:
        for path in files:
            rel = path.relative_to(root)
            info = tar.gettarinfo(str(path), arcname='naive-bridge/' + rel.as_posix())
            info.uid = info.gid = 0
            info.uname = info.gname = 'root'
            info.mode = 0o755 if path.suffix == '.sh' or (rel.parts[0] == 'bin' and path.name != 'SHA256SUMS') else 0o644
            with path.open('rb') as stream:
                tar.addfile(info, stream)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (dest / 'SHA256SUMS').write_text(digest + '  ' + archive.name + '\n', encoding='ascii', newline='\n')
    print(archive.name + ': ' + digest)
    return archive


if __name__ == '__main__':
    argparse.ArgumentParser(description=__doc__).parse_args()
    build()
