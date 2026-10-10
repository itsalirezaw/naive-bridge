import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from naivebridge import manager, model
from tools import package
from test_core import NODE


class ReleaseTests(unittest.TestCase):
    def test_current_pairing_prefix_and_legacy_import(self):
        code = model.encode(NODE)
        self.assertTrue(code.startswith('NB1.'))
        self.assertEqual(model.decode('WB1.' + code[4:]), NODE)

    def test_export_rejects_paths_before_reading(self):
        with self.assertRaises(ValueError):
            manager.export('../node-secret')

    def test_lifecycle_only_lists_configured_owned_services(self):
        with tempfile.TemporaryDirectory() as directory:
            conf = Path(directory)
            (conf / 'node-fi1.json').write_text(json.dumps(NODE))
            (conf / 'iran.json').write_text(json.dumps({'nodes': [{'node': {**NODE, 'id': 'de1'}, 'slot': 0}]}))
            with patch.object(manager, 'CONF', conf):
                names = manager.service_units()
            self.assertEqual(set(names), {'naive-bridge-watch', 'naive-bridge-router', 'naive-bridge-naive-de1',
                                         'naive-bridge-https-fi1', 'naive-bridge-exit-fi1'})

    def test_bundle_allowlist_excludes_server_state_and_checks_engines(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in package.FILES:
                (root / name).write_text('release source\n')
            (root / 'bin').mkdir()
            manifest = ''
            for name in ('naive', 'xray', 'caddy'):
                data = ('test engine ' + name).encode()
                (root / 'bin' / name).write_bytes(data)
                manifest += hashlib.sha256(data).hexdigest() + '  ' + name + '\n'
            (root / 'bin/SHA256SUMS').write_text(manifest)
            for name in ('node-fi1.json', '.env', 'secret.code', 'private.pem'):
                (root / name).write_text('DO NOT SHIP')
            (root / 'evidence').mkdir()
            (root / 'evidence/results.json').write_text('PRIVATE RESULT')
            included = {p.relative_to(root).as_posix() for p in package.sources(root)}
            self.assertFalse(any('secret' in p or 'evidence' in p or p.endswith('.pem') for p in included))
            import tarfile
            with patch('builtins.print'):
                archive = package.build(root)
            with tarfile.open(archive) as tar:
                self.assertEqual(set(tar.getnames()), {'naive-bridge/' + p for p in included})
                self.assertEqual(tar.getmember('naive-bridge/bin/naive').mode, 0o755)
            (root / 'bin/naive').write_bytes(b'corrupted download')
            with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                package.build(root)


if __name__ == '__main__':
    unittest.main()
