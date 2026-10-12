"""Exercise the bundled Caddy's signal reload with a real in-flight TLS response."""
import hashlib
import os
from pathlib import Path
import shutil
import signal
import socket
import ssl
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from naivebridge import render
from test_core import NODE

ENGINE = Path(__file__).resolve().parents[1] / 'bin/caddy'


@unittest.skipUnless(os.name == 'posix' and ENGINE.is_file() and os.access(ENGINE, os.X_OK) and shutil.which('openssl'),
                     'Linux release engine and openssl are required')
class TLSReloadTests(unittest.TestCase):
    def test_signal_loads_new_certificate_without_interrupting_active_download(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('a', 'b'):
                subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '3',
                                '-subj', '/CN=node.example.com', '-addext', 'subjectAltName=DNS:node.example.com',
                                '-keyout', str(root / (name + '.key')), '-out', str(root / (name + '.pem'))],
                               check=True, capture_output=True)
            cert, key = root / 'active.pem', root / 'active.key'
            shutil.copyfile(root / 'a.pem', cert)
            shutil.copyfile(root / 'a.key', key)
            context = ssl.create_default_context(cadata=(root / 'a.pem').read_text() + (root / 'b.pem').read_text())
            expected_cert = ssl.PEM_cert_to_DER_cert((root / 'b.pem').read_text())
            content = root / 'www-fi1' / 'download.bin'
            content.parent.mkdir()
            block = b'NaiveBridge reload test\n' * 4096
            digest = hashlib.sha256()
            with content.open('wb') as stream:
                for _ in range(400):
                    stream.write(block)
                    digest.update(block)
            with socket.socket() as free:
                free.bind(('127.0.0.1', 0))
                port = free.getsockname()[1]
            config = root / 'Caddyfile'
            with patch.object(render, 'CONF', str(root)):
                value = render.caddy(NODE, 20300, str(cert), str(key), port)
            value = value.replace(f':{port}, https://node.example.com:{port} {{',
                                  f':{port}, https://node.example.com:{port} {{\n bind 127.0.0.1')
            config.write_text(value)
            env = {**os.environ, 'XDG_DATA_HOME': str(root / 'data'), 'XDG_CONFIG_HOME': str(root / 'config')}
            with (root / 'caddy.log').open('w') as log:
                process = subprocess.Popen([str(ENGINE), 'run', '--config', str(config), '--adapter', 'caddyfile'],
                                           env=env, stdout=log, stderr=log)
                try:
                    def connect():
                        raw = socket.create_connection(('127.0.0.1', port), timeout=5)
                        try:
                            return context.wrap_socket(raw, server_hostname='node.example.com')
                        except Exception:
                            raw.close()
                            raise
                    deadline = time.monotonic() + 10
                    while True:
                        try:
                            stream = connect()
                            break
                        except OSError:
                            if process.poll() is not None or time.monotonic() >= deadline:
                                self.fail('Caddy did not become ready')
                            time.sleep(0.05)
                    with stream:
                        stream.sendall(b'GET /download.bin HTTP/1.1\r\nHost: node.example.com\r\nConnection: close\r\n\r\n')
                        first = b''
                        while b'\r\n\r\n' not in first:
                            first += stream.recv(4096)
                        headers, data = first.split(b'\r\n\r\n', 1)
                        self.assertIn(b'200 OK', headers)
                        self.assertIn(str(content.stat().st_size).encode(), headers)
                        received, count = hashlib.sha256(data), len(data)
                        shutil.copyfile(root / 'b.pem', cert)
                        shutil.copyfile(root / 'b.key', key)
                        os.kill(process.pid, signal.SIGUSR1)
                        deadline = time.monotonic() + 10
                        while True:
                            with connect() as probe:
                                if probe.getpeercert(binary_form=True) == expected_cert:
                                    break
                            if time.monotonic() >= deadline:
                                self.fail('Signal reload did not load the new certificate')
                            time.sleep(0.05)
                        while chunk := stream.recv(262144):
                            count += len(chunk)
                            received.update(chunk)
                        self.assertEqual(count, content.stat().st_size)
                        self.assertEqual(received.digest(), digest.digest())
                        self.assertIsNone(process.poll())
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
