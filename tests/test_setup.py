import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from naivebridge import certificates, manager, model, setup


class SetupTests(unittest.TestCase):
    def test_ssh_public_destination_needs_no_external_lookup(self):
        with patch.dict(os.environ, {'SSH_CONNECTION': '1.1.1.1 50000 8.8.8.8 22'}), patch.object(setup.urllib.request, 'urlopen') as request:
            self.assertEqual(setup.public_ip(), '8.8.8.8')
            request.assert_not_called()

    def test_local_detection_skips_private_addresses_and_prefers_ipv4(self):
        interfaces = [{'addr_info': [{'local': '10.0.0.1'}, {'local': '2001:4860:4860::8888'}, {'local': '8.8.8.8'}]}]
        with patch.dict(os.environ, {'SSH_CONNECTION': ''}), patch.object(setup.subprocess, 'run', return_value=Mock(stdout=json.dumps(interfaces))), patch.object(setup.urllib.request, 'urlopen') as request:
            self.assertEqual(setup.public_ip(), '8.8.8.8')
            request.assert_not_called()

    def test_nat_detection_and_unavailable_lookup_fall_back_safely(self):
        response = Mock()
        response.read.return_value = b'8.8.8.8\n'
        opened = contextlib.nullcontext(response)
        with patch.dict(os.environ, {'SSH_CONNECTION': '1.1.1.1 50000 10.0.0.1 22'}), patch.object(setup.subprocess, 'run', side_effect=OSError), patch.object(setup.urllib.request, 'urlopen', side_effect=[OSError(), opened]):
            self.assertEqual(setup.public_ip(), '8.8.8.8')
        with patch.dict(os.environ, {'SSH_CONNECTION': ''}), patch.object(setup.subprocess, 'run', side_effect=OSError), patch.object(setup.urllib.request, 'urlopen', side_effect=OSError):
            self.assertIsNone(setup.public_ip())

    def test_lookup_never_uses_private_or_malformed_result(self):
        response = Mock()
        response.read.side_effect = [b'10.0.0.1', b'<html>proxy error</html>']
        with patch.dict(os.environ, {'SSH_CONNECTION': ''}), patch.object(setup.subprocess, 'run', side_effect=OSError), patch.object(setup.urllib.request, 'urlopen', side_effect=lambda *a, **kw: contextlib.nullcontext(response)):
            self.assertIsNone(setup.public_ip())

    def test_port_selection_skips_occupied_ports_and_public_listener(self):
        def free(port):
            if port in (443, 8443, 9443, 20300):
                raise ValueError('occupied')
        with patch.object(setup, 'free_port', side_effect=free):
            self.assertEqual(setup.available_port(setup.HTTPS_PORTS), 10443)
            self.assertEqual(setup.backend_port(exclude=(20301,)), 20302)
        with patch.object(setup, 'free_port', side_effect=ValueError):
            self.assertIsNone(setup.available_port(setup.HTTPS_PORTS))
            with self.assertRaisesRegex(ValueError, '--backend'):
                setup.backend_port()

    def test_actual_ipv4_listener_and_invalid_ports_are_rejected(self):
        with socket.socket() as listener:
            listener.bind(('0.0.0.0', 0))
            listener.listen()
            with self.assertRaisesRegex(ValueError, 'unavailable'):
                setup.free_port(listener.getsockname()[1])
        for port in (0, 65536, True):
            with self.assertRaises(ValueError):
                setup.free_port(port)

    def test_actual_ipv6_only_listener_is_rejected(self):
        try:
            listener = socket.socket(socket.AF_INET6)
            listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            listener.bind(('::', 0))
            listener.listen()
        except OSError:
            if 'listener' in locals():
                listener.close()
            self.skipTest('IPv6 is unavailable')
        with listener:
            with self.assertRaisesRegex(ValueError, 'unavailable'):
                setup.free_port(listener.getsockname()[1])

    def test_menu_accepts_defaults_and_recovers_from_bad_id_and_busy_port(self):
        answers = ['gr1\u200b', 'gr1', '', 'node.example.com', '443', '']
        output = io.StringIO()
        certs = ('/etc/tls/fullchain.pem', '/etc/tls/privkey.pem')
        with tempfile.TemporaryDirectory() as directory, patch.object(manager, 'CONF', Path(directory)), patch('builtins.input', side_effect=answers) as prompt, patch.object(setup, 'public_ip', return_value='8.8.8.8'), patch.object(setup, 'available_port', return_value=10443), patch.object(setup, 'backend_port', return_value=20301), patch.object(manager, 'free_port', side_effect=[ValueError('occupied'), None]), patch.object(setup, 'prompt_certificates', return_value=certs), patch.object(manager, 'outside') as outside, contextlib.redirect_stdout(output):
            manager.outside_menu()
        args = outside.call_args.args[0]
        self.assertEqual((args.id, args.address, args.port, args.backend), ('gr1', '8.8.8.8', 10443, 20301))
        self.assertEqual((args.cert, args.key), certs)
        self.assertIn('lowercase ASCII', output.getvalue())
        self.assertIn('occupied', output.getvalue())
        self.assertIn('Outside server public IP [8.8.8.8]: ', [c.args[0] for c in prompt.call_args_list])

    def test_no_ip_detection_requires_manual_valid_address(self):
        with patch('builtins.input', side_effect=['', 'bad ip', '8.8.4.4']), contextlib.redirect_stdout(io.StringIO()):
            value = setup.prompt('Outside server public IP', None, lambda v: str(manager.ipaddress.ip_address(v)))
        self.assertEqual(value, '8.8.4.4')

    def test_duplicate_id_is_reported_before_ip_detection(self):
        with tempfile.TemporaryDirectory() as directory:
            conf = Path(directory)
            (conf / 'node-gr1.json').write_text('{}')
            with patch.object(manager, 'CONF', conf), patch('builtins.input', side_effect=['gr1', KeyboardInterrupt]), patch.object(setup, 'public_ip') as detect, contextlib.redirect_stdout(io.StringIO()) as output:
                with self.assertRaises(KeyboardInterrupt):
                    manager.outside_menu()
                detect.assert_not_called()
            self.assertIn('menu option 7', output.getvalue())

    def test_auto_certificate_retries_when_port_80_is_busy(self):
        with patch.object(setup, 'existing_certificate', return_value=None), patch.object(certificates, 'method', side_effect=[ValueError('Enter an existing fullchain.pem file'), 'standalone']), patch('builtins.input', side_effect=['', 'auto']), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(setup.prompt_certificates('node.example.com'), ('auto', 'auto'))
        self.assertIn('existing fullchain.pem', output.getvalue())

    def test_cli_backend_default_is_selected_before_any_installation(self):
        args = manager.argparse.Namespace(id='gr1', address='8.8.8.8', domain='node.example.com', port=443, backend=None)
        with tempfile.TemporaryDirectory() as directory, patch.object(manager, 'CONF', Path(directory)), patch.object(setup, 'backend_port', return_value=20301) as select, patch.object(manager, 'free_port', side_effect=ValueError('stop before writing')), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(ValueError, 'stop before writing'):
                manager.outside(args)
            select.assert_called_once_with(exclude=(443, 443))
            self.assertEqual(args.backend, 20301)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_menu_links_are_english_and_do_not_change_option_numbers(self):
        with patch('builtins.input', return_value='0'), contextlib.redirect_stdout(io.StringIO()) as output:
            manager.menu()
        value = output.getvalue()
        self.assertTrue(value.isascii())
        self.assertIn('1) Set up an outside node', value)
        self.assertIn('https://github.com/itsalirezaw', value)
        self.assertIn('https://www.youtube.com/@ialirezaw', value)


@unittest.skipUnless(shutil.which('openssl'), 'openssl is required for certificate integration tests')
class CertificateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name)
        cls.lineage = cls.root / 'node.example.com'
        cls.lineage.mkdir()
        cls.cert = cls.lineage / 'fullchain.pem'
        cls.key = cls.lineage / 'privkey.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '3',
                        '-subj', '/CN=node.example.com', '-addext', 'subjectAltName=DNS:node.example.com',
                        '-keyout', str(cls.key), '-out', str(cls.cert)], check=True, capture_output=True)

    def test_existing_certificate_pair_and_enter_defaults(self):
        with patch.object(setup, 'CERT_ROOT', self.root):
            self.assertEqual(setup.existing_certificate('node.example.com'), (str(self.cert), str(self.key)))
            with patch('builtins.input', side_effect=['', '']), patch.object(setup, 'free_port') as check, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(setup.prompt_certificates('node.example.com'), (str(self.cert), str(self.key)))
                check.assert_not_called()

    def test_wrong_domain_or_private_key_is_rejected(self):
        with patch.object(setup, 'CERT_ROOT', self.root):
            self.assertIsNone(setup.existing_certificate('wrong.example.com'))
        other = self.root / 'other.pem'
        subprocess.run(['openssl', 'genrsa', '-out', str(other), '2048'], check=True, capture_output=True)
        with self.assertRaisesRegex(ValueError, 'do not match'):
            setup.certificate_pair(str(self.cert), str(other))

    def test_expiring_certificate_is_not_suggested(self):
        result = Mock(returncode=0, stdout='Hostname does match certificate')
        expired = Mock(returncode=1)
        with patch.object(setup, 'CERT_ROOT', self.root), patch.object(setup.subprocess, 'run', side_effect=[result, expired]):
            self.assertIsNone(setup.existing_certificate('node.example.com'))

    def test_port_and_directory_input_retry_without_losing_certificate_step(self):
        with patch.object(setup, 'CERT_ROOT', self.root), patch('builtins.input', side_effect=['80', '', str(self.root), '']), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(setup.prompt_certificates('node.example.com'), (str(self.cert), str(self.key)))
        self.assertEqual(output.getvalue().count('not a port or directory'), 2)

    def test_live_symlink_paths_are_preserved_for_renewal(self):
        if os.name == 'nt':
            self.skipTest('symlinks require extra privileges on Windows')
        live = self.root / 'live'
        live.mkdir(exist_ok=True)
        linked = live / 'fullchain.pem'
        linked.symlink_to(self.cert)
        self.assertEqual(setup.certificate_fullchain('node.example.com', str(linked)), str(linked))

    def test_home_paths_are_rejected_even_if_file_exists(self):
        if os.name == 'nt':
            self.skipTest('Linux service path restrictions')
        with patch.object(Path, 'is_file', return_value=True):
            for path in ('/root/fullchain.pem', '/home/user/private.pem', '/run/user/1000/key.pem'):
                with self.assertRaisesRegex(ValueError, 'cannot read'):
                    setup.certificate_file(path)
