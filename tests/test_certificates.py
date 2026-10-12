import configparser
import contextlib
import io
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from naivebridge import certificates as acme, setup


class CertificateAutomationTests(unittest.TestCase):
    def test_certbot_timeout_allows_challenge_cleanup_before_returning_error(self):
        process = Mock()
        process.communicate.side_effect = [subprocess.TimeoutExpired('certbot', 300), ('', '')]
        with patch.object(acme.subprocess, 'Popen') as popen:
            popen.return_value.__enter__.return_value = process
            with self.assertRaisesRegex(RuntimeError, 'could not complete'):
                acme.command(['/usr/bin/certbot', 'certonly'], 300)
        process.send_signal.assert_called_once_with(signal.SIGINT)
        process.kill.assert_not_called()

    def test_active_nginx_is_used_without_requiring_a_free_port(self):
        with patch.object(acme, 'nginx_active', return_value=True), patch.object(acme, 'command', side_effect=['', 'LISTEN users:(("nginx",pid=1,fd=4))\n']) as run, patch.object(setup, 'free_port') as free:
            self.assertEqual(acme.method(), 'nginx')
            free.assert_not_called()
        self.assertEqual(run.call_args_list[0].args[0], ['nginx', '-t'])

    def test_other_port_owner_and_invalid_nginx_config_fail_before_acme(self):
        with patch.object(acme, 'nginx_active', return_value=True), patch.object(acme, 'command', side_effect=['', 'LISTEN users:(("docker-proxy",pid=1))']):
            with self.assertRaisesRegex(ValueError, 'another service'):
                acme.method()
        with patch.object(acme, 'nginx_active', return_value=True), patch.object(acme, 'command', side_effect=RuntimeError('invalid config')):
            with self.assertRaisesRegex(RuntimeError, 'invalid config'):
                acme.method()

    def test_standalone_is_only_used_when_nginx_is_inactive_and_port_is_free(self):
        with patch.object(acme, 'nginx_active', return_value=False), patch.object(setup, 'free_port') as free:
            self.assertEqual(acme.method(), 'standalone')
            free.assert_called_once_with(80)
        with patch.object(acme, 'nginx_active', return_value=False), patch.object(setup, 'free_port', side_effect=ValueError):
            with self.assertRaisesRegex(ValueError, 'host Nginx is not active'):
                acme.method()

    def test_nginx_auto_prompt_accepts_enter_while_port_80_is_busy(self):
        with patch.object(setup, 'existing_certificate', return_value=None), patch.object(acme, 'method', return_value='nginx'), patch('builtins.input', return_value=''), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(setup.prompt_certificates('node.example.com'), ('auto', 'auto'))

    def test_obtain_uses_isolated_lineage_and_certonly_not_nginx_tls_install(self):
        with patch.object(acme.socket, 'getaddrinfo', return_value=[(0, 0, 0, '', ('203.0.113.5', 80))]), patch.object(acme, 'method', return_value='nginx'), patch.object(acme, 'certbot', return_value='/usr/bin/certbot'), patch.object(acme, 'backup_nginx') as backup, patch.object(acme, 'command', return_value='') as run, contextlib.redirect_stdout(io.StringIO()):
            cert, key = acme.obtain('node.example.com', '203.0.113.5')
        backup.assert_called_once()
        invocation = run.call_args_list[0].args[0]
        self.assertIn('certonly', invocation)
        self.assertEqual(invocation[invocation.index('--authenticator') + 1], 'nginx')
        self.assertIn('--no-directory-hooks', invocation)
        self.assertNotIn('--force-renewal', invocation)
        self.assertIn('naive-bridge-', cert)
        self.assertEqual(Path(cert).parent, Path(key).parent)
        self.assertEqual(run.call_args_list[-1].args[0], ['nginx', '-t'])

    def test_wrong_dns_never_installs_plugins_or_touches_nginx(self):
        with patch.object(acme.socket, 'getaddrinfo', return_value=[(0, 0, 0, '', ('203.0.113.9', 80))]), patch.object(acme, 'certbot') as install, patch.object(acme, 'backup_nginx') as backup:
            with self.assertRaisesRegex(ValueError, 'resolve directly'):
                acme.obtain('node.example.com', '203.0.113.5')
            install.assert_not_called()
            backup.assert_not_called()

    def test_nginx_config_is_checked_even_after_issuance_failure(self):
        with patch.object(acme.socket, 'getaddrinfo', return_value=[(0, 0, 0, '', ('203.0.113.5', 80))]), patch.object(acme, 'method', return_value='nginx'), patch.object(acme, 'certbot', return_value='/usr/bin/certbot'), patch.object(acme, 'backup_nginx'), patch.object(acme, 'command', side_effect=[RuntimeError('ACME failed'), '']) as run, contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, 'ACME failed'):
                acme.obtain('node.example.com', '203.0.113.5')
            self.assertEqual(run.call_args_list[-1].args[0], ['nginx', '-t'])

    def test_backup_preserves_symlinks_and_is_private(self):
        if os.name == 'nt':
            self.skipTest('Linux permissions and symlinks')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            nginx = root / 'nginx'
            nginx.mkdir()
            (nginx / 'nginx.conf').write_text('events {}\nhttp {}')
            (nginx / 'linked.conf').symlink_to(nginx / 'nginx.conf')
            with patch.object(acme, 'NGINX_ROOT', nginx), patch.object(acme, 'BACKUPS', root / 'backups'), patch.object(acme, 'command'), contextlib.redirect_stdout(io.StringIO()):
                acme.backup_nginx()
            saved = next((root / 'backups').glob('*/nginx'))
            self.assertTrue((saved / 'linked.conf').is_symlink())
            self.assertEqual((saved / 'nginx.conf').read_text(), (nginx / 'nginx.conf').read_text())
            self.assertEqual((root / 'backups').stat().st_mode & 0o777, 0o700)

    def config(self, auth='standalone', hooks=''):
        c = configparser.ConfigParser()
        c.read_string('[renewalparams]\nauthenticator = ' + auth + '\n' + hooks)
        return c

    def test_existing_standalone_migrates_with_staging_checked_reconfigure(self):
        with patch.object(acme, 'renewal_info', return_value=('example.com', self.config())), patch.object(acme, 'nginx_active', return_value=True), patch.object(acme, 'method', return_value='nginx'), patch.object(acme, 'certbot', return_value='/usr/bin/certbot'), patch.object(acme, 'backup_nginx'), patch.object(acme, 'command', side_effect=['certbot 5.8.0', '', '']) as run, contextlib.redirect_stdout(io.StringIO()):
            acme.prepare_renewal('/etc/letsencrypt/live/example.com/fullchain.pem')
        args = run.call_args_list[1].args[0]
        self.assertIn('reconfigure', args)
        self.assertIn('--no-directory-hooks', args)
        self.assertNotIn('--force-renewal', args)

    def test_older_certbot_only_migrates_after_successful_dry_run(self):
        with patch.object(acme, 'renewal_info', return_value=('example.com', self.config())), patch.object(acme, 'nginx_active', return_value=True), patch.object(acme, 'method', return_value='nginx'), patch.object(acme, 'certbot', return_value='/usr/bin/certbot'), patch.object(acme, 'backup_nginx'), patch.object(acme, 'command', side_effect=['certbot 1.21.0', RuntimeError('dry run failed'), '']) as run, contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, 'dry run failed'):
                acme.prepare_renewal('/etc/letsencrypt/live/example.com/fullchain.pem')
        self.assertIn('--dry-run', run.call_args_list[1].args[0])
        self.assertEqual(run.call_args_list[2].args[0], ['nginx', '-t'])
        self.assertFalse(any('--force-renewal' in c.args[0] for c in run.call_args_list))

    def test_existing_webroot_is_not_reconfigured(self):
        with patch.object(acme, 'renewal_info', return_value=('example.com', self.config('webroot'))), patch.object(acme, 'certbot') as install:
            acme.prepare_renewal('/etc/letsencrypt/live/example.com/fullchain.pem')
            install.assert_not_called()

    def test_custom_stop_hooks_are_never_executed_during_migration(self):
        with patch.object(acme, 'renewal_info', return_value=('example.com', self.config(hooks='pre_hook = systemctl stop nginx'))), patch.object(acme, 'nginx_active', return_value=True), patch.object(acme, 'command') as run:
            with self.assertRaisesRegex(ValueError, 'custom renewal hooks'):
                acme.prepare_renewal('/etc/letsencrypt/live/example.com/fullchain.pem')
            run.assert_not_called()

    def test_renewal_config_with_global_keys_is_read_and_external_files_are_skipped(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(acme, 'LE_ROOT', Path(directory)):
            root = Path(directory)
            (root / 'renewal').mkdir()
            (root / 'renewal/example.com.conf').write_text('version = 5.8.0\n[renewalparams]\nauthenticator = nginx\n')
            name, config = acme.renewal_info(str(root / 'live/example.com/fullchain.pem'))
            self.assertEqual((name, config.get('renewalparams', 'authenticator')), ('example.com', 'nginx'))
            self.assertIsNone(acme.renewal_info('/etc/custom/fullchain.pem'))

    def test_reuses_active_certbot_timer_without_touching_service_state(self):
        writes = Mock()
        with patch.object(acme, 'renewal_info', return_value=('example.com', self.config('nginx'))), patch.object(acme.subprocess, 'run', return_value=Mock(returncode=0)), patch.object(acme, 'command') as run, contextlib.redirect_stdout(io.StringIO()):
            acme.configure_renewal('fi1', '/etc/letsencrypt/live/example.com/fullchain.pem', '/etc/naive-bridge/Caddyfile-fi1', '/opt/naive-bridge', writes)
        self.assertEqual(writes.call_count, 1)
        run.assert_not_called()

    def test_missing_scheduler_creates_a_lineage_scoped_timer(self):
        writes = Mock()
        with patch.object(acme, 'renewal_info', return_value=('example.com', self.config('nginx'))), patch.object(acme.subprocess, 'run', return_value=Mock(returncode=3)), patch.object(acme, 'certbot', return_value='/usr/bin/certbot'), patch.object(acme, 'command'), contextlib.redirect_stdout(io.StringIO()):
            acme.configure_renewal('fi1', '/etc/letsencrypt/live/example.com/fullchain.pem', '/etc/naive-bridge/Caddyfile-fi1', '/opt/naive-bridge', writes)
        content = '\n'.join(c.args[1] for c in writes.call_args_list)
        self.assertIn('renew --cert-name example.com', content)
        self.assertIn('Persistent=true', content)
        self.assertNotIn('systemctl restart', content)

    def test_deploy_hook_skips_unrelated_lineages_and_stopped_services(self):
        if os.name == 'nt':
            self.skipTest('Shell integration test')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / 'calls'
            tool = root / 'systemctl'
            tool.write_text('#!/bin/sh\necho "$*" >> "$CALL_LOG"\nexit 3\n')
            tool.chmod(0o755)
            hook = root / 'hook.sh'
            hook.write_text(acme.deploy_hook('fi1', '/etc/letsencrypt/live/example.com/fullchain.pem', '/etc/naive-bridge/Caddyfile-fi1', '/opt/naive-bridge'))
            env = {**os.environ, 'PATH': str(root) + ':' + os.environ['PATH'], 'CALL_LOG': str(log), 'RENEWED_LINEAGE': '/etc/letsencrypt/live/other.com'}
            subprocess.run(['sh', str(hook)], env=env, check=True)
            self.assertFalse(log.exists())
            env['RENEWED_LINEAGE'] = '/etc/letsencrypt/live/example.com'
            subprocess.run(['sh', str(hook)], env=env, check=True)
            self.assertEqual(log.read_text().strip(), 'is-active --quiet naive-bridge-https-fi1')

    def test_deploy_hook_validates_then_signals_only_active_matching_node(self):
        if os.name == 'nt':
            self.skipTest('Shell integration test')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'bin').mkdir()
            for name in ('systemctl', 'bin/caddy'):
                tool = root / name
                tool.write_text('#!/bin/sh\necho "' + name + ' $*" >> "$CALL_LOG"\n')
                tool.chmod(0o755)
            hook = root / 'hook.sh'
            hook.write_text(acme.deploy_hook('fi1', '/etc/letsencrypt/live/example.com/fullchain.pem', '/etc/naive-bridge/Caddyfile-fi1', root))
            log = root / 'calls'
            env = {**os.environ, 'PATH': str(root) + ':' + os.environ['PATH'], 'CALL_LOG': str(log), 'RENEWED_LINEAGE': '/etc/letsencrypt/live/example.com'}
            subprocess.run(['sh', str(hook)], env=env, check=True)
            lines = log.read_text().splitlines()
            self.assertEqual(len(lines), 3)
            self.assertIn('validate --config', lines[1])
            self.assertEqual(lines[2], 'systemctl kill --kill-who=main --signal=USR1 naive-bridge-https-fi1')
