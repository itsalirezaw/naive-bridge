"""Certbot integration for active host Nginx and unattended renewal."""
import configparser
import hashlib
import ipaddress
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import socket
import subprocess
import tempfile

from . import setup

LE_ROOT = Path('/etc/letsencrypt')
NGINX_ROOT = Path('/etc/nginx')
BACKUPS = Path('/var/lib/naive-bridge/nginx-backups')
UNITS = Path('/etc/systemd/system')


def command(args, timeout=30):
    try:
        env = {**os.environ, 'DEBIAN_FRONTEND': 'noninteractive', 'NEEDRESTART_MODE': 'l'}
        if Path(args[0]).name == 'certbot':
            # Give Certbot time to roll back its temporary Nginx challenge on timeout.
            with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env) as process:
                try:
                    stdout, _ = process.communicate(timeout=timeout)
                except subprocess.TimeoutExpired:
                    process.send_signal(signal.SIGINT)
                    try:
                        process.communicate(timeout=30)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.communicate()
                    raise
                result = subprocess.CompletedProcess(args, process.returncode, stdout)
        else:
            result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=env)
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f'{Path(args[0]).name} could not complete; inspect the local Certbot/Nginx logs.') from exc
    if result.returncode:
        raise RuntimeError(f'{Path(args[0]).name} failed (exit {result.returncode}); inspect /var/log/letsencrypt and the Nginx logs.')
    return result.stdout


def nginx_active():
    if not shutil.which('nginx'):
        return False
    try:
        return subprocess.run(['systemctl', 'is-active', '--quiet', 'nginx'],
                              capture_output=True, timeout=10).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def method():
    if nginx_active():
        command(['nginx', '-t'])
        # Do not mistake a Docker proxy or another web server for host Nginx.
        listeners = command(['ss', '-H', '-ltnp', 'sport = :80'])
        if any('"nginx"' not in line for line in listeners.splitlines() if line.strip()):
            raise ValueError('TCP port 80 belongs to another service. Automatic Nginx issuance requires host Nginx on port 80.')
        return 'nginx'
    try:
        setup.free_port(80)
    except ValueError as exc:
        raise ValueError('TCP port 80 is busy and host Nginx is not active. Supply an existing fullchain.pem file.') from exc
    return 'standalone'


def certbot(authenticator):
    binary = shutil.which('certbot') or ('/snap/bin/certbot' if Path('/snap/bin/certbot').exists() else None)
    if not binary:
        apt = shutil.which('apt-get')
        if not apt:
            raise ValueError('Install Certbot first; automatic dependency installation needs apt-get.')
        print('Installing Certbot...', flush=True)
        command([apt, 'update'], 240)
        command([apt, 'install', '-y', 'certbot'], 240)
        binary = shutil.which('certbot')
    if not binary:
        raise RuntimeError('Certbot was not found after installation.')
    if authenticator == 'nginx':
        plugins = command([binary, 'plugins', '--text'], 60)
        if not re.search(r'^\* nginx\s*$', plugins, re.M):
            apt = shutil.which('apt-get')
            if not apt or Path(binary).resolve().as_posix().startswith('/snap/'):
                raise ValueError('This Certbot installation has no Nginx plugin. Install its matching Nginx plugin.')
            print('Installing the Certbot Nginx plugin...', flush=True)
            command([apt, 'update'], 240)
            command([apt, 'install', '-y', 'python3-certbot-nginx'], 240)
            if not re.search(r'^\* nginx\s*$', command([binary, 'plugins', '--text'], 60), re.M):
                raise RuntimeError('The Certbot Nginx plugin is unavailable after installation.')
    return binary


def backup_nginx():
    command(['nginx', '-t'])
    BACKUPS.mkdir(parents=True, exist_ok=True, mode=0o700)
    BACKUPS.chmod(0o700)
    target = Path(tempfile.mkdtemp(prefix='before-acme-', dir=BACKUPS)) / 'nginx'
    shutil.copytree(NGINX_ROOT, target, symlinks=True)
    print('Nginx configuration backup: ' + str(target))


def obtain(domain, address):
    addresses = {ipaddress.ip_address(item[4][0]) for item in socket.getaddrinfo(domain, 80)}
    if ipaddress.ip_address(address) not in addresses:
        raise ValueError('Domain must resolve directly to the supplied outside IP.')
    auth = method()
    binary = certbot(auth)
    if auth == 'nginx':
        backup_nginx()
        print('Obtaining a certificate through active Nginx; only graceful reloads are used.', flush=True)
    else:
        print('Obtaining a certificate using free TCP port 80...', flush=True)
    # Use our own lineage; never replace another application's certificate/SANs.
    name = 'naive-bridge-' + hashlib.sha256(domain.encode()).hexdigest()[:20]
    try:
        command([binary, 'certonly', '--authenticator', auth, '--cert-name', name,
                 '--keep-until-expiring', '--non-interactive', '--agree-tos',
                 '--register-unsafely-without-email', '--no-directory-hooks',
                 '--pre-hook', '', '--post-hook', '', '--deploy-hook', '', '-d', domain], 300)
    finally:
        if auth == 'nginx':
            command(['nginx', '-t'])
    return str(LE_ROOT / 'live' / name / 'fullchain.pem'), str(LE_ROOT / 'live' / name / 'privkey.pem')


def renewal_info(cert):
    lineage = Path(cert).parent
    if lineage.parent != LE_ROOT / 'live':
        return None
    name = lineage.name
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,240}', name):
        raise ValueError('Unsupported Certbot certificate name.')
    renewal = LE_ROOT / 'renewal' / (name + '.conf')
    if not renewal.is_file():
        raise ValueError('Certbot renewal configuration is missing for ' + name + '.')
    config = configparser.ConfigParser(interpolation=None, strict=False)
    try:
        config.read_string('[certificate]\n' + renewal.read_text())
    except configparser.Error as exc:
        raise ValueError('Cannot read Certbot renewal settings for ' + name + '.') from exc
    return name, config


def prepare_renewal(cert):
    info = renewal_info(cert)
    if info is None:
        return
    name, config = info
    auth = config.get('renewalparams', 'authenticator', fallback='')
    if auth != 'standalone' or not nginx_active():
        return
    # Migrating a third-party hook could stop a live web server. Do not execute it.
    if any(config.get('renewalparams', k, fallback='').strip() for k in ('pre_hook', 'post_hook', 'deploy_hook')):
        raise ValueError('This existing certificate has custom renewal hooks. Enter auto to create a separate managed certificate.')
    method()  # Validate Nginx and ownership of port 80 before migration.
    binary = certbot('nginx')
    backup_nginx()
    version = re.search(r'(\d+)\.(\d+)', command([binary, '--version']))
    print('Updating standalone renewal to use active Nginx...', flush=True)
    try:
        if version and tuple(map(int, version.groups())) >= (2, 3):
            command([binary, 'reconfigure', '--cert-name', name, '--authenticator', 'nginx',
                     '--non-interactive', '--no-directory-hooks'], 300)
        else:
            base = [binary, 'renew', '--cert-name', name, '--authenticator', 'nginx',
                    '--non-interactive', '--no-directory-hooks', '--no-random-sleep-on-renew']
            command([*base, '--dry-run'], 300)
            command([*base, '--force-renewal'], 300)
    finally:
        command(['nginx', '-t'])


def deploy_hook(ident, cert, caddy, root):
    lineage = shlex.quote(str(Path(cert).parent))
    config = shlex.quote(str(caddy))
    engine = shlex.quote(str(Path(root) / 'bin/caddy'))
    service = 'naive-bridge-https-' + ident
    return ('#!/bin/sh\nset -eu\n'
            f'[ "${{RENEWED_LINEAGE:-}}" = {lineage} ] || exit 0\n'
            f'systemctl is-active --quiet {service} || exit 0\n'
            f'{engine} validate --config {config} --adapter caddyfile >/dev/null 2>&1\n'
            # Bundled Caddy supports forced config/certificate reload via SIGUSR1,
            # including with admin off. Target only the running main process.
            f'systemctl kill --kill-who=main --signal=USR1 {service}\n')


def configure_renewal(ident, cert, caddy, root, write):
    info = renewal_info(cert)
    if info is None:
        print('External certificate: renewal remains with its existing certificate manager.')
        return
    name, config = info
    write(LE_ROOT / 'renewal-hooks/deploy' / ('naive-bridge-' + ident),
          deploy_hook(ident, cert, caddy, root), 0o700)
    # Reuse an active distribution/snap timer. Otherwise schedule only this lineage.
    for timer in ('certbot.timer', 'snap.certbot.renew.timer'):
        if subprocess.run(['systemctl', 'is-active', '--quiet', timer], capture_output=True, timeout=10).returncode == 0:
            print('Automatic certificate renewal: ' + timer)
            return
    binary = certbot(config.get('renewalparams', 'authenticator', fallback='standalone'))
    timer = 'naive-bridge-cert-' + hashlib.sha256(name.encode()).hexdigest()[:16]
    write(UNITS / (timer + '.service'), '[Unit]\nDescription=NaiveBridge certificate renewal\nAfter=network-online.target\nWants=network-online.target\n'
          '[Service]\nType=oneshot\nUMask=0077\n'
          f'ExecStart={binary} renew --cert-name {name} --non-interactive --quiet\n', 0o644)
    write(UNITS / (timer + '.timer'), '[Unit]\nDescription=NaiveBridge certificate renewal schedule\n'
          '[Timer]\nOnCalendar=*-*-* 00,12:00:00\nRandomizedDelaySec=3600\nPersistent=true\n'
          '[Install]\nWantedBy=timers.target\n', 0o644)
    command(['systemctl', 'daemon-reload'])
    command(['systemctl', 'enable', '--now', timer + '.timer'])
    print('Automatic certificate renewal: ' + timer + '.timer')
