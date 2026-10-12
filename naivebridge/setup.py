"""Outside setup defaults and validation; never change existing host services."""
import errno
import ipaddress
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import urllib.request

CERT_ROOT = Path('/etc/letsencrypt/live')
HTTPS_PORTS = (443, 8443, 9443, 10443, *range(10444, 10544))
BACKEND_PORTS = range(20300, 20400)


def public_ip():
    """Prefer the SSH destination/local public IPv4; use HTTPS for NAT hosts."""
    def public(value):
        try:
            address = ipaddress.ip_address(value)
            return str(address) if address.is_global else None
        except ValueError:
            return None

    connection = os.environ.get('SSH_CONNECTION', '').split()
    if len(connection) == 4 and public(connection[2]):
        return public(connection[2])
    try:
        result = subprocess.run(['ip', '-j', 'address', 'show', 'scope', 'global'],
                                capture_output=True, text=True, timeout=3, check=True)
        addresses = [public(a.get('local', '')) for interface in json.loads(result.stdout)
                     for a in interface.get('addr_info', [])]
        addresses = sorted({a for a in addresses if a}, key=lambda a: (':' in a, a))
        if addresses:
            return addresses[0]
    except (OSError, ValueError, TypeError, AttributeError, subprocess.SubprocessError):
        pass
    for url in ('https://api.ipify.org', 'https://ipv4.icanhazip.com'):
        try:
            with urllib.request.urlopen(url, timeout=3) as response:
                address = public(response.read(128).decode('ascii').strip())
            if address:
                return address
        except (OSError, ValueError, UnicodeError):
            pass
    return None


def free_port(port):
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('Port must be a number from 1 to 65535.')
    for family, address in ((socket.AF_INET, '0.0.0.0'), (socket.AF_INET6, '::')):
        try:
            with socket.socket(family) as sock:
                if family == socket.AF_INET6:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                sock.bind((address, port))
        except OSError as exc:
            if family == socket.AF_INET6 and exc.errno in (errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT, errno.EADDRNOTAVAIL):
                continue
            raise ValueError(f'Port {port} is unavailable. Choose another free port.') from exc


def available_port(candidates, exclude=()):
    for port in candidates:
        if port in exclude:
            continue
        try:
            free_port(port)
            return port
        except ValueError:
            pass
    return None


def backend_port(exclude=()):
    port = available_port(BACKEND_PORTS, exclude)
    if port is None:
        raise ValueError('No free internal port in 20300-20399. Use outside --backend with another free port.')
    return port


def certificate_file(value):
    path = Path(value)
    if not value or not path.is_absolute() or not path.is_file():
        raise ValueError('Enter an absolute path to an existing certificate/key file, not a port or directory.')
    if any(ch.isspace() for ch in value):
        raise ValueError('Certificate paths must not contain whitespace.')
    # Preserve live symlinks for renewal, but reject targets hidden by ProtectHome.
    for candidate in (path, path.resolve()):
        if any(candidate == root or root in candidate.parents for root in (Path('/root'), Path('/home'), Path('/run/user'))):
            raise ValueError('The service cannot read files under /root, /home or /run/user. Use a path under /etc.')
    return str(path)


def certificate_fullchain(domain, value):
    cert = certificate_file(value)
    try:
        host = subprocess.run(['openssl', 'x509', '-in', cert, '-noout', '-checkhost', domain],
                              capture_output=True, text=True, timeout=10)
        if host.returncode or 'does match certificate' not in host.stdout:
            raise ValueError('The certificate is invalid or does not cover ' + domain + '.')
        expiry = subprocess.run(['openssl', 'x509', '-in', cert, '-noout', '-checkend', '86400'],
                                capture_output=True, text=True, timeout=10)
        if expiry.returncode:
            raise ValueError('The certificate expires within 24 hours. Renew it or enter auto for a new certificate.')
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError('Could not check the certificate with openssl.') from exc
    return cert


def certificate_pair(cert, value):
    key = certificate_file(value)
    try:
        # An explicit password prevents an encrypted key from opening a hidden prompt.
        ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(cert, key, password='')
    except (OSError, ValueError) as exc:
        raise ValueError('The certificate and private key do not match or cannot be loaded. Use an unencrypted matching key.') from exc
    return key


def existing_certificate(domain):
    preferred = CERT_ROOT / domain
    others = sorted(p for p in CERT_ROOT.glob('*') if p.is_dir() and p != preferred)[:64]
    for directory in (preferred, *others):
        cert, key = directory / 'fullchain.pem', directory / 'privkey.pem'
        if not cert.is_file() or not key.is_file():
            continue
        try:
            certificate_fullchain(domain, str(cert))
            certificate_pair(str(cert), str(key))
            return str(cert), str(key)
        except ValueError:
            continue
    return None


def prompt(label, default=None, validate=lambda value: value):
    while True:
        value = input(label + (f' [{default}]' if default is not None else '') + ': ').strip()
        value = default if not value and default is not None else value
        try:
            return validate(value)
        except ValueError as exc:
            print('Invalid input: ' + str(exc))


def prompt_certificates(domain):
    found = existing_certificate(domain)
    if found:
        print('Found a matching certificate. Press Enter to use it, or type auto to request a new one.')
    else:
        print('Press Enter for automatic issuance (requires free, reachable TCP port 80), or enter an existing fullchain.pem path.')
    print('This is a file path, not a port number.')

    def fullchain(value):
        if value == 'auto':
            try:
                free_port(80)
            except ValueError as exc:
                raise ValueError('Automatic issuance requires free TCP port 80. Enter an existing fullchain.pem path instead.') from exc
            return value
        return certificate_fullchain(domain, value)

    cert = prompt('Certificate fullchain file or auto', found[0] if found else 'auto', fullchain)
    if cert == 'auto':
        return 'auto', 'auto'
    key = found[1] if found and cert == found[0] else str(Path(cert).parent / 'privkey.pem')
    default = key if Path(key).is_file() else None
    key = prompt('Certificate private key file', default, lambda value: certificate_pair(cert, value))
    return cert, key
