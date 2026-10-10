"""Bounded SOCKS5 TCP/UDP probes using normal certificate verification."""
import hashlib
import http.client
import ipaddress
import secrets
import socket
import ssl
import struct

TIMEOUT = 8


def readn(s, count):
    out = b''
    while len(out) < count:
        chunk = s.recv(count - len(out))
        if not chunk:
            raise OSError('Unexpected EOF')
        out += chunk
    return out


def address(host, port):
    try:
        ip = ipaddress.ip_address(host)
        value = bytes([1 if ip.version == 4 else 4]) + ip.packed
    except ValueError:
        value = host.encode('idna')
        if not 1 <= len(value) <= 253:
            raise ValueError('Invalid hostname')
        value = b'\x03' + bytes([len(value)]) + value
    return value + struct.pack('!H', port)


def socks(port, host, target_port, udp=False):
    s = socket.create_connection(('127.0.0.1', port), timeout=TIMEOUT)
    try:
        s.sendall(b'\x05\x01\x00')
        if readn(s, 2) != b'\x05\x00':
            raise OSError('SOCKS authentication failed')
        s.sendall(bytes([5, 3 if udp else 1, 0]) + address(host, target_port))
        head = readn(s, 4)
        if head[:3] != b'\x05\x00\x00' or head[3] not in (1, 3, 4):
            raise OSError('SOCKS connection refused')
        size = {1: 4, 4: 16}.get(head[3])
        raw = readn(s, size) if size else readn(s, readn(s, 1)[0])
        peer = str(ipaddress.ip_address(raw)) if size else raw.decode('ascii')
        return s, (peer, struct.unpack('!H', readn(s, 2))[0])
    except Exception:
        s.close()
        raise


def fetch(port, host, path, target_port=443, limit=131072):
    raw, _ = socks(port, host, target_port)
    try:
        with ssl.create_default_context().wrap_socket(raw, server_hostname=host) as tls:
            tls.sendall(f'GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n'.encode())
            response = http.client.HTTPResponse(tls)
            response.begin()
            data = response.read(limit + 1)
            if response.status != 200 or len(data) > limit:
                raise OSError('Health HTTP response invalid')
            return data
    finally:
        raw.close()


def tcp(port, n):
    body = fetch(port, n['domain'], n['health_path'], n['port'])
    if hashlib.sha256(body).hexdigest() != n['health_sha256']:
        raise OSError('Health content mismatch')
    # Also exercise foreign egress; a reachable local web server alone is insufficient.
    body = fetch(port, 'www.cloudflare.com', '/cdn-cgi/trace', limit=8192)
    if b'ip=' not in body:
        raise OSError('Egress health response invalid')


def udp(port, resolver):
    control, relay = socks(port, '0.0.0.0', 0, udp=True)
    try:
        if not ipaddress.ip_address(relay[0]).is_loopback:
            raise OSError('Nonlocal UDP relay')
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(TIMEOUT)
            ident = secrets.token_bytes(2)
            query = ident + b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'
            sock.sendto(b'\x00\x00\x00' + address(resolver, 53) + query, relay)
            packet, source = sock.recvfrom(4096)
            if source != relay or len(packet) < 10 or packet[:3] != b'\x00\x00\x00':
                raise OSError('Invalid UDP relay response')
            off = 10 if packet[3] == 1 else 22 if packet[3] == 4 else 7 + packet[4]
            response = packet[off:]
            if len(response) < 12 or response[:2] != ident or not response[2] & 128 or response[3] & 15 or not int.from_bytes(response[6:8], 'big'):
                raise OSError('Invalid DNS response')
    finally:
        control.close()
