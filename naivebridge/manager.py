import argparse
import concurrent.futures
import getpass
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import time
import uuid

from . import model, probe, render

CONF = Path(render.CONF)
ROOT = Path(render.ROOT)
STATE = Path('/var/lib/naive-bridge')
UNITS = Path('/etc/systemd/system')


def run(args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=30)
    if result.returncode:
        # Do not echo config contents or credentials from child-process diagnostics.
        raise RuntimeError(f'{Path(args[0]).name} failed (exit {result.returncode}); inspect local service logs')
    return result.stdout


def write(path, value, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + '.tmp')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'w') as out:
            out.write(value)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()


def save(path, obj):
    write(path, json.dumps(obj, indent=2))


def entries():
    p = CONF / 'iran.json'
    return json.loads(p.read_text())['nodes'] if p.exists() else []


def free_port(port):
    with socket.socket() as s:
        try:
            s.bind(('0.0.0.0', port))
        except OSError as exc:
            raise ValueError(f'Port {port} is occupied / پورت {port} اشغال است؛ پورت دیگری انتخاب کنید یا راهنمای همزیستی با وب‌سرور را بخوانید.') from exc


def unit(name, command):
    write(UNITS / (name + '.service'), render.unit(command, name), 0o644)


def check_xray(path):
    run([str(ROOT / 'bin/xray'), 'run', '-test', '-config', str(path)])


def apply_iran(new):
    old = entries()
    for e in new:
        model.node(e['node'])
        if type(e['slot']) is not int or not 0 <= e['slot'] < 32:
            raise ValueError('Invalid node slot')
    if len({e['slot'] for e in new}) != len(new) or len({e['node']['id'] for e in new}) != len(new):
        raise ValueError('Duplicate node ID or slot')
    candidate = CONF / 'iran-candidate.json'
    save(candidate, render.iran(new))
    check_xray(candidate)
    if not (CONF / 'iran.json').exists():
        for p in (20080, 20085):
            free_port(p)
    for e in new:
        if e['node']['id'] not in {x['node']['id'] for x in old}:
            for p in (20100 + 2 * e['slot'], 20101 + 2 * e['slot'], 20200 + e['slot']):
                free_port(p)
    for e in new:
        n = e['node']
        save(CONF / ('naive-' + n['id'] + '.json'), render.naive(n, e['slot']))
        unit('naive-bridge-naive-' + n['id'], f'{ROOT}/bin/naive {CONF}/naive-{n["id"]}.json')
    unit('naive-bridge-router', f'{ROOT}/bin/xray run -config {CONF}/router.json')
    unit('naive-bridge-watch', f'/usr/bin/python3 -m naivebridge.manager watch')
    # Python package is installed into ROOT; the service launches through an absolute wrapper.
    watch_path = UNITS / 'naive-bridge-watch.service'
    write(watch_path, watch_path.read_text().replace('/usr/bin/python3 -m naivebridge.manager watch', '/usr/local/bin/naive-bridge watch').replace('Restart=always', 'WatchdogSec=180\nNotifyAccess=main\nRestart=always'), 0o644)
    prior = (CONF / 'router.json').read_text() if (CONF / 'router.json').exists() else None
    try:
        save(CONF / 'iran.json', {'version': 1, 'nodes': new})
        os.replace(candidate, CONF / 'router.json')
        run(['systemctl', 'daemon-reload'])
        for e in new:
            run(['systemctl', 'enable', '--now', 'naive-bridge-naive-' + e['node']['id']])
            if any(x['node']['id'] == e['node']['id'] and x != e for x in old):
                run(['systemctl', 'restart', 'naive-bridge-naive-' + e['node']['id']])
        run(['systemctl', 'enable', 'naive-bridge-router', 'naive-bridge-watch'])
        run(['systemctl', 'restart', 'naive-bridge-router', 'naive-bridge-watch'])
        run(['systemctl', 'is-active', 'naive-bridge-router', 'naive-bridge-watch'])
    except Exception:
        save(CONF / 'iran.json', {'version': 1, 'nodes': old})
        for e in old:
            save(CONF / ('naive-' + e['node']['id'] + '.json'), render.naive(e['node'], e['slot']))
            run(['systemctl', 'restart', 'naive-bridge-naive-' + e['node']['id']])
        for e in new:
            if e['node']['id'] not in {x['node']['id'] for x in old}:
                run(['systemctl', 'disable', '--now', 'naive-bridge-naive-' + e['node']['id']])
        if prior is not None:
            write(CONF / 'router.json', prior)
            run(['systemctl', 'restart', 'naive-bridge-router', 'naive-bridge-watch'])
        else:
            run(['systemctl', 'disable', '--now', 'naive-bridge-router', 'naive-bridge-watch'])
            (CONF / 'iran.json').unlink(missing_ok=True)
        raise
    for e in old:
        if e['node']['id'] not in {x['node']['id'] for x in new}:
            name = 'naive-bridge-naive-' + e['node']['id']
            run(['systemctl', 'disable', '--now', name])
            (UNITS / (name + '.service')).unlink(missing_ok=True)
            (CONF / ('naive-' + e['node']['id'] + '.json')).unlink(missing_ok=True)
    print('Iran ready. Automatic SOCKS: 127.0.0.1:20080. Initial health checks take about 20 seconds.')


def add(code, replace=False):
    n = model.decode(code)
    new = entries()
    if any(e['node']['id'] == n['id'] for e in new):
        if not replace:
            raise ValueError('Node ID already exists; use add --replace to update it')
        for e in new:
            if e['node']['id'] == n['id']:
                e['node'] = n
        apply_iran(new)
        return
    slot = next((i for i in range(32) if i not in {e['slot'] for e in new}), None)
    if slot is None:
        raise ValueError('Maximum 32 nodes')
    new.append({'node': n, 'slot': slot})
    apply_iran(new)


def outside(args):
    n = model.node({'version': 1, 'id': args.id, 'address': args.address,
                    'domain': args.domain, 'port': args.port,
                    'username': secrets.token_hex(12), 'password': secrets.token_urlsafe(32),
                    'uuid': str(uuid.uuid4()), 'path': '/api/' + secrets.token_hex(24),
                    'health_path': '/assets/' + secrets.token_hex(24), 'health_sha256': '0' * 64})
    descriptor = CONF / ('node-' + n['id'] + '.json')
    if descriptor.exists():
        raise ValueError('Node already exists; use export to retrieve its pairing code')
    listen_port = getattr(args, 'listen_port', None) or args.port
    for p in (listen_port, args.backend):
        if not 1 <= p <= 65535:
            raise ValueError('Invalid local port')
        free_port(p)
    if listen_port == args.backend:
        raise ValueError('Public and backend ports must differ')
    if args.cert == 'auto':
        if n['address'] not in {item[4][0] for item in socket.getaddrinfo(n['domain'], 80)}:
            raise ValueError('Domain must resolve directly to the supplied outside IP')
        free_port(80)
        certbot = shutil.which('certbot') or ('/snap/bin/certbot' if Path('/snap/bin/certbot').exists() else None)
        if not certbot:
            apt = shutil.which('apt-get')
            if not apt:
                raise ValueError('Install certbot first, or supply existing --cert and --key paths')
            print('Installing certbot for automatic certificate issuance...', flush=True)
            subprocess.run([apt, 'update'], check=True, timeout=180)
            subprocess.run([apt, 'install', '-y', 'certbot'], check=True, timeout=180)
            certbot = shutil.which('certbot')
        subprocess.run([certbot, 'certonly', '--standalone', '--non-interactive', '--agree-tos', '--register-unsafely-without-email', '-d', n['domain']], check=True, timeout=180)
        args.cert = '/etc/letsencrypt/live/' + n['domain'] + '/fullchain.pem'
        args.key = '/etc/letsencrypt/live/' + n['domain'] + '/privkey.pem'
    # Preserve certbot's live symlinks: resolving to archive/fullchain1.pem would freeze renewal.
    cert, key = os.path.abspath(args.cert), os.path.abspath(args.key)
    if any(ch.isspace() for ch in cert + key) or '\n' in cert + key:
        raise ValueError('Certificate paths must not contain whitespace')
    if cert.startswith('/root/') or key.startswith('/root/'):
        raise ValueError('Use certificate paths under /etc; the service cannot access /root')
    # Verify SAN, expiry, chain presentation and private-key match locally before installation.
    matched = run(['openssl', 'x509', '-in', cert, '-noout', '-checkhost', n['domain']])
    if 'does match certificate' not in matched:
        raise ValueError('Certificate does not cover this domain')
    run(['openssl', 'x509', '-in', cert, '-noout', '-checkend', '86400'])
    import ssl
    ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(cert, key)
    www = CONF / ('www-' + n['id'])
    health = secrets.token_bytes(65536)
    target = www / n['health_path'].lstrip('/')
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(health)
    n['health_sha256'] = hashlib.sha256(health).hexdigest()
    write(www / 'index.html', '<!doctype html><html><head><title>Welcome</title></head><body><p>Welcome</p></body></html>')
    xray = CONF / ('exit-' + n['id'] + '.json')
    caddy = CONF / ('Caddyfile-' + n['id'])
    save(xray, render.outside(n, args.backend))
    write(caddy, render.caddy(n, args.backend, cert, key, listen_port, getattr(args, 'proxy_protocol', False)))
    check_xray(xray)
    run([str(ROOT / 'bin/caddy'), 'validate', '--config', str(caddy), '--adapter', 'caddyfile'])
    unit('naive-bridge-exit-' + n['id'], f'{ROOT}/bin/xray run -config {xray}')
    unit('naive-bridge-https-' + n['id'], f'{ROOT}/bin/caddy run --config {caddy} --adapter caddyfile')
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'enable', '--now', 'naive-bridge-exit-' + n['id'], 'naive-bridge-https-' + n['id']])
    run(['systemctl', 'is-active', 'naive-bridge-exit-' + n['id'], 'naive-bridge-https-' + n['id']])
    save(descriptor, n)
    # Certbot updates referenced files; reload these isolated listeners after renewal.
    hooks = Path('/etc/letsencrypt/renewal-hooks/deploy')
    if cert.startswith('/etc/letsencrypt/'):
        hooks.mkdir(parents=True, exist_ok=True)
        write(hooks / ('naive-bridge-' + n['id']), '#!/bin/sh\nset -eu\n' +
              f'{ROOT}/bin/caddy validate --config {caddy} --adapter caddyfile >/dev/null 2>&1\n' +
              f'systemctl restart naive-bridge-https-{n["id"]}\n', 0o700)
    print('Outside node ready. Pairing code is secret; copy it only to your Iran server:')
    print(model.encode(n))


def check_one(kind, e):
    n, slot = e['node'], e['slot']
    try:
        if kind == 'udp':
            for resolver in ('1.1.1.1', '9.9.9.9'):
                try:
                    probe.udp(20101 + 2 * slot, resolver)
                    return True
                except (OSError, ValueError):
                    pass
            return False
        probe.tcp(20100 + 2 * slot + (kind == 'xhttp'), n)
        return True
    except (OSError, ValueError, http.client.HTTPException):
        return False


def watch():
    nodes = entries()
    health = {e['node']['id'] + '-' + kind: model.Health() for e in nodes for kind in ('naive', 'xhttp', 'udp')}
    while True:
        start = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(16, max(1, len(health)))) as pool:
            futures = {pool.submit(check_one, k, e): e['node']['id'] + '-' + k for e in nodes for k in ('naive', 'xhttp', 'udp')}
            for future in concurrent.futures.as_completed(futures):
                health[futures[future]].record(future.result())
        choices = model.choose(nodes, {k: h.up for k, h in health.items()})
        applied = {}
        for balancer, target in choices.items():
            try:
                run([str(ROOT / 'bin/xray'), 'api', 'bo', '--server=127.0.0.1:20085', '-b', balancer, target])
                applied[balancer] = target
            except RuntimeError:
                applied[balancer] = 'api-unavailable'
        save(STATE / 'health.json', {'updated_at': int(time.time()), 'healthy': {k: h.up for k, h in health.items()}, 'routes': applied})
        # A systemd watchdog also restarts the controller if it gets stuck.
        if os.environ.get('NOTIFY_SOCKET'):
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as notify:
                notify.connect(os.environ['NOTIFY_SOCKET'])
                notify.sendall(b'WATCHDOG=1')
        time.sleep(max(1, 10 - (time.monotonic() - start)))


def status():
    p = STATE / 'health.json'
    data = json.loads(p.read_text()) if p.exists() else {'routes': {}, 'healthy': {}}
    data['stale'] = time.time() - data.get('updated_at', 0) > 90
    data['endpoints'] = {'auto': 20080, **{e['node']['id']: 20200 + e['slot'] for e in entries()}}
    data['outside_nodes'] = [p.stem.removeprefix('node-') for p in sorted(CONF.glob('node-*.json'))]
    data['services'] = {name: subprocess.run(['systemctl', 'is-active', name], capture_output=True, text=True, timeout=10).stdout.strip()
                        for name in service_units()}
    print(json.dumps(data, indent=2))


def service_units():
    names = []
    if (CONF / 'iran.json').exists():
        names += ['naive-bridge-watch', 'naive-bridge-router']
        names += ['naive-bridge-naive-' + model.node(e['node'])['id'] for e in entries()]
    for path in sorted(CONF.glob('node-*.json')):
        ident = model.node(json.loads(path.read_text()))['id']
        names += ['naive-bridge-https-' + ident, 'naive-bridge-exit-' + ident]
    return names


def service(action):
    names = service_units()
    if not names:
        raise ValueError('No configured services / ابتدا نود را راه‌اندازی کنید.')
    run(['systemctl', action, *names])
    if action != 'stop':
        run(['systemctl', 'is-active', *names])
    print('Done / انجام شد. ' + ('بررسی سلامت ایران حدود ۲۰ ثانیه زمان می‌برد.' if action != 'stop' else 'اتصال‌های وابسته به تانل متوقف شدند.'))


def panel():
    print(json.dumps({'outbounds': [{'tag': 'naive-bridge-auto', 'protocol': 'socks', 'settings': {'servers': [{'address': '127.0.0.1', 'port': 20080}]}}] +
                     [{'tag': 'naive-bridge-' + e['node']['id'], 'protocol': 'socks', 'settings': {'servers': [{'address': '127.0.0.1', 'port': 20200 + e['slot']}]}} for e in entries()]}, indent=2))


def doctor():
    nodes = entries()
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        jobs = {pool.submit(check_one, kind, e): (e['node']['id'], kind) for e in nodes for kind in ('naive', 'xhttp', 'udp')}
        for job in concurrent.futures.as_completed(jobs):
            ident, kind = jobs[job]
            results.append({'node': ident, 'transport': kind, 'ok': job.result()})
    print(json.dumps({'checks': results, 'ok': bool(results) and all(r['ok'] for r in results)}, indent=2))
    if not results or not all(r['ok'] for r in results):
        raise SystemExit(1)


def menu():
    while True:
        print('''\nNaiveBridge 0.1.0
  1) راه‌اندازی نود خارج
  2) افزودن کد نود در ایران
  3) وضعیت سرویس‌ها و مسیرها
  4) تنظیمات خروجی پنل ایران
  5) حذف نود از ایران
  6) آزمون اتصال از ایران
  7) نمایش دوبارهٔ کد اتصال در خارج
  8) راه‌اندازی مجدد سرویس‌ها
  9) توقف سرویس‌ها
 10) شروع سرویس‌ها
  0) خروج''')
        choice = input('گزینه / Select: ').strip()
        if choice == '0':
            return
        try:
            if choice == '1':
                print('دامنه باید مستقیم به IP خارج اشاره کند؛ ابر کلودفلیر خاموش باشد.')
                ident = input('نام نود [fi1]: ').strip() or 'fi1'
                address = input('IP عمومی سرور خارج: ').strip()
                domain = input('دامنه یا زیردامنه: ').strip().lower()
                port = int(input('پورت آزاد HTTPS [443]: ') or 443)
                cert = input('مسیر fullchain یا Enter برای صدور خودکار [auto؛ نیازمند پورت آزاد 80]: ').strip() or 'auto'
                key = 'auto' if cert == 'auto' else input('مسیر کلید خصوصی گواهی: ').strip()
                outside(argparse.Namespace(id=ident, address=address, domain=domain, port=port, backend=20300, cert=cert, key=key))
            elif choice == '2':
                print('کد NB1 محرمانه است. هنگام چسباندن، روی صفحه نمایش داده نمی‌شود.')
                add(getpass.getpass('کد اتصال: '))
            elif choice == '3':
                status()
            elif choice == '4':
                panel()
            elif choice == '5':
                ident = input('نام نود برای حذف از ایران: ').strip()
                if not any(e['node']['id'] == ident for e in entries()):
                    raise ValueError('Unknown node / این نود وجود ندارد.')
                apply_iran([e for e in entries() if e['node']['id'] != ident])
            elif choice == '6':
                try:
                    doctor()
                except SystemExit:
                    pass
            elif choice == '7':
                export(input('نام نود [fi1]: ').strip() or 'fi1')
            elif choice in ('8', '9', '10'):
                service({'8': 'restart', '9': 'stop', '10': 'start'}[choice])
            else:
                print('گزینه نامعتبر است.')
        except Exception as exc:
            print(type(exc).__name__ + ': ' + str(exc))


def export(ident):
    if not __import__('re').fullmatch('[a-z][a-z0-9]{0,15}', ident):
        raise ValueError('Invalid node ID')
    print(model.encode(json.loads((CONF / ('node-' + ident + '.json')).read_text())))


def main():
    parser = argparse.ArgumentParser(description='NaiveBridge: HTTPS egress for a local Iran panel')
    parser.add_argument('--version', action='version', version='NaiveBridge 0.1.0')
    sub = parser.add_subparsers(dest='command')
    for name in ('menu', 'status', 'panel', 'watch', 'doctor', 'start', 'stop', 'restart'):
        sub.add_parser(name)
    p = sub.add_parser('add'); p.add_argument('--file', help='Secret pairing-code file; otherwise read hidden prompt')
    p.add_argument('--replace', action='store_true', help='Replace this node without changing its local port or priority')
    p = sub.add_parser('remove'); p.add_argument('id')
    p = sub.add_parser('export'); p.add_argument('id')
    p = sub.add_parser('outside')
    for name in ('id', 'address', 'domain'):
        p.add_argument('--' + name, required=True)
    p.add_argument('--cert', default='auto', help='Fullchain path, or auto for standalone certbot')
    p.add_argument('--key', default='auto', help='Private key path when using an existing certificate')
    p.add_argument('--port', type=int, default=443)
    p.add_argument('--backend', type=int, default=20300)
    p.add_argument('--listen-port', type=int, help='Local HTTPS listener behind an existing TCP proxy')
    p.add_argument('--proxy-protocol', action='store_true', help='Accept PROXY headers only from a loopback TCP proxy')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Run with sudo')
    for path in (CONF, STATE):
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(0o700)
    if args.command == 'watch':
        watch(); return
    # Serialize mutations and export, including interactive menu operations.
    import fcntl
    with open(STATE / 'manager.lock', 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.command in (None, 'menu'):
            menu()
        elif args.command == 'add':
            add(Path(args.file).read_text() if args.file else getpass.getpass('Secret pairing code: '), args.replace)
        elif args.command == 'outside':
            outside(args)
        elif args.command == 'remove':
            old = entries()
            if not any(e['node']['id'] == args.id for e in old):
                raise ValueError('Unknown node')
            apply_iran([e for e in old if e['node']['id'] != args.id])
        elif args.command == 'export':
            export(args.id)
        elif args.command in ('start', 'stop', 'restart'):
            service(args.command)
        elif args.command == 'status':
            status()
        elif args.command == 'panel':
            panel()
        elif args.command == 'doctor':
            doctor()


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, RuntimeError) as exc:
        print(type(exc).__name__ + ': ' + str(exc), file=sys.stderr)
        raise SystemExit(1)
    except (KeyboardInterrupt, EOFError):
        print('\nخروج / Exiting.', file=sys.stderr)
        raise SystemExit(130)
