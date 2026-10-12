import argparse
import concurrent.futures
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shlex
import socket
import subprocess
import sys
import time
import uuid

from . import __version__, certificates, model, ports, probe, render, setup
from .setup import free_port

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


def iran_state():
    p = CONF / 'iran.json'
    return json.loads(p.read_text()) if p.exists() else None


def entries():
    return (iran_state() or {}).get('nodes', [])


def unit(name, command):
    write(UNITS / (name + '.service'), render.unit(command, name), 0o644)


def check_xray(path):
    run([str(ROOT / 'bin/xray'), 'run', '-test', '-config', str(path)])


def apply_iran(new):
    previous = iran_state()
    old = (previous or {}).get('nodes', [])
    planned = ports.plan(previous, new)
    new = planned['nodes']
    local = planned['ports']
    print(f'Local panel SOCKS: 127.0.0.1:{local["auto"]} (selected automatically; saved for future use).')
    print('Iran ports are local only. They do not need to match the outside HTTPS port or be opened publicly.')
    candidate = CONF / 'iran-candidate.json'
    save(candidate, render.iran(new, local))
    check_xray(candidate)
    for e in new:
        n = e['node']
        save(CONF / ('naive-' + n['id'] + '.json'), render.naive(n, e['slot'], ports.node(e)['naive']))
        unit('naive-bridge-naive-' + n['id'], f'{ROOT}/bin/naive {CONF}/naive-{n["id"]}.json')
    unit('naive-bridge-router', f'{ROOT}/bin/xray run -config {CONF}/router.json')
    unit('naive-bridge-watch', f'/usr/bin/python3 -m naivebridge.manager watch')
    # Python package is installed into ROOT; the service launches through an absolute wrapper.
    watch_path = UNITS / 'naive-bridge-watch.service'
    write(watch_path, watch_path.read_text().replace('/usr/bin/python3 -m naivebridge.manager watch', '/usr/local/bin/naive-bridge watch').replace('Restart=always', 'WatchdogSec=180\nNotifyAccess=main\nRestart=always'), 0o644)
    prior = (CONF / 'router.json').read_text() if (CONF / 'router.json').exists() else None
    try:
        save(CONF / 'iran.json', planned)
        os.replace(candidate, CONF / 'router.json')
        run(['systemctl', 'daemon-reload'])
        for e in new:
            run(['systemctl', 'enable', '--now', 'naive-bridge-naive-' + e['node']['id']])
            if any(x['node']['id'] == e['node']['id'] and x != e for x in old):
                run(['systemctl', 'restart', 'naive-bridge-naive-' + e['node']['id']])
        run(['systemctl', 'enable', 'naive-bridge-router', 'naive-bridge-watch'])
        run(['systemctl', 'restart', 'naive-bridge-router', 'naive-bridge-watch'])
        run(['systemctl', 'is-active', 'naive-bridge-router', 'naive-bridge-watch',
             *['naive-bridge-naive-' + e['node']['id'] for e in new]])
    except Exception:
        if previous is not None:
            save(CONF / 'iran.json', previous)
        for e in old:
            save(CONF / ('naive-' + e['node']['id'] + '.json'), render.naive(e['node'], e['slot'], ports.node(e)['naive']))
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
    return planned


def success(title):
    print('\n' + '=' * 64)
    print('SUCCESS - ' + title)
    print('=' * 64)


def show_pairing(n):
    print(f'Node: {n["id"]} | Outside HTTPS port: {n["port"]}')
    print('NEXT: Open NaiveBridge on IRAN and choose 2) Add a node on Iran.')
    print('Copy the ENTIRE line below, starting with NB1., and paste it there.')
    print('Keep this code private; it contains the node credentials.')
    print('\n--------------------- BEGIN PAIRING CODE ---------------------\n')
    print(model.encode(n))
    print('\n---------------------- END PAIRING CODE ----------------------\n')
    print('Copy only the NB1. line, without the BEGIN/END labels.')


def read_pairing():
    print('Paste the full NB1. pairing code from the OUTSIDE server, then press Enter.')
    print('Pasted text IS VISIBLE. Keep it out of public recordings.')

    def validate(value):
        return model.encode(model.decode(value))

    return setup.prompt('Pairing code (NB1...)', validate=validate)


def add(code, replace=False):
    n = model.decode(code)
    print(f'Pairing code accepted. Node: {n["id"]}; outside: {n["domain"]}:{n["port"]}.')
    new = entries()
    if any(e['node']['id'] == n['id'] for e in new):
        if not replace:
            raise ValueError('Node ID already exists; use add --replace to update it')
        for e in new:
            if e['node']['id'] == n['id']:
                e['node'] = n
    else:
        slot = next((i for i in range(32) if i not in {e['slot'] for e in new}), None)
        if slot is None:
            raise ValueError('Maximum 32 nodes')
        new.append({'node': n, 'slot': slot})
    state = apply_iran(new)
    e = next(e for e in state['nodes'] if e['node']['id'] == n['id'])
    success('IRAN NODE SETUP COMPLETE: ' + n['id'])
    print('The node is saved and its local services are running on this server.')
    print(f'Panel automatic outbound: 127.0.0.1:{state["ports"]["auto"]}')
    print(f'Panel outbound for {n["id"]}: 127.0.0.1:{ports.node(e)["panel"]}')
    print('NEXT: Wait about 20 seconds, then choose 6) Test connections from Iran.')
    print('Then choose 4) Iran panel outbound settings and copy the settings into your panel.')
    print('Panel routing is a separate step. Setup success does not yet confirm end-to-end connectivity.')


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
    if args.backend is None:
        args.backend = setup.backend_port(exclude=(listen_port, args.port))
        print(f'Internal backend port: {args.backend} (selected automatically; local only).')
    for p in (listen_port, args.backend):
        if not 1 <= p <= 65535:
            raise ValueError('Invalid local port')
        free_port(p)
    if listen_port == args.backend:
        raise ValueError('Public and backend ports must differ')
    if args.cert == 'auto':
        args.cert, args.key = certificates.obtain(n['domain'], n['address'])
    # Preserve certbot's live symlinks: resolving to archive/fullchain1.pem would freeze renewal.
    cert = setup.certificate_fullchain(n['domain'], args.cert)
    key = setup.certificate_pair(cert, args.key)
    certificates.prepare_renewal(cert)
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
    certificates.configure_renewal(n['id'], cert, caddy, ROOT, write)
    success('OUTSIDE NODE SETUP COMPLETE: ' + n['id'])
    print('Setup on this OUTSIDE server is finished. Continue on the IRAN server.')
    print(f'Outside TCP {n["port"]} must be reachable from Iran through the host/provider firewall.')
    show_pairing(n)


def check_one(kind, e):
    n, local = e['node'], ports.node(e)
    try:
        if kind == 'udp':
            for resolver in ('1.1.1.1', '9.9.9.9'):
                try:
                    probe.udp(local['xhttp'], resolver)
                    return True
                except (OSError, ValueError):
                    pass
            return False
        probe.tcp(local[kind], n)
        return True
    except (OSError, ValueError, http.client.HTTPException):
        return False


def watch():
    nodes = entries()
    api = ports.shared(iran_state())['api']
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
                run([str(ROOT / 'bin/xray'), 'api', 'bo', f'--server=127.0.0.1:{api}', '-b', balancer, target])
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
    state = iran_state()
    data['endpoints'] = ({'auto': ports.shared(state)['auto'], **{e['node']['id']: ports.node(e)['panel'] for e in state['nodes']}}
                         if state is not None else {})
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
        raise ValueError('No configured services. Set up a node first.')
    run(['systemctl', action, *names])
    if action != 'stop':
        run(['systemctl', 'is-active', *names])
    print('Done. ' + ('Initial health checks on Iran take about 20 seconds.' if action != 'stop' else 'Tunnel connections have been stopped.'))


def panel():
    state = iran_state()
    if state is None:
        raise ValueError('No Iran configuration. First choose 2) Add a node on Iran.')
    print(json.dumps({'outbounds': [{'tag': 'naive-bridge-auto', 'protocol': 'socks', 'settings': {'servers': [{'address': '127.0.0.1', 'port': ports.shared(state)['auto']}]}}] +
                     [{'tag': 'naive-bridge-' + e['node']['id'], 'protocol': 'socks', 'settings': {'servers': [{'address': '127.0.0.1', 'port': ports.node(e)['panel']}]}} for e in state['nodes']]}, indent=2))


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


def outside_menu():
    print('The domain must point directly to the outside IP. Disable the Cloudflare proxy (DNS only).')

    def ident(value):
        model.node_id(value)
        if (CONF / ('node-' + value + '.json')).exists():
            raise ValueError('Node already exists. Choose another ID, or use menu option 7 to retrieve its pairing code.')
        return value

    name = setup.prompt('Node name', 'fi1', ident)
    print('Checking the public IP address. Verify the suggestion before accepting it.')
    address = setup.prompt('Outside server public IP', setup.public_ip(), lambda value: str(ipaddress.ip_address(value)))
    domain = setup.prompt('Domain or subdomain', validate=lambda value: model.public_domain(value.lower()))

    def port(value):
        try:
            number = int(value)
        except ValueError as exc:
            raise ValueError('Enter a port number from 1 to 65535.') from exc
        free_port(number)
        return number

    suggestion = setup.available_port(setup.HTTPS_PORTS)
    public = setup.prompt('Available HTTPS port', str(suggestion) if suggestion else None, port)
    print(f'Allow TCP {public} in the host/provider firewall. Availability was checked locally only.')
    backend = setup.backend_port(exclude=(public,))
    print(f'Internal backend port: {backend} (selected automatically; local only).')
    cert, key = setup.prompt_certificates(domain)
    outside(argparse.Namespace(id=name, address=address, domain=domain, port=public, backend=backend, cert=cert, key=key))


def refresh_certificates():
    for path in sorted(CONF.glob('node-*.json')):
        ident = model.node(json.loads(path.read_text()))['id']
        caddy = CONF / ('Caddyfile-' + ident)
        for line in caddy.read_text().splitlines():
            fields = shlex.split(line)
            if len(fields) == 3 and fields[0] == 'tls':
                cert = fields[1]
                certificates.prepare_renewal(cert)
                certificates.configure_renewal(ident, cert, caddy, ROOT, write)
                break


def menu():
    while True:
        print(f'''\nNaiveBridge {__version__}
  1) Set up an outside node
  2) Add a node on Iran
  3) Service and route status
  4) Iran panel outbound settings
  5) Remove a node from Iran
  6) Test connections from Iran
  7) Show outside node pairing code
  8) Restart services
  9) Stop services
 10) Start services
  0) Exit

  ------------------------------------------------------
  By itsalirezaw
  GitHub   https://github.com/itsalirezaw
  YouTube  https://www.youtube.com/@ialirezaw
  ------------------------------------------------------''')
        choice = input('Select: ').strip()
        if choice == '0':
            return
        try:
            if choice == '1':
                outside_menu()
            elif choice == '2':
                add(read_pairing())
            elif choice == '3':
                status()
            elif choice == '4':
                panel()
            elif choice == '5':
                ident = input('Node name to remove from Iran: ').strip()
                if not any(e['node']['id'] == ident for e in entries()):
                    raise ValueError('Unknown node.')
                apply_iran([e for e in entries() if e['node']['id'] != ident])
                success('NODE REMOVED FROM IRAN: ' + ident)
            elif choice == '6':
                try:
                    doctor()
                except SystemExit:
                    pass
            elif choice == '7':
                names = [p.stem.removeprefix('node-') for p in sorted(CONF.glob('node-*.json'))]
                if not names:
                    raise ValueError('No outside node configured. First choose 1) Set up an outside node.')
                print('Outside nodes: ' + ', '.join(names))
                export(setup.prompt('Node name', names[0]), pretty=True)
            elif choice in ('8', '9', '10'):
                service({'8': 'restart', '9': 'stop', '10': 'start'}[choice])
            else:
                print('Invalid selection.')
            input('\nPress Enter to return to the menu...')
        except Exception as exc:
            print(type(exc).__name__ + ': ' + str(exc))


def export(ident, pretty=False):
    model.node_id(ident)
    n = model.node(json.loads((CONF / ('node-' + ident + '.json')).read_text()))
    show_pairing(n) if pretty else print(model.encode(n))


def main():
    parser = argparse.ArgumentParser(description='NaiveBridge: HTTPS egress for a local Iran panel')
    parser.add_argument('--version', action='version', version='NaiveBridge ' + __version__)
    sub = parser.add_subparsers(dest='command')
    for name in ('menu', 'status', 'panel', 'watch', 'doctor', 'start', 'stop', 'restart', 'refresh-certificates'):
        sub.add_parser(name)
    p = sub.add_parser('add'); p.add_argument('--file', help='Secret pairing-code file; otherwise read visible prompt')
    p.add_argument('--replace', action='store_true', help='Replace this node without changing its local port or priority')
    p = sub.add_parser('remove'); p.add_argument('id')
    p = sub.add_parser('export'); p.add_argument('id')
    p = sub.add_parser('outside')
    for name in ('id', 'address', 'domain'):
        p.add_argument('--' + name, required=True)
    p.add_argument('--cert', default='auto', help='Fullchain path, or auto for Nginx/standalone Certbot')
    p.add_argument('--key', default='auto', help='Private key path when using an existing certificate')
    p.add_argument('--port', type=int, default=443)
    p.add_argument('--backend', type=int, help='Internal port; default: first free port in 20300-20399')
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
    if args.command == 'refresh-certificates':
        # Upgrade only atomic renewal hooks/timers; do not restart active nodes.
        refresh_certificates(); return
    # Serialize mutations and export, including interactive menu operations.
    import fcntl
    with open(STATE / 'manager.lock', 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.command in (None, 'menu'):
            menu()
        elif args.command == 'add':
            add(Path(args.file).read_text() if args.file else read_pairing(), args.replace)
        elif args.command == 'outside':
            outside(args)
        elif args.command == 'remove':
            old = entries()
            if not any(e['node']['id'] == args.id for e in old):
                raise ValueError('Unknown node')
            apply_iran([e for e in old if e['node']['id'] != args.id])
            success('NODE REMOVED FROM IRAN: ' + args.id)
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
        print('\nExiting.', file=sys.stderr)
        raise SystemExit(130)
