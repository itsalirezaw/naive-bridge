import json

ROOT = '/opt/naive-bridge'
CONF = '/etc/naive-bridge'
PRIVATE = ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/4', '::/128', '::1/128', 'fc00::/7', 'fe80::/10', 'ff00::/8']


def inbound(tag, port):
    return {'tag': tag, 'listen': '127.0.0.1', 'port': port, 'protocol': 'socks', 'settings': {'auth': 'noauth', 'udp': True, 'ip': '127.0.0.1'}}


def xhttp(n):
    return {'tag': n['id'] + '-xhttp', 'protocol': 'vless', 'settings': {'vnext': [{'address': n['address'], 'port': n['port'], 'users': [{'id': n['uuid'], 'encryption': 'none'}]}]},
            'streamSettings': {'network': 'xhttp', 'security': 'tls', 'tlsSettings': {'serverName': n['domain'], 'alpn': ['h2'], 'fingerprint': 'chrome', 'allowInsecure': False}, 'xhttpSettings': {'path': n['path'], 'mode': 'auto'}}}


def iran(entries):
    c = {'log': {'loglevel': 'warning'}, 'stats': {}, 'api': {'tag': 'api', 'services': ['RoutingService']},
         'inbounds': [inbound('auto', 20080), {'tag': 'api-in', 'listen': '127.0.0.1', 'port': 20085, 'protocol': 'dokodemo-door', 'settings': {'address': '127.0.0.1'}}],
         'outbounds': [{'tag': 'blocked', 'protocol': 'blackhole'}],
         'routing': {'rules': [{'type': 'field', 'inboundTag': ['api-in'], 'outboundTag': 'api'}], 'balancers': []}}
    def balanced(tag):
        for net in ('tcp', 'udp'):
            b = tag + '-' + net
            c['routing']['balancers'].append({'tag': b, 'selector': ['blocked'], 'strategy': {'type': 'random'}})
            c['routing']['rules'].append({'type': 'field', 'inboundTag': [tag], 'network': net, 'balancerTag': b})
    balanced('auto')
    for e in entries:
        n, slot = e['node'], e['slot']
        tag = n['id']
        c['inbounds'] += [inbound(tag, 20200 + slot), inbound(tag + '-probe', 20101 + 2 * slot)]
        c['outbounds'] += [xhttp(n), {'tag': tag + '-naive', 'protocol': 'socks', 'settings': {'servers': [{'address': '127.0.0.1', 'port': 20100 + 2 * slot}]}}]
        c['routing']['rules'].append({'type': 'field', 'inboundTag': [tag + '-probe'], 'outboundTag': tag + '-xhttp'})
        balanced(tag)
    return c


def naive(n, slot):
    address = '[' + n['address'] + ']' if ':' in n['address'] else n['address']
    return {'listen': f'socks://127.0.0.1:{20100 + 2 * slot}',
            'proxy': f'https://{n["username"]}:{n["password"]}@{n["domain"]}:{n["port"]}',
            'host-resolver-rules': f'MAP {n["domain"]} {address}'}


def outside(n, backend):
    return {'log': {'loglevel': 'warning'}, 'inbounds': [{'listen': '127.0.0.1', 'port': backend, 'protocol': 'vless', 'settings': {'clients': [{'id': n['uuid']}], 'decryption': 'none'}, 'streamSettings': {'network': 'xhttp', 'security': 'none', 'xhttpSettings': {'path': n['path'], 'mode': 'auto'}}}],
            'outbounds': [{'tag': 'egress', 'protocol': 'freedom'}, {'tag': 'blocked', 'protocol': 'blackhole'}],
            'routing': {'domainStrategy': 'IPOnDemand', 'rules': [{'type': 'field', 'ip': PRIVATE, 'outboundTag': 'blocked'}]}}


def caddy(n, backend, cert, key, listen_port=None, proxy_protocol=False):
    # Catch-all first is essential: CONNECT authority contains the destination hostname.
    port = listen_port or n['port']
    wrappers = '''  listener_wrappers {
   proxy_protocol {
    timeout 2s
    allow 127.0.0.1/32 ::1/128
    fallback_policy reject
   }
   tls
  }
''' if proxy_protocol else ''
    return f'''{{
 admin off
 auto_https off
 order forward_proxy before reverse_proxy
 servers {{
  protocols h1 h2
{wrappers.rstrip()}
 }}
}}
:{port}, https://{n['domain']}:{port} {{
{' bind 127.0.0.1' if proxy_protocol else ''}
 tls {json.dumps(cert)} {json.dumps(key)}
 forward_proxy {{
  basic_auth {n['username']} {n['password']}
  hide_ip
  hide_via
  probe_resistance
 }}
 @tunnel path {n['path']} {n['path']}/*
 reverse_proxy @tunnel 127.0.0.1:{backend} {{
  flush_interval -1
  transport http {{
   versions h2c
  }}
 }}
 root * {CONF}/www-{n['id']}
 file_server
}}
'''


def unit(command, description):
    return f'''[Unit]
Description=NaiveBridge {description}
After=network-online.target
Wants=network-online.target
[Service]
ExecStart={command}
Restart=always
RestartSec=3
UMask=0077
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths={CONF} /var/lib/naive-bridge
Environment=XDG_DATA_HOME=/var/lib/naive-bridge
Environment=XDG_CONFIG_HOME=/var/lib/naive-bridge
[Install]
WantedBy=multi-user.target
'''
