import copy
import unittest
from naivebridge import model, render

NODE = {'version': 1, 'id': 'fi1', 'address': '203.0.113.5', 'domain': 'node.example.com', 'port': 443, 'username': 'user', 'password': 'a' * 32, 'uuid': 'dda82802-b103-4153-9f07-47c7be27ae6e', 'path': '/api/' + 'a' * 24, 'health_path': '/assets/' + 'b' * 24, 'health_sha256': 'a' * 64}


class Tests(unittest.TestCase):
    def test_secret_roundtrip(self):
        self.assertEqual(model.decode(model.encode(NODE)), NODE)

    def test_reject_config_injection(self):
        for key, bad in [('id', '../escape'), ('domain', 'example.com\nfoo'), ('path', '/api/x { }'), ('password', 'foo\nbar'), ('port', True), ('address', '$(whoami)')]:
            n = {**NODE, key: bad}
            with self.assertRaises((ValueError, TypeError)):
                model.node(n)

    def test_two_nodes_and_fail_closed(self):
        nodes = [{'node': NODE, 'slot': 0}, {'node': {**NODE, 'id': 'de1'}, 'slot': 3}]
        self.assertEqual(model.choose(nodes, {})['auto-tcp'], 'blocked')
        routes = model.choose(nodes, {'fi1-naive': True, 'de1-xhttp': True, 'de1-udp': True})
        self.assertEqual(routes['auto-tcp'], 'fi1-naive')
        self.assertEqual(routes['auto-udp'], 'de1-xhttp')
        routes = model.choose(nodes, {'fi1-xhttp': True})
        self.assertEqual(routes['auto-tcp'], 'fi1-xhttp')
        self.assertEqual(routes['auto-udp'], 'blocked')

    def test_hysteresis(self):
        h = model.Health()
        self.assertFalse(h.record(True))
        self.assertTrue(h.record(True))
        self.assertTrue(h.record(False))
        self.assertFalse(h.record(False))

    def test_no_iran_direct_fallback_or_public_listener(self):
        cfg = render.iran([{'node': NODE, 'slot': 3}])
        self.assertNotIn('freedom', [o['protocol'] for o in cfg['outbounds']])
        self.assertTrue(all(i['listen'] == '127.0.0.1' for i in cfg['inbounds']))
        self.assertTrue(all(b['selector'] == ['blocked'] for b in cfg['routing']['balancers']))
        x = next(o for o in cfg['outbounds'] if o['protocol'] == 'vless')
        self.assertFalse(x['streamSettings']['tlsSettings']['allowInsecure'])


if __name__ == '__main__':
    unittest.main()
