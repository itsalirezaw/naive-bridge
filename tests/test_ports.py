import unittest
from naivebridge import model, render
from test_core import NODE


class Ports(unittest.TestCase):
    def test_reserved_ids_cannot_override_control_routes(self):
        for value in ('auto', 'api', 'blocked', 'fi1-probe'):
            with self.assertRaises(ValueError):
                model.node({**NODE, 'id': value})

    def test_restarting_router_defaults_to_blocked(self):
        cfg = render.iran([{'node': NODE, 'slot': 0}])
        self.assertEqual(cfg['outbounds'][0]['tag'], 'blocked')
        self.assertEqual(cfg['outbounds'][0]['protocol'], 'blackhole')
        self.assertEqual(cfg['routing']['rules'][0]['outboundTag'], 'api')
        self.assertTrue(all(b['selector'] == ['blocked'] for b in cfg['routing']['balancers']))

    def test_adding_node_does_not_reassign_existing_local_port(self):
        entries = [{'node': NODE, 'slot': 0}, {'node': {**NODE, 'id': 'de1'}, 'slot': 5}]
        before = {i['tag']: i['port'] for i in render.iran(entries)['inbounds']}
        after = {i['tag']: i['port'] for i in render.iran(entries[1:])['inbounds']}
        self.assertEqual(before['de1'], after['de1'])
        self.assertEqual(before['de1-probe'], after['de1-probe'])

    def test_catchall_and_proxy_header_trust_boundary(self):
        config = render.caddy(NODE, 20300, '/etc/tls/cert.pem', '/etc/tls/key.pem', 24444, True)
        self.assertIn(':24444, https://node.example.com:24444', config)
        self.assertIn('allow 127.0.0.1/32 ::1/128', config)
        self.assertIn('fallback_policy reject', config)
        self.assertNotIn('protocols h3', config)


if __name__ == '__main__':
    unittest.main()
