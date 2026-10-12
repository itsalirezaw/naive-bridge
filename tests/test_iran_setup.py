import contextlib
import copy
import io
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

from naivebridge import manager, model, ports, render, setup
from test_core import NODE


class IranSetupTests(unittest.TestCase):
    def allocated(self):
        def available(port, udp=False):
            if port < 20400:
                raise ValueError('occupied')
        with patch.object(setup, 'free_port', side_effect=available):
            return ports.plan(None, [{'node': NODE, 'slot': 0}])

    def test_busy_default_ports_select_unique_alternatives_everywhere(self):
        state = self.allocated()
        entry = state['nodes'][0]
        values = [*state['ports'].values(), *entry['ports'].values()]
        self.assertEqual(len(set(values)), 5)
        self.assertTrue(all(p >= 20400 for p in values))
        cfg = render.iran(state['nodes'], state['ports'])
        listeners = {i['tag']: i['port'] for i in cfg['inbounds']}
        self.assertEqual(listeners, {'auto': state['ports']['auto'], 'api-in': state['ports']['api'],
                                     'fi1': entry['ports']['panel'], 'fi1-probe': entry['ports']['xhttp']})
        naive = render.naive(NODE, 0, entry['ports']['naive'])
        self.assertTrue(naive['listen'].endswith(':' + str(entry['ports']['naive'])))
        outbound = next(o for o in cfg['outbounds'] if o['tag'] == 'fi1-naive')
        self.assertEqual(outbound['settings']['servers'][0]['port'], entry['ports']['naive'])
        # Outside connection parameters remain the pairing-code values.
        remote = next(o for o in cfg['outbounds'] if o['tag'] == 'fi1-xhttp')
        self.assertEqual(remote['settings']['vnext'][0]['port'], NODE['port'])

    def test_legacy_ports_survive_an_upgrade_even_when_already_listening(self):
        old = {'version': 1, 'nodes': [{'node': NODE, 'slot': 3}]}
        with patch.object(setup, 'free_port', side_effect=AssertionError('existing ports must stay')):
            state = ports.plan(old, old['nodes'])
        self.assertEqual(state['ports'], {'auto': 20080, 'api': 20085})
        self.assertEqual(state['nodes'][0]['ports'], {'naive': 20106, 'xhttp': 20107, 'panel': 20203})
        self.assertNotIn('ports', old)

    def test_add_remove_and_replace_preserve_saved_panel_ports(self):
        original = self.allocated()
        saved = copy.deepcopy(original)
        second = {'node': {**NODE, 'id': 'de1'}, 'slot': 1}
        with patch.object(setup, 'free_port'):
            added = ports.plan(original, [*original['nodes'], second])
            removed = ports.plan(added, added['nodes'][1:])
            replacement = copy.deepcopy(removed['nodes'])
            replacement[0]['node']['port'] = 10443
            replaced = ports.plan(removed, replacement)
        self.assertEqual(original, saved)
        self.assertEqual(added['nodes'][0], original['nodes'][0])
        self.assertEqual(replaced['ports'], original['ports'])
        self.assertEqual(replaced['nodes'][0]['ports'], added['nodes'][1]['ports'])

    def test_udp_occupied_port_is_not_selected_for_a_socks_listener(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            sock.bind(('0.0.0.0', 0))
            port = sock.getsockname()[1]
            with self.assertRaisesRegex(ValueError, 'unavailable'):
                setup.free_port(port, udp=True)

    def test_bad_saved_ports_and_duplicate_slots_are_rejected(self):
        for value in (True, 0, 65536, '20080'):
            with self.assertRaises(ValueError):
                ports.shared({'ports': {'auto': value, 'api': 20085}})
        with self.assertRaisesRegex(ValueError, 'Duplicate saved local ports'):
            ports.plan({'version': 1, 'nodes': [], 'ports': {'auto': 20080, 'api': 20080}}, [])
        with patch.object(setup, 'free_port'), self.assertRaisesRegex(ValueError, 'Duplicate node ID or slot'):
            ports.plan(None, [{'node': NODE, 'slot': 0}, {'node': {**NODE, 'id': 'de1'}, 'slot': 0}])

    def test_no_available_port_fails_before_state_is_changed(self):
        entries = [{'node': NODE, 'slot': 0}]
        with patch.object(setup, 'free_port', side_effect=ValueError('occupied')), patch.object(ports, 'FALLBACK', range(20400, 20402)):
            with self.assertRaisesRegex(ValueError, 'No free local Iran port'):
                ports.plan(None, entries)
        self.assertNotIn('ports', entries[0])

    def test_panel_and_probes_use_the_saved_ports(self):
        state = self.allocated()
        with patch.object(manager, 'iran_state', return_value=state), contextlib.redirect_stdout(io.StringIO()) as output:
            manager.panel()
        outbounds = json.loads(output.getvalue())['outbounds']
        self.assertEqual(outbounds[0]['settings']['servers'][0]['port'], state['ports']['auto'])
        self.assertEqual(outbounds[1]['settings']['servers'][0]['port'], state['nodes'][0]['ports']['panel'])
        with patch.object(manager.probe, 'tcp') as tcp, patch.object(manager.probe, 'udp') as udp:
            for kind in ('naive', 'xhttp', 'udp'):
                self.assertTrue(manager.check_one(kind, state['nodes'][0]))
        self.assertEqual([c.args[0] for c in tcp.call_args_list], [state['nodes'][0]['ports'][k] for k in ('naive', 'xhttp')])
        self.assertEqual(udp.call_args.args[0], state['nodes'][0]['ports']['xhttp'])

    def test_watch_uses_saved_api_port(self):
        state = self.allocated()
        with patch.object(manager, 'iran_state', return_value=state), patch.object(manager, 'check_one', return_value=True), patch.object(manager, 'run', return_value='') as run, patch.object(manager, 'save'), patch.dict(manager.os.environ, {'NOTIFY_SOCKET': ''}), patch.object(manager.time, 'sleep', side_effect=InterruptedError):
            with self.assertRaises(InterruptedError):
                manager.watch()
        self.assertTrue(run.call_count)
        self.assertTrue(all(f'--server=127.0.0.1:{state["ports"]["api"]}' in call.args[0] for call in run.call_args_list))

    def test_failed_service_start_restores_saved_ports_and_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            conf, units = root / 'conf', root / 'units'
            conf.mkdir()
            units.mkdir()
            previous = self.allocated()
            (conf / 'iran.json').write_text(json.dumps(previous))
            prior_router = json.dumps(render.iran(previous['nodes'], previous['ports']))
            (conf / 'router.json').write_text(prior_router)
            failed = False

            def command(args):
                nonlocal failed
                if args[:3] == ['systemctl', 'restart', 'naive-bridge-router'] and not failed:
                    failed = True
                    raise RuntimeError('start failed')
                return ''

            def write(path, value, mode=0o600):
                Path(path).write_text(value)

            with patch.object(manager, 'CONF', conf), patch.object(manager, 'UNITS', units), patch.object(manager, 'write', side_effect=write), patch.object(manager, 'check_xray'), patch.object(manager, 'run', side_effect=command), patch.object(setup, 'free_port'), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(RuntimeError, 'start failed'):
                    manager.apply_iran([*previous['nodes'], {'node': {**NODE, 'id': 'de1'}, 'slot': 1}])
            self.assertEqual(json.loads((conf / 'iran.json').read_text()), previous)
            self.assertEqual((conf / 'router.json').read_text(), prior_router)
            restored = json.loads((conf / 'naive-fi1.json').read_text())
            self.assertTrue(restored['listen'].endswith(':' + str(previous['nodes'][0]['ports']['naive'])))

    def test_visible_input_retries_invalid_code_and_accepts_pasted_whitespace(self):
        code = model.encode(NODE)
        pasted = '  ' + code[:20] + ' \t' + code[20:] + '  '
        with patch('builtins.input', side_effect=['invalid', pasted]), contextlib.redirect_stdout(io.StringIO()) as output:
            result = manager.read_pairing()
        self.assertEqual(model.decode(result), NODE)
        self.assertIn('IS VISIBLE', output.getvalue())
        self.assertIn('Invalid input:', output.getvalue())
        self.assertEqual(model.decode(code[:20] + '\n' + code[20:]), NODE)

    def test_outside_pairing_display_contains_one_exact_copyable_code(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            manager.show_pairing(NODE)
        lines = output.getvalue().splitlines()
        self.assertEqual([line for line in lines if line.startswith('NB1.')], [model.encode(NODE)])
        self.assertIn('choose 2) Add a node on Iran', output.getvalue())

    def test_menu_waits_after_success_and_add_reports_next_step(self):
        state = self.allocated()
        prompts = []
        answers = iter(['2', model.encode(NODE), '', '0'])

        def answer(prompt):
            prompts.append(prompt)
            return next(answers)

        with patch('builtins.input', side_effect=answer), patch.object(manager, 'entries', return_value=[]), patch.object(manager, 'apply_iran', return_value=state), contextlib.redirect_stdout(io.StringIO()) as output:
            manager.menu()
        self.assertIn('Pairing code accepted.', output.getvalue())
        self.assertIn('SUCCESS - IRAN NODE SETUP COMPLETE', output.getvalue())
        self.assertIn('4) Iran panel outbound settings', output.getvalue())
        self.assertEqual(prompts[-2], '\nPress Enter to return to the menu...')
