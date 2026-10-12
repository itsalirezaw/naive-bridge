"""Persist local Iran ports while preserving the layout of older installations."""
import copy

from . import model, setup

FALLBACK = range(20400, 30000)


def checked(value, keys):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ValueError('Invalid saved local port settings.')
    if any(type(port) is not int or not 1024 <= port <= 65535 for port in value.values()):
        raise ValueError('Saved local ports must be numbers from 1024 to 65535.')
    return dict(value)


def shared(state=None):
    return checked((state or {}).get('ports', {'auto': 20080, 'api': 20085}), ('auto', 'api'))


def node(entry):
    slot = entry['slot']
    if type(slot) is not int or not 0 <= slot < 32:
        raise ValueError('Invalid node slot')
    return checked(entry.get('ports', {'naive': 20100 + 2 * slot, 'xhttp': 20101 + 2 * slot,
                                       'panel': 20200 + slot}), ('naive', 'xhttp', 'panel'))


def plan(previous, entries):
    """Select ports only for new listeners. Never move an existing panel endpoint."""
    entries = copy.deepcopy(entries)
    old = (previous or {}).get('nodes', [])
    used = set()

    def reserve(settings):
        for port in settings.values():
            if port in used:
                raise ValueError('Duplicate saved local ports. Restore the Iran configuration backup.')
            used.add(port)

    def select(preferred, udp):
        for port in (preferred, *FALLBACK):
            if port in used:
                continue
            try:
                setup.free_port(port, udp=udp)
            except ValueError:
                continue
            used.add(port)
            return port
        raise ValueError('No free local Iran port in 20400-29999. Check local listeners and retry.')

    # Also reserve removed nodes until the old services have stopped.
    global_ports = shared(previous) if previous is not None else None
    if global_ports:
        reserve(global_ports)
    by_id = {}
    for entry in old:
        ident = model.node(entry['node'])['id']
        if ident in by_id:
            raise ValueError('Duplicate saved node ID')
        by_id[ident] = node(entry)
        reserve(by_id[ident])
    if global_ports is None:
        global_ports = {'auto': select(20080, True), 'api': select(20085, False)}
    ids, slots = set(), set()
    for entry in entries:
        ident = model.node(entry['node'])['id']
        preferred = node(entry)
        if ident in ids or entry['slot'] in slots:
            raise ValueError('Duplicate node ID or slot')
        ids.add(ident)
        slots.add(entry['slot'])
        entry['ports'] = by_id[ident] if ident in by_id else {
            key: select(port, key != 'naive') for key, port in preferred.items()}
    return {'version': 1, 'ports': global_ports, 'nodes': entries}
