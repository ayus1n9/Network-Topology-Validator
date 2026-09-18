"""Interactive REPL for building and validating topologies.

This is the PBQ-style simulator: the user builds a topology command by command,
and can validate it on demand. All validation reuses the same rules, score, and
report functions used by the file-based CLI.
"""

import json

from topology_validator.loader import load_topology
from topology_validator.parser import parse_devices, parse_connections
from topology_validator.graph import build_graph
from topology_validator.rules import validate_security_rules
from topology_validator.report import generate_report, calculate_score
from topology_validator.visualize import visualize_topology


_HELP_TEXT = """
Commands:
  add <id> <type> <zone>     Add a device
  remove <id>                Remove a device (and its connections)
  connect <from> <to>        Connect two devices
  disconnect <from> <to>     Remove a connection
  show                       Show current topology
  check                      Run the full security validator
  score                      Show score only
  render [file]              Save a PNG of the current topology
  save [file]                Save topology to JSON (default: topology.json)
  load <file>                Load topology from a .json or .txt file
  clear                      Remove all devices and connections
  help                       Show this help
  quit / exit                Exit

Example session:
  add internet internet external
  add fw1 firewall dmz
  add db1 database internal
  connect internet fw1
  connect fw1 db1
  check
  save my_topology.json
  quit
"""


def run_interactive(initial_file=None):
    """
    Start the interactive REPL.

    Args:
        initial_file (str, optional): A topology file to load at startup.
    """
    state = {"devices": {}, "connections": []}

    print("=" * 60)
    print("  Interactive Topology Builder (PBQ Simulator)")
    print("=" * 60)
    print("  Type 'help' for commands, 'quit' to exit.")
    print("=" * 60)

    if initial_file:
        try:
            _load_into_state(state, initial_file)
            print(f"\nLoaded {len(state['devices'])} devices and "
                  f"{len(state['connections'])} connections from {initial_file}.")
        except (FileNotFoundError, ValueError) as e:
            print(f"\nWarning: could not load {initial_file}: {e}")
            print("Starting with an empty topology.")

    while True:
        try:
            line = input("\n> ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nGoodbye.")
            return

        if not line:
            continue

        parts = line.split()
        cmd = parts[0].lower()
        args = parts[1:]

        try:
            if cmd in ("quit", "exit", "q"):
                print("Goodbye.")
                return
            elif cmd in ("help", "?"):
                print(_HELP_TEXT)
            elif cmd == "add":
                _cmd_add(state, args)
            elif cmd in ("remove", "rm"):
                _cmd_remove(state, args)
            elif cmd in ("connect", "c"):
                _cmd_connect(state, args)
            elif cmd in ("disconnect", "d"):
                _cmd_disconnect(state, args)
            elif cmd in ("show", "s"):
                _cmd_show(state)
            elif cmd == "check":
                _cmd_check(state)
            elif cmd == "score":
                _cmd_score(state)
            elif cmd == "render":
                _cmd_render(state, args)
            elif cmd == "save":
                _cmd_save(state, args)
            elif cmd == "load":
                _cmd_load(state, args)
            elif cmd == "clear":
                state["devices"].clear()
                state["connections"].clear()
                print("Cleared all devices and connections.")
            else:
                print(f"Unknown command: '{cmd}'. Type 'help' for a list.")
        except (ValueError, FileNotFoundError, OSError) as e:
            print(f"Error: {e}")


# ---------- Command implementations ----------

def _cmd_add(state, args):
    if len(args) != 3:
        raise ValueError("Usage: add <id> <type> <zone>")
    dev_id, dev_type, zone = args
    if dev_id in state["devices"]:
        raise ValueError(f"Device '{dev_id}' already exists.")
    state["devices"][dev_id] = {"id": dev_id, "type": dev_type, "zone": zone}
    print(f"Added {dev_id} ({dev_type}, {zone})")


def _cmd_remove(state, args):
    if len(args) != 1:
        raise ValueError("Usage: remove <id>")
    dev_id = args[0]
    if dev_id not in state["devices"]:
        raise ValueError(f"Unknown device: '{dev_id}'")
    del state["devices"][dev_id]
    before = len(state["connections"])
    state["connections"] = [
        (s, d) for s, d in state["connections"]
        if s != dev_id and d != dev_id
    ]
    removed = before - len(state["connections"])
    print(f"Removed {dev_id} (and {removed} connection(s)).")


def _cmd_connect(state, args):
    if len(args) != 2:
        raise ValueError("Usage: connect <from> <to>")
    src, dst = args
    if src not in state["devices"]:
        raise ValueError(f"Unknown device: '{src}'")
    if dst not in state["devices"]:
        raise ValueError(f"Unknown device: '{dst}'")
    if src == dst:
        raise ValueError("Cannot connect a device to itself.")

    pair = tuple(sorted((src, dst)))
    for s, d in state["connections"]:
        if tuple(sorted((s, d))) == pair:
            print(f"Already connected: {src} <-> {dst}")
            return

    state["connections"].append((src, dst))
    print(f"Connected {src} <-> {dst}")


def _cmd_disconnect(state, args):
    if len(args) != 2:
        raise ValueError("Usage: disconnect <from> <to>")
    src, dst = args
    pair = tuple(sorted((src, dst)))
    before = len(state["connections"])
    state["connections"] = [
        (s, d) for s, d in state["connections"]
        if tuple(sorted((s, d))) != pair
    ]
    if len(state["connections"]) == before:
        print(f"No connection between {src} and {dst}.")
    else:
        print(f"Disconnected {src} <-> {dst}")


def _cmd_show(state):
    if not state["devices"]:
        print("(empty — add devices with 'add <id> <type> <zone>')")
        return

    print("\nDevices:")
    for dev_id, dev in state["devices"].items():
        print(f"  {dev_id:<20} {dev['type']:<15} {dev['zone']}")

    print("\nConnections:")
    if not state["connections"]:
        print("  (none)")
    else:
        for s, d in state["connections"]:
            print(f"  {s} -- {d}")


def _cmd_check(state):
    if not state["devices"]:
        print("No devices to check. Add some with 'add <id> <type> <zone>'.")
        return

    devices = state["devices"]
    connections = state["connections"]
    graph = build_graph(devices, connections)
    findings = validate_security_rules(devices, graph)

    print(f"\nChecking {len(devices)} devices, {len(connections)} connections...")
    generate_report(findings)


def _cmd_score(state):
    if not state["devices"]:
        print("No devices to score.")
        return

    devices = state["devices"]
    connections = state["connections"]
    graph = build_graph(devices, connections)
    findings = validate_security_rules(devices, graph)
    score = calculate_score(findings)

    print(f"Score: {score['score']} / 100   Grade: {score['grade']}")


def _cmd_render(state, args):
    if not state["devices"]:
        print("Nothing to render.")
        return
    output_path = args[0] if args else "topology.png"

    devices = state["devices"]
    connections = state["connections"]
    graph = build_graph(devices, connections)
    findings = validate_security_rules(devices, graph)

    visualize_topology(devices, graph, findings, output_path)
    print(f"Rendered to {output_path}")


def _cmd_save(state, args):
    output_path = args[0] if args else "topology.json"

    data = {
        "devices": list(state["devices"].values()),
        "connections": [{"from": s, "to": d} for s, d in state["connections"]],
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    print(f"Saved {len(state['devices'])} devices, "
          f"{len(state['connections'])} connections to {output_path}")


def _cmd_load(state, args):
    if len(args) != 1:
        raise ValueError("Usage: load <file>")
    path = args[0]
    _load_into_state(state, path)
    print(f"Loaded {len(state['devices'])} devices, "
          f"{len(state['connections'])} connections from {path}")


def _load_into_state(state, path):
    """Load a topology file into the given state dict in place."""
    topo = load_topology(path)
    devices = parse_devices(topo["devices"])
    connections = parse_connections(topo["connections"], devices)
    state["devices"] = devices
    state["connections"] = connections