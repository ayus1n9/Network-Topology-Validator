import json
import argparse
import sys
EXTERNAL_ZONES = {"external"}
TRUSTED_ZONES = {"internal", "database"}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

def load_topology(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError(f"Topology file not found: {file_path}")
    except json.JSONDecodeError as e:
        raise ValueError(
            f"Invalid JSON in {file_path}: {e.msg} (line {e.lineno}, col {e.colno})"
        ) from e

    if not isinstance(data, dict):
        raise ValueError("Topology file must contain a JSON object at the top level.")

    if 'devices' not in data:
        raise ValueError("Topology must have a 'devices' key.")
    if 'connections' not in data:
        raise ValueError("Topology must have a 'connections' key.")

    if not isinstance(data['devices'], list):
        raise ValueError("'devices' must be a list.")
    if not isinstance(data['connections'], list):
        raise ValueError("'connections' must be a list.")

    return data

def parse_devices(devices_list):
    devices_dict = {}

    for index, device in enumerate(devices_list):
        if not isinstance(device, dict):
            raise ValueError(f"Device at index {index} is not a dictionary.")

        for field in ("id", "type", "zone"):
            if field not in device:
                raise ValueError(
                    f"Device at index {index} is missing required field '{field}': {device}"
                )
            if not isinstance(device[field], str) or not device[field].strip():
                raise ValueError(
                    f"Device at index {index} has an invalid '{field}' value: {device[field]!r}"
                )

        device_id = device["id"]
        if device_id in devices_dict:
            raise ValueError(f"Duplicate device id found: '{device_id}'")

        devices_dict[device_id] = device

    return devices_dict

def parse_connections(connections_list, devices_dict):
    """
    Validate connections and return them as a list of (from_id, to_id) tuples.

    Args:
        connections_list (list): List of dicts with 'from' and 'to' keys.
        devices_dict (dict): Mapping of device_id -> device_dict.

    Returns:
        list: List of tuples (from_id, to_id).

    Raises:
        ValueError: If a connection is malformed, references an unknown device,
                    or is a self-loop.
    """
    connections = []

    for index, conn in enumerate(connections_list):
        if not isinstance(conn, dict):
            raise ValueError(f"Connection at index {index} is not a dictionary.")

        for field in ("from", "to"):
            if field not in conn:
                raise ValueError(
                    f"Connection at index {index} is missing required field '{field}': {conn}"
                )
            if not isinstance(conn[field], str) or not conn[field].strip():
                raise ValueError(
                    f"Connection at index {index} has an invalid '{field}' value: {conn[field]!r}"
                )

        src = conn["from"]
        dst = conn["to"]

        if src not in devices_dict:
            raise ValueError(
                f"Connection at index {index} references unknown device: '{src}'"
            )
        if dst not in devices_dict:
            raise ValueError(
                f"Connection at index {index} references unknown device: '{dst}'"
            )

        if src == dst:
            raise ValueError(
                f"Connection at index {index} is a self-loop: '{src}' connects to itself."
            )

        connections.append((src, dst))

    return connections

def build_graph(devices_dict, connections):
    """
    Build an undirected adjacency list from devices and connections.

    Args:
        devices_dict (dict): Mapping of device_id -> device_dict.
        connections (list): List of (from_id, to_id) tuples.

    Returns:
        dict: Mapping of device_id -> set of neighbor device_ids.
              Every device appears as a key, even if it has no connections.
    """
    graph = {device_id: set() for device_id in devices_dict}

    for src, dst in connections:
        graph[src].add(dst)
        graph[dst].add(src)

    return graph

def rule_database_exposed(devices_dict, graph):
    """
    Flag databases that are directly connected to external or DMZ devices.

    A database should only be reachable via the internal zone, behind a firewall.

    Args:
        devices_dict (dict): Mapping of device_id -> device_dict.
        graph (dict): Adjacency list mapping device_id -> set of neighbors.

    Returns:
        list: List of finding dicts.
    """
    findings = []

    for device_id, device in devices_dict.items():
        if device["type"] != "database":
            continue

        for neighbor_id in graph.get(device_id, set()):
            neighbor = devices_dict[neighbor_id]

            if neighbor["type"] == "internet" or neighbor["zone"] == "external":
                findings.append({
                    "severity": "high",
                    "message": (
                        f"Database '{device_id}' is directly connected to "
                        f"Internet-facing device '{neighbor_id}'."
                    ),
                    "devices": [device_id, neighbor_id],
                })
            elif neighbor["zone"] == "dmz":
                findings.append({
                    "severity": "high",
                    "message": (
                        f"Database '{device_id}' is directly connected to "
                        f"DMZ device '{neighbor_id}' (no internal firewall in between)."
                    ),
                    "devices": [device_id, neighbor_id],
                })

    return findings

def rule_internet_to_internal(devices_dict, graph):
    """
    Flag direct links between external/internet devices and internal/database devices.

    Traffic between the internet and trusted zones must always pass through a firewall.

    Args:
        devices_dict (dict): Mapping of device_id -> device_dict.
        graph (dict): Adjacency list mapping device_id -> set of neighbors.

    Returns:
        list: List of finding dicts.
    """
    findings = []
    seen_pairs = set()

    for device_id, device in devices_dict.items():
        # We only care about external-facing devices as the starting point.
        is_external = (
            device["type"] == "internet" or device["zone"] in EXTERNAL_ZONES
        )
        if not is_external:
            continue

        for neighbor_id in graph.get(device_id, set()):
            neighbor = devices_dict[neighbor_id]

            if neighbor["zone"] not in TRUSTED_ZONES:
                continue

            # Avoid duplicate findings (a->b and b->a).
            pair = tuple(sorted((device_id, neighbor_id)))
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)

            findings.append({
                "severity": "high",
                "message": (
                    f"External device '{device_id}' is directly connected to "
                    f"internal-zone device '{neighbor_id}' "
                    f"(zone '{neighbor['zone']}') without an intervening firewall."
                ),
                "devices": [device_id, neighbor_id],
            })

    return findings

def rule_dmz_to_internal(devices_dict, graph):
    """
    Flag DMZ devices directly connected to internal/database devices
    without a firewall on either end.

    Args:
        devices_dict (dict): Mapping of device_id -> device_dict.
        graph (dict): Adjacency list mapping device_id -> set of neighbors.

    Returns:
        list: List of finding dicts.
    """
    findings = []
    seen_pairs = set()

    for device_id, device in devices_dict.items():
        if device["zone"] != "dmz":
            continue
        if device["type"] == "firewall":
            continue  # firewalls are the intended bridge

        for neighbor_id in graph.get(device_id, set()):
            neighbor = devices_dict[neighbor_id]

            if neighbor["zone"] not in TRUSTED_ZONES:
                continue
            if neighbor["type"] == "firewall":
                continue

            pair = tuple(sorted((device_id, neighbor_id)))
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)

            findings.append({
                "severity": "high",
                "message": (
                    f"DMZ device '{device_id}' is directly connected to "
                    f"internal-zone device '{neighbor_id}' "
                    f"(zone '{neighbor['zone']}') without an intervening firewall."
                ),
                "devices": [device_id, neighbor_id],
            })

    return findings

def rule_web_to_database(devices_dict, graph):
    """
    Flag web servers that are directly connected to databases.

    Best practice: web servers should talk to app servers, not databases.
    The app tier enforces business logic and least privilege.

    Args:
        devices_dict (dict): Mapping of device_id -> device_dict.
        graph (dict): Adjacency list mapping device_id -> set of neighbors.

    Returns:
        list: List of finding dicts.
    """
    findings = []
    seen_pairs = set()

    for device_id, device in devices_dict.items():
        if device["type"] != "web_server":
            continue

        for neighbor_id in graph.get(device_id, set()):
            neighbor = devices_dict[neighbor_id]

            if neighbor["type"] != "database":
                continue

            pair = tuple(sorted((device_id, neighbor_id)))
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)

            findings.append({
                "severity": "high",
                "message": (
                    f"Web server '{device_id}' is directly connected to "
                    f"database '{neighbor_id}' — missing app-tier separation."
                ),
                "devices": [device_id, neighbor_id],
            })

    return findings

def validate_security_rules(devices_dict, graph):
    """
    Run every security rule against the topology and return deduplicated,
    severity-sorted findings.

    Args:
        devices_dict (dict): Mapping of device_id -> device_dict.
        graph (dict): Adjacency list mapping device_id -> set of neighbors.

    Returns:
        list: Sorted, deduplicated list of finding dicts.
    """
    all_findings = []
    all_findings.extend(rule_database_exposed(devices_dict, graph))
    all_findings.extend(rule_internet_to_internal(devices_dict, graph))
    all_findings.extend(rule_dmz_to_internal(devices_dict, graph))
    all_findings.extend(rule_web_to_database(devices_dict, graph))

    seen = set()
    unique_findings = []
    for finding in all_findings:
        key = (
            finding["severity"],
            finding["message"],
            frozenset(finding["devices"]),
        )
        if key in seen:
            continue
        seen.add(key)
        unique_findings.append(finding)

    unique_findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))

    return unique_findings

def generate_report(findings):
    """
    Print a formatted security report to stdout.

    Groups findings by severity (critical -> high -> medium -> low),
    prints a summary header, then each finding with its devices.

    Args:
        findings (list): List of finding dicts from validate_security_rules.

    Returns:
        None
    """
    print("=" * 60)
    print("  NETWORK TOPOLOGY SECURITY REPORT")
    print("=" * 60)

    if not findings:
        print("\n  [OK] No security design flaws detected.")
        print("=" * 60)
        return

    # Count by severity
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    # Summary line
    total = len(findings)
    print(f"\n  Total findings: {total}")
    for severity in ("critical", "high", "medium", "low"):
        if severity in counts:
            print(f"    {severity.upper():<8} : {counts[severity]}")

    # Group and print findings
    for severity in ("critical", "high", "medium", "low"):
        group = [f for f in findings if f["severity"] == severity]
        if not group:
            continue

        print("\n" + "-" * 60)
        print(f"  {severity.upper()} ({len(group)})")
        print("-" * 60)

        for i, f in enumerate(group, start=1):
            devices_str = ", ".join(f["devices"])
            print(f"\n  {i}. {f['message']}")
            print(f"     Affected devices: {devices_str}")

    print("\n" + "=" * 60)

def main():
    """
    CLI entry point. Parses arguments, runs the validator, prints the report.

    Exit codes:
        0 = no findings (topology is clean)
        1 = findings present (topology has security flaws)
        2 = error (bad arguments, missing file, malformed data)
    """
    parser = argparse.ArgumentParser(
        description="Validate a network topology JSON file for security design flaws.",
    )
    parser.add_argument(
        "topology_file",
        help="Path to the JSON topology file (e.g. secure.json).",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress the report; only set the exit code.",
    )
    args = parser.parse_args()

    try:
        topo = load_topology(args.topology_file)
        devices = parse_devices(topo["devices"])
        connections = parse_connections(topo["connections"], devices)
        graph = build_graph(devices, connections)
    except (FileNotFoundError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)

    findings = validate_security_rules(devices, graph)

    if not args.quiet:
        generate_report(findings)

    sys.exit(1 if findings else 0)

if __name__ == "__main__":
    main()