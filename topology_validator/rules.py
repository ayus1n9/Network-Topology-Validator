from topology_validator.graph import reachable_from, is_reachable, shortest_path
from topology_validator.constants import (
    EXTERNAL_ZONES,
    TRUSTED_ZONES,
    SEVERITY_ORDER,
)


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

        # No seen_pairs needed: we only start from databases,
        # so each (db, neighbor) pair is visited exactly once.
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
        is_external = (
            device["type"] == "internet" or device["zone"] in EXTERNAL_ZONES
        )
        if not is_external:
            continue

        for neighbor_id in graph.get(device_id, set()):
            neighbor = devices_dict[neighbor_id]

            if neighbor["zone"] not in TRUSTED_ZONES:
                continue

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

def rule_no_firewall_path(devices_dict, graph):
    """
    Flag any path from an internet-facing device to a database that
    never passes through a firewall.

    This catches "silent bypasses" — cases where the internet can reach
    the DB through non-firewall hops, even if there's no direct edge.

    Args:
        devices_dict (dict): Mapping of device_id -> device_dict.
        graph (dict): Adjacency list mapping device_id -> set of neighbors.

    Returns:
        list: List of finding dicts.
    """
    firewalls = {
        dev_id for dev_id, dev in devices_dict.items()
        if dev["type"] == "firewall"
    }
    internet_devices = {
        dev_id for dev_id, dev in devices_dict.items()
        if dev["type"] == "internet" or dev["zone"] in EXTERNAL_ZONES
    }
    db_devices = {
        dev_id for dev_id, dev in devices_dict.items()
        if dev["type"] == "database"
    }

    findings = []

    for src in internet_devices:
        # BFS from this internet device, refusing to pass through any firewall.
        reachable = reachable_from(graph, src, blocked=frozenset(firewalls))

        for db in db_devices:
            if db in reachable:
                findings.append({
                    "severity": "critical",
                    "message": (
                        f"Internet-facing device '{src}' can reach database "
                        f"'{db}' without passing through any firewall."
                    ),
                    "devices": [src, db],
                })

    return findings


def rule_single_point_of_failure(devices_dict, graph):
    """
    Flag devices whose failure disconnects an internet-facing device
    from a database.

    Every path from internet to DB passes through these nodes — meaning
    a single hardware failure or compromise takes the whole chain down.

    Args:
        devices_dict (dict): Mapping of device_id -> device_dict.
        graph (dict): Adjacency list mapping device_id -> set of neighbors.

    Returns:
        list: List of finding dicts.
    """
    internet_devices = {
        dev_id for dev_id, dev in devices_dict.items()
        if dev["type"] == "internet" or dev["zone"] in EXTERNAL_ZONES
    }
    db_devices = {
        dev_id for dev_id, dev in devices_dict.items()
        if dev["type"] == "database"
    }

    findings = []

    for src in internet_devices:
        for db in db_devices:
            path = shortest_path(graph, src, db)
            if not path:
                continue  # No path at all — different problem (not our concern here)

            spofs = []
            for node in path[1:-1]:  # exclude src and db themselves
                if not is_reachable(graph, src, db, blocked=frozenset({node})):
                    spofs.append(node)

            if spofs:
                findings.append({
                    "severity": "medium",
                    "message": (
                        f"Critical path from '{src}' to '{db}' has no redundancy — "
                        f"these devices are single points of failure: "
                        f"{', '.join(spofs)}."
                    ),
                    "devices": [src, db] + spofs,
                })

    return findings

def validate_security_rules(devices_dict, graph):
    """
    Run every security rule against the topology and return deduplicated,
    severity-sorted findings.
    """
    all_findings = []
    all_findings.extend(rule_database_exposed(devices_dict, graph))
    all_findings.extend(rule_internet_to_internal(devices_dict, graph))
    all_findings.extend(rule_dmz_to_internal(devices_dict, graph))
    all_findings.extend(rule_web_to_database(devices_dict, graph))
    all_findings.extend(rule_no_firewall_path(devices_dict, graph))
    all_findings.extend(rule_single_point_of_failure(devices_dict, graph))

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