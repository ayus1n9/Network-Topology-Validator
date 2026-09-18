"""Tests for security rules."""

from topology_validator.parser import parse_devices, parse_connections
from topology_validator.graph import build_graph
from topology_validator.rules import (
    rule_database_exposed,
    rule_internet_to_internal,
    rule_dmz_to_internal,
    rule_web_to_database,
    rule_no_firewall_path,
    rule_single_point_of_failure,
    validate_security_rules,
)


def _build(devices_list, connections_list):
    devices = parse_devices(devices_list)
    connections = parse_connections(connections_list, devices)
    graph = build_graph(devices, connections)
    return devices, graph


def test_rule_database_exposed_flags_dmz_neighbor():
    devices, graph = _build(
        [
            {"id": "db1", "type": "database", "zone": "internal"},
            {"id": "web1", "type": "web_server", "zone": "dmz"},
        ],
        [{"from": "db1", "to": "web1"}],
    )
    findings = rule_database_exposed(devices, graph)
    assert len(findings) == 1
    assert "db1" in findings[0]["devices"]


def test_rule_database_exposed_clean():
    devices, graph = _build(
        [
            {"id": "db1", "type": "database", "zone": "internal"},
            {"id": "fw1", "type": "firewall", "zone": "internal"},
        ],
        [{"from": "db1", "to": "fw1"}],
    )
    assert rule_database_exposed(devices, graph) == []


def test_rule_internet_to_internal():
    devices, graph = _build(
        [
            {"id": "net", "type": "internet", "zone": "external"},
            {"id": "app1", "type": "app_server", "zone": "internal"},
        ],
        [{"from": "net", "to": "app1"}],
    )
    findings = rule_internet_to_internal(devices, graph)
    assert len(findings) == 1


def test_rule_dmz_to_internal_exception_for_firewall():
    devices, graph = _build(
        [
            {"id": "fw2", "type": "firewall", "zone": "dmz"},
            {"id": "app1", "type": "app_server", "zone": "internal"},
        ],
        [{"from": "fw2", "to": "app1"}],
    )
    assert rule_dmz_to_internal(devices, graph) == []


def test_rule_web_to_database():
    devices, graph = _build(
        [
            {"id": "web1", "type": "web_server", "zone": "dmz"},
            {"id": "db1", "type": "database", "zone": "internal"},
        ],
        [{"from": "web1", "to": "db1"}],
    )
    findings = rule_web_to_database(devices, graph)
    assert len(findings) == 1


def test_rule_no_firewall_path_direct():
    devices, graph = _build(
        [
            {"id": "net", "type": "internet", "zone": "external"},
            {"id": "db1", "type": "database", "zone": "internal"},
        ],
        [{"from": "net", "to": "db1"}],
    )
    findings = rule_no_firewall_path(devices, graph)
    assert len(findings) == 1
    assert findings[0]["severity"] == "critical"


def test_rule_no_firewall_path_blocked_by_firewall():
    devices, graph = _build(
        [
            {"id": "net", "type": "internet", "zone": "external"},
            {"id": "fw1", "type": "firewall", "zone": "dmz"},
            {"id": "db1", "type": "database", "zone": "internal"},
        ],
        [
            {"from": "net", "to": "fw1"},
            {"from": "fw1", "to": "db1"},
        ],
    )
    assert rule_no_firewall_path(devices, graph) == []

def test_rule_no_firewall_path_transitive():
    devices, graph = _build(
        [
            {"id": "net", "type": "internet", "zone": "external"},
            {"id": "r1", "type": "router", "zone": "dmz"},
            {"id": "sw1", "type": "switch", "zone": "internal"},
            {"id": "db1", "type": "database", "zone": "internal"},
        ],
        [
            {"from": "net", "to": "r1"},
            {"from": "r1", "to": "sw1"},
            {"from": "sw1", "to": "db1"},
        ],
    )
    findings = rule_no_firewall_path(devices, graph)
    assert len(findings) == 1
    assert findings[0]["severity"] == "critical"


def test_rule_single_point_of_failure_linear_chain():
    devices, graph = _build(
        [
            {"id": "net", "type": "internet", "zone": "external"},
            {"id": "fw1", "type": "firewall", "zone": "dmz"},
            {"id": "db1", "type": "database", "zone": "internal"},
        ],
        [
            {"from": "net", "to": "fw1"},
            {"from": "fw1", "to": "db1"},
        ],
    )
    findings = rule_single_point_of_failure(devices, graph)
    assert len(findings) == 1
    assert "fw1" in findings[0]["devices"]


def test_rule_single_point_of_failure_redundant_path():
    # net has two parallel routes to db — no SPOF
    devices, graph = _build(
        [
            {"id": "net", "type": "internet", "zone": "external"},
            {"id": "fw1", "type": "firewall", "zone": "dmz"},
            {"id": "fw2", "type": "firewall", "zone": "dmz"},
            {"id": "db1", "type": "database", "zone": "internal"},
        ],
        [
            {"from": "net", "to": "fw1"},
            {"from": "net", "to": "fw2"},
            {"from": "fw1", "to": "db1"},
            {"from": "fw2", "to": "db1"},
        ],
    )
    assert rule_single_point_of_failure(devices, graph) == []


def test_validate_security_rules_dedupes_and_sorts():
    devices, graph = _build(
        [
            {"id": "net", "type": "internet", "zone": "external"},
            {"id": "db1", "type": "database", "zone": "internal"},
        ],
        [{"from": "net", "to": "db1"}],
    )
    findings = validate_security_rules(devices, graph)
    # critical must come before high
    severities = [f["severity"] for f in findings]
    assert severities == sorted(
        severities,
        key=lambda s: {"critical": 0, "high": 1, "medium": 2, "low": 3}[s],
    )
    # no exact duplicates
    keys = [(f["severity"], f["message"], frozenset(f["devices"])) for f in findings]
    assert len(keys) == len(set(keys))