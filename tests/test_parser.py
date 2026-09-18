"""Tests for device and connection parsing."""

import pytest

from topology_validator.parser import parse_devices, parse_connections


def test_parse_devices_basic():
    devices = [
        {"id": "fw1", "type": "firewall", "zone": "dmz"},
        {"id": "db1", "type": "database", "zone": "internal"},
    ]
    result = parse_devices(devices)
    assert set(result.keys()) == {"fw1", "db1"}
    assert result["fw1"]["type"] == "firewall"


def test_parse_devices_empty():
    assert parse_devices([]) == {}


def test_parse_devices_missing_field():
    with pytest.raises(ValueError, match="missing required field"):
        parse_devices([{"id": "fw1", "type": "firewall"}])  # no zone


def test_parse_devices_duplicate_id():
    with pytest.raises(ValueError, match="Duplicate device id"):
        parse_devices([
            {"id": "fw1", "type": "firewall", "zone": "dmz"},
            {"id": "fw1", "type": "firewall", "zone": "internal"},
        ])


def test_parse_devices_non_dict():
    with pytest.raises(ValueError, match="not a dictionary"):
        parse_devices(["not a dict"])


def test_parse_connections_basic():
    devices = parse_devices([
        {"id": "a", "type": "router", "zone": "external"},
        {"id": "b", "type": "router", "zone": "internal"},
    ])
    conns = [{"from": "a", "to": "b"}]
    result = parse_connections(conns, devices)
    assert result == [("a", "b")]


def test_parse_connections_unknown_device():
    devices = parse_devices([{"id": "a", "type": "router", "zone": "dmz"}])
    with pytest.raises(ValueError, match="unknown device"):
        parse_connections([{"from": "a", "to": "ghost"}], devices)


def test_parse_connections_self_loop():
    devices = parse_devices([{"id": "a", "type": "router", "zone": "dmz"}])
    with pytest.raises(ValueError, match="self-loop"):
        parse_connections([{"from": "a", "to": "a"}], devices)