"""Tests for topology loading."""

import json

import pytest

from topology_validator.loader import load_topology


@pytest.fixture
def secure_json(tmp_path):
    data = {
        "devices": [
            {"id": "fw1", "type": "firewall", "zone": "dmz"},
            {"id": "db1", "type": "database", "zone": "internal"},
        ],
        "connections": [
            {"from": "fw1", "to": "db1"},
        ],
    }
    path = tmp_path / "secure.json"
    path.write_text(json.dumps(data))
    return str(path)


@pytest.fixture
def secure_txt(tmp_path):
    content = """
    # sample topology
    device fw1 firewall dmz
    device db1 database internal
    fw1 -- db1
    """
    path = tmp_path / "secure.txt"
    path.write_text(content)
    return str(path)


def test_load_json_returns_dict(secure_json):
    topo = load_topology(secure_json)
    assert isinstance(topo, dict)
    assert "devices" in topo
    assert "connections" in topo
    assert len(topo["devices"]) == 2


def test_load_text_returns_dict(secure_txt):
    topo = load_topology(secure_txt)
    assert isinstance(topo, dict)
    assert len(topo["devices"]) == 2
    assert len(topo["connections"]) == 1
    assert topo["connections"][0] == {"from": "fw1", "to": "db1"}


def test_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        load_topology("/nonexistent/path/to/file.json")


def test_invalid_json_raises(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not valid json")
    with pytest.raises(ValueError, match="Invalid JSON"):
        load_topology(str(path))


def test_missing_devices_key_raises(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"connections": []}))
    with pytest.raises(ValueError, match="devices"):
        load_topology(str(path))


def test_unsupported_extension_raises(tmp_path):
    path = tmp_path / "topo.yaml"
    path.write_text("devices: []")
    with pytest.raises(ValueError, match="Unsupported file extension"):
        load_topology(str(path))


def test_text_bad_device_line_raises(tmp_path):
    path = tmp_path / "bad.txt"
    path.write_text("device web1 web_server\n")  # missing zone
    with pytest.raises(ValueError, match="line 1"):
        load_topology(str(path))