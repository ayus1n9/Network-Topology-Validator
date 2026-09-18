"""Tests for graph construction and traversal."""

from topology_validator.graph import (
    build_graph,
    reachable_from,
    is_reachable,
    shortest_path,
)


def _devices(*ids):
    return {i: {"id": i, "type": "router", "zone": "internal"} for i in ids}


def test_build_graph_undirected():
    devices = _devices("a", "b", "c")
    conns = [("a", "b"), ("b", "c")]
    g = build_graph(devices, conns)
    assert g["a"] == {"b"}
    assert g["b"] == {"a", "c"}
    assert g["c"] == {"b"}


def test_build_graph_isolated_device():
    devices = _devices("a", "lonely")
    g = build_graph(devices, [])
    assert g["lonely"] == set()


def test_build_graph_dedupes_duplicate_edges():
    devices = _devices("a", "b")
    conns = [("a", "b"), ("a", "b"), ("b", "a")]
    g = build_graph(devices, conns)
    assert g["a"] == {"b"}
    assert g["b"] == {"a"}


def test_reachable_from_linear_chain():
    devices = _devices("a", "b", "c", "d")
    g = build_graph(devices, [("a", "b"), ("b", "c"), ("c", "d")])
    assert reachable_from(g, "a") == {"a", "b", "c", "d"}


def test_reachable_from_with_blocked():
    devices = _devices("a", "b", "c", "d")
    g = build_graph(devices, [("a", "b"), ("b", "c"), ("c", "d")])
    assert reachable_from(g, "a", blocked=frozenset({"c"})) == {"a", "b"}


def test_reachable_from_missing_source():
    devices = _devices("a")
    g = build_graph(devices, [])
    assert reachable_from(g, "ghost") == set()


def test_is_reachable_true():
    devices = _devices("a", "b")
    g = build_graph(devices, [("a", "b")])
    assert is_reachable(g, "a", "b")


def test_is_reachable_false():
    devices = _devices("a", "b")
    g = build_graph(devices, [])
    assert not is_reachable(g, "a", "b")


def test_shortest_path_direct():
    devices = _devices("a", "b")
    g = build_graph(devices, [("a", "b")])
    assert shortest_path(g, "a", "b") == ["a", "b"]


def test_shortest_path_no_path():
    devices = _devices("a", "b")
    g = build_graph(devices, [])
    assert shortest_path(g, "a", "b") == []


def test_shortest_path_prefers_shorter_route():
    # a-b-c and a-c ; shortest is a-c
    devices = _devices("a", "b", "c")
    g = build_graph(devices, [("a", "b"), ("b", "c"), ("a", "c")])
    path = shortest_path(g, "a", "c")
    assert len(path) == 2
    assert path[0] == "a" and path[-1] == "c"