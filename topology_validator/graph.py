"""Build the adjacency list (undirected graph) from devices and connections."""


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