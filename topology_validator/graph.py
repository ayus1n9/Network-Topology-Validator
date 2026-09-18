"""Build and traverse the adjacency-list graph."""

from collections import deque

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


def reachable_from(graph, source, blocked=frozenset()):
    """
    BFS: return the set of nodes reachable from source without visiting blocked nodes.

    Args:
        graph (dict): Adjacency list.
        source (str): Starting device_id.
        blocked (frozenset): Nodes that cannot be visited (not even as passthrough).

    Returns:
        set: Every device_id reachable from source (including source itself),
             excluding blocked nodes.
    """
    if source in blocked:
        return set()
    if source not in graph:
        return set() 

    visited = {source}
    queue = deque([source])

    while queue:
        node = queue.popleft()
        for neighbor in graph.get(node, set()):
            if neighbor in blocked or neighbor in visited:
                continue
            visited.add(neighbor)
            queue.append(neighbor)

    return visited


def is_reachable(graph, source, target, blocked=frozenset()):
    """
    Return True if target is reachable from source, avoiding blocked nodes.
    """
    if source in blocked or target in blocked:
        return False
    return target in reachable_from(graph, source, blocked)


def shortest_path(graph, source, target):
    """
    BFS: return the shortest path from source to target as a list of node ids.
    Return [] if no path exists.

    Args:
        graph (dict): Adjacency list.
        source (str): Starting device_id.
        target (str): Target device_id.

    Returns:
        list: Node ids in order, from source to target inclusive. Empty if unreachable.
    """
    if source == target:
        return [source]

    visited = {source}
    parent = {source: None}
    queue = deque([source])

    while queue:
        node = queue.popleft()
        for neighbor in graph.get(node, set()):
            if neighbor in visited:
                continue
            visited.add(neighbor)
            parent[neighbor] = node

            if neighbor == target:
                # Walk parents back to source, then reverse.
                path = [target]
                while parent[path[-1]] is not None:
                    path.append(parent[path[-1]])
                path.reverse()
                return path

            queue.append(neighbor)

    return []