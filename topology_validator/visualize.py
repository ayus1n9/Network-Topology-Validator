"""Render a topology as a PNG image using networkx and matplotlib."""

import networkx as nx
import matplotlib.pyplot as plt

from topology_validator.constants import ZONE_COLORS, DEFAULT_ZONE_COLOR


def visualize_topology(devices_dict, graph, findings, output_path="topology.png"):
    """
    Render the topology graph to a PNG file.

    Nodes are colored by zone. Nodes involved in any finding get a red outline.

    Args:
        devices_dict (dict): Mapping of device_id -> device_dict.
        graph (dict): Adjacency list mapping device_id -> set of neighbors.
        findings (list): List of finding dicts (may be empty).
        output_path (str): Where to write the PNG file.

    Returns:
        str: The output_path (for convenience).
    """
    G = nx.Graph()
    G.add_nodes_from(graph.keys())
    G.add_edges_from(
        (src, dst) for src, neighbors in graph.items() for dst in neighbors
    )

    node_colors = [
        ZONE_COLORS.get(devices_dict[node]["zone"], DEFAULT_ZONE_COLOR)
        for node in G.nodes()
    ]

    flagged = _finding_device_ids(findings)
    node_edgecolors = ["red" if node in flagged else "black" for node in G.nodes()]
    node_linewidths = [3.0 if node in flagged else 0.8 for node in G.nodes()]

    pos = nx.spring_layout(G, seed=42, k=0.8, iterations=100)

    fig, ax = plt.subplots(figsize=(12, 8))
    nx.draw_networkx_edges(G, pos, ax=ax, edge_color="#888888", width=1.5)
    nx.draw_networkx_nodes(
        G, pos, ax=ax,
        node_color=node_colors,
        edgecolors=node_edgecolors,
        linewidths=node_linewidths,
        node_size=1400,
    )
    nx.draw_networkx_labels(
        G, pos, ax=ax,
        font_size=9,
        font_color="white",
        font_weight="bold",
    )

    _add_legend(ax)
    ax.set_title("Network Topology", fontsize=14, fontweight="bold")
    ax.axis("off")

    fig.tight_layout()
    fig.savefig(output_path, dpi=120, bbox_inches="tight")
    plt.close(fig)

    return output_path


def _finding_device_ids(findings):
    """Return the set of device_ids mentioned in any finding."""
    ids = set()
    for f in findings:
        ids.update(f["devices"])
    return ids


def _add_legend(ax):
    """Draw a small legend explaining zone colors."""
    from matplotlib.patches import Patch

    handles = [
        Patch(facecolor=color, label=zone)
        for zone, color in ZONE_COLORS.items()
    ]
    handles.append(
        Patch(facecolor="white", edgecolor="red", linewidth=2.0,
              label="flagged device")
    )
    ax.legend(
        handles=handles,
        loc="upper left",
        bbox_to_anchor=(0, 1),
        fontsize=9,
        frameon=True,
    )