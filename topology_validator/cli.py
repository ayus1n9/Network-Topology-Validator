"""Command-line interface for the topology validator."""

import argparse
import sys

from topology_validator.visualize import visualize_topology
from topology_validator.loader import load_topology
from topology_validator.parser import parse_devices, parse_connections
from topology_validator.graph import build_graph
from topology_validator.rules import validate_security_rules
from topology_validator.report import generate_report


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
        help="Path to the topology file (.json or .txt).",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress the report; only set the exit code.",
    )
    parser.add_argument(
        "-v", "--visualize",
        action="store_true",
        help="Render the topology to a PNG file (e.g. insecure.png).",
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

    if args.visualize:
        # Strip .json / .txt from the input, add .png
        base = args.topology_file.rsplit(".", 1)[0]
        output_path = f"{base}.png"
        try:
            visualize_topology(devices, graph, findings, output_path)
            print(f"\nVisualization written to: {output_path}")
        except Exception as e:
            print(f"Error generating visualization: {e}", file=sys.stderr)
            sys.exit(2)

    sys.exit(1 if findings else 0)

if __name__ == "__main__":
    main()