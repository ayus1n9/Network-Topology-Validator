"""Command-line interface for the topology validator."""

import argparse
import sys

from topology_validator.loader import load_topology
from topology_validator.parser import parse_devices, parse_connections
from topology_validator.graph import build_graph
from topology_validator.rules import validate_security_rules
from topology_validator.report import (
    calculate_score,
    generate_report,
    generate_json_report,
    generate_html_report,
)
from topology_validator.visualize import visualize_topology
from topology_validator.interactive import run_interactive

def main():
    """
    CLI entry point. Parses arguments, runs the validator, prints the report.

    Exit codes:
        0 = no findings (topology is clean)
        1 = findings present (topology has security flaws)
        2 = error (bad arguments, missing file, malformed data)
    """
    parser = argparse.ArgumentParser(
        description="Validate a network topology file for security design flaws.",
    )
    parser.add_argument(
        "topology_file",
        nargs="?",
        help="Path to the topology file (.json or .txt). Optional with --interactive.",
    )
    parser.add_argument(
        "-i", "--interactive",
        action="store_true",
        help="Launch the interactive PBQ-style topology builder.",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress the terminal report; only set the exit code.",
    )
    parser.add_argument(
        "-v", "--visualize",
        action="store_true",
        help="Render the topology to a PNG file.",
    )
    parser.add_argument(
        "-f", "--format",
        choices=("text", "json", "html"),
        default="text",
        help="Report format (default: text).",
    )
    parser.add_argument(
        "-o", "--output",
        help="Output path for json/html reports (default derived from input).",
    )
    args = parser.parse_args()

    # ---- Interactive mode short-circuits everything else ----
    if args.interactive:
        run_interactive(initial_file=args.topology_file)
        sys.exit(0)

    # ---- Non-interactive mode requires a topology file ----
    if not args.topology_file:
        parser.error("topology_file is required unless --interactive is used.")

    # ---- Load + parse ----
    try:
        topo = load_topology(args.topology_file)
        devices = parse_devices(topo["devices"])
        connections = parse_connections(topo["connections"], devices)
        graph = build_graph(devices, connections)
    except (FileNotFoundError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)

    # ---- Validate ----
    findings = validate_security_rules(devices, graph)
    score = calculate_score(findings)

    base = args.topology_file.rsplit(".", 1)[0]
    outputs_written = []

    # ---- Optional visualization ----
    png_path = None
    if args.visualize:
        png_path = f"{base}.png"
        try:
            visualize_topology(devices, graph, findings, png_path)
            outputs_written.append(png_path)
        except Exception as e:
            print(f"Error generating visualization: {e}", file=sys.stderr)
            sys.exit(2)

    # ---- Report ----
    if args.format == "text":
        if not args.quiet:
            generate_report(findings)
    elif args.format == "json":
        output_path = args.output or f"{base}.report.json"
        try:
            generate_json_report(findings, score, args.topology_file, output_path)
            outputs_written.append(output_path)
        except OSError as e:
            print(f"Error writing JSON report: {e}", file=sys.stderr)
            sys.exit(2)
    elif args.format == "html":
        output_path = args.output or f"{base}.report.html"
        try:
            generate_html_report(
                findings, score, args.topology_file, output_path,
                png_path=png_path,
            )
            outputs_written.append(output_path)
        except OSError as e:
            print(f"Error writing HTML report: {e}", file=sys.stderr)
            sys.exit(2)

    if not args.quiet and outputs_written:
        print()
        for path in outputs_written:
            print(f"Wrote: {path}")

    sys.exit(1 if findings else 0)