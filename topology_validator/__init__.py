"""
Network Topology Security Validator.

Public API:
    load_topology           -- parse a topology JSON or text file
    parse_topology_text     -- parse a text-format topology file
    parse_devices           -- convert devices list to dict
    parse_connections       -- validate and normalize connections
    build_graph             -- build adjacency list
    validate_security_rules -- run all rules, return findings
    calculate_score         -- compute 0-100 score + grade
    generate_report         -- print a formatted report
    generate_json_report    -- write a JSON report
    generate_html_report    -- write an HTML report
    visualize_topology      -- render a PNG of the topology
    run_interactive         -- start the interactive PBQ-style REPL
"""

from topology_validator.loader import load_topology
from topology_validator.text_parser import parse_topology_text
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

__all__ = [
    "load_topology",
    "parse_topology_text",
    "parse_devices",
    "parse_connections",
    "build_graph",
    "validate_security_rules",
    "calculate_score",
    "generate_report",
    "generate_json_report",
    "generate_html_report",
    "visualize_topology",
    "run_interactive",
]