"""
Network Topology Security Validator.

Public API:
    load_topology           -- parse a topology JSON or text file
    parse_topology_text     -- parse a text-format topology file
    parse_devices           -- convert devices list to dict
    parse_connections       -- validate and normalize connections
    build_graph             -- build adjacency list
    validate_security_rules -- run all rules, return findings
    generate_report         -- print a formatted report
"""

from topology_validator.loader import load_topology
from topology_validator.text_parser import parse_topology_text
from topology_validator.parser import parse_devices, parse_connections
from topology_validator.graph import build_graph
from topology_validator.rules import validate_security_rules
from topology_validator.report import generate_report

__all__ = [
    "load_topology",
    "parse_topology_text",
    "parse_devices",
    "parse_connections",
    "build_graph",
    "validate_security_rules",
    "generate_report"
]