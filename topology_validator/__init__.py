"""
Network Topology Security Validator.

Public API:
    load_topology      -- parse a topology JSON file
    parse_devices      -- convert devices list to dict
    parse_connections  -- validate and normalize connections
    build_graph        -- build adjacency list
    validate_security_rules -- run all rules, return findings
    generate_report    -- print a formatted report
    main               -- CLI entry point
"""

from topology_validator.loader import load_topology
from topology_validator.parser import parse_devices, parse_connections
from topology_validator.graph import build_graph
from topology_validator.rules import validate_security_rules
from topology_validator.report import generate_report

__all__ = [
    "load_topology",
    "parse_devices",
    "parse_connections",
    "build_graph",
    "validate_security_rules",
    "generate_report"
]