"""Shared constants for the topology validator."""

EXTERNAL_ZONES = {"external"}
TRUSTED_ZONES = {"internal", "database"}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# Zone colors for visualization. Keys are exact strings from the topology.
ZONE_COLORS = {
    "external": "#e74c3c",   # red — untrusted
    "dmz":      "#f39c12",   # orange — semi-trusted
    "internal": "#3498db",   # blue — trusted
    "database": "#8e44ad",   # purple — crown jewels
}

# Fallback for unknown zones.
DEFAULT_ZONE_COLOR = "#95a5a6"  # grey