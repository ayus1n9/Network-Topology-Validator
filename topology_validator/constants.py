"""Shared constants for the topology validator."""

EXTERNAL_ZONES = {"external"}
TRUSTED_ZONES = {"internal", "database"}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# Zone colors for visualization.
ZONE_COLORS = {
    "external": "#e74c3c",   # red — untrusted
    "dmz":      "#f39c12",   # orange — semi-trusted
    "internal": "#3498db",   # blue — trusted
    "database": "#8e44ad",   # purple — crown jewels
}
DEFAULT_ZONE_COLOR = "#95a5a6"  # grey fallback

# Score penalties per finding severity.
# Base score is 100. Each finding subtracts its penalty. Floor at 0.
SCORE_PENALTIES = {
    "critical": 25,
    "high":     10,
    "medium":    4,
    "low":       1,
}

# Score -> letter grade thresholds (inclusive lower bound).
GRADE_THRESHOLDS = [
    (90, "A"),
    (80, "B"),
    (70, "C"),
    (60, "D"),
    (0,  "F"),
]

# Colors used in the HTML report, per grade letter.
GRADE_COLORS = {
    "A": "#27ae60",  # green
    "B": "#2ecc71",  # light green
    "C": "#f39c12",  # orange
    "D": "#e67e22",  # dark orange
    "F": "#e74c3c",  # red
}