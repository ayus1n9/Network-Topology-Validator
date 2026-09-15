"""Load a topology definition from a JSON or text file."""

import json

from topology_validator.text_parser import parse_topology_text

def load_topology(file_path):
    """
    Load a topology from a file. Format is chosen by extension:
        .json  -> JSON parser
        .txt   -> text-format parser

    Args:
        file_path (str): Path to the topology file.

    Returns:
        dict: Parsed topology with 'devices' and 'connections' keys.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the extension is unsupported or the file is malformed.
    """
    if file_path.endswith(".json"):
        return _load_json(file_path)
    if file_path.endswith(".txt"):
        return parse_topology_text(file_path)
    raise ValueError(
        f"Unsupported file extension for {file_path!r}. Use .json or .txt."
    )


def _load_json(file_path):
    """Load and validate a JSON topology file."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError(f"Topology file not found: {file_path}")
    except json.JSONDecodeError as e:
        raise ValueError(
            f"Invalid JSON in {file_path}: {e.msg} (line {e.lineno}, col {e.colno})"
        ) from e

    if not isinstance(data, dict):
        raise ValueError("Topology file must contain a JSON object at the top level.")
    if "devices" not in data:
        raise ValueError("Topology must have a 'devices' key.")
    if "connections" not in data:
        raise ValueError("Topology must have a 'connections' key.")
    if not isinstance(data["devices"], list):
        raise ValueError("'devices' must be a list.")
    if not isinstance(data["connections"], list):
        raise ValueError("'connections' must be a list.")

    return data