"""Load a topology definition from a JSON file."""

import json


def load_topology(file_path):
    """
    Load a network topology from a JSON file.

    Args:
        file_path (str): Path to the JSON file.

    Returns:
        dict: Parsed topology with 'devices' and 'connections' keys.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the JSON structure is invalid.
    """
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