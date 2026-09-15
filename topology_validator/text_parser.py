"""Parse topologies written in the simple text format.

Format:
    # comments start with #
    device <id> <type> <zone>
    <id> -- <id>          (connection)

Example:
    device internet internet external
    device fw1 firewall dmz
    internet -- fw1
"""


def parse_topology_text(file_path):
    """
    Parse a .txt topology file into the same dict shape as load_topology().

    Args:
        file_path (str): Path to the .txt topology file.

    Returns:
        dict: {"devices": [...], "connections": [...]}

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If a line cannot be parsed.
    """
    devices = []
    connections = []

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        raise FileNotFoundError(f"Topology file not found: {file_path}")

    for lineno, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()

        # Skip blank lines and comments.
        if not line or line.startswith("#"):
            continue

        if line.startswith("device "):
            parts = line.split()
            if len(parts) != 4:
                raise ValueError(
                    f"{file_path}, line {lineno}: "
                    f"device lines must be 'device <id> <type> <zone>' — got: {line!r}"
                )
            _, dev_id, dev_type, zone = parts
            devices.append({"id": dev_id, "type": dev_type, "zone": zone})

        elif "--" in line:
            left, right = line.split("--", 1)
            src = left.strip()
            dst = right.strip()
            if not src or not dst:
                raise ValueError(
                    f"{file_path}, line {lineno}: "
                    f"connection must have a device on each side of '--' — got: {line!r}"
                )
            connections.append({"from": src, "to": dst})

        else:
            raise ValueError(
                f"{file_path}, line {lineno}: unrecognized line — got: {line!r}\n"
                f"Expected 'device <id> <type> <zone>' or '<id> -- <id>'."
            )

    return {"devices": devices, "connections": connections}