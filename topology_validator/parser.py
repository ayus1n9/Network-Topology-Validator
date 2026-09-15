"""Parse and validate the raw devices and connections lists."""


def parse_devices(devices_list):
    """
    Convert a list of device dicts into a dict keyed by device id.
    Validates required fields: 'id', 'type', 'zone'.

    Args:
        devices_list (list): List of device dictionaries.

    Returns:
        dict: Mapping of device_id -> device_dict.

    Raises:
        ValueError: If any device is missing required fields or has a duplicate id.
    """
    devices_dict = {}

    for index, device in enumerate(devices_list):
        if not isinstance(device, dict):
            raise ValueError(f"Device at index {index} is not a dictionary.")

        for field in ("id", "type", "zone"):
            if field not in device:
                raise ValueError(
                    f"Device at index {index} is missing required field '{field}': {device}"
                )
            if not isinstance(device[field], str) or not device[field].strip():
                raise ValueError(
                    f"Device at index {index} has an invalid '{field}' value: {device[field]!r}"
                )

        device_id = device["id"]
        if device_id in devices_dict:
            raise ValueError(f"Duplicate device id found: '{device_id}'")

        devices_dict[device_id] = device

    return devices_dict


def parse_connections(connections_list, devices_dict):
    """
    Validate connections and return them as a list of (from_id, to_id) tuples.

    Args:
        connections_list (list): List of dicts with 'from' and 'to' keys.
        devices_dict (dict): Mapping of device_id -> device_dict.

    Returns:
        list: List of tuples (from_id, to_id).

    Raises:
        ValueError: If a connection is malformed, references an unknown device,
                    or is a self-loop.
    """
    connections = []

    for index, conn in enumerate(connections_list):
        if not isinstance(conn, dict):
            raise ValueError(f"Connection at index {index} is not a dictionary.")

        for field in ("from", "to"):
            if field not in conn:
                raise ValueError(
                    f"Connection at index {index} is missing required field '{field}': {conn}"
                )
            if not isinstance(conn[field], str) or not conn[field].strip():
                raise ValueError(
                    f"Connection at index {index} has an invalid '{field}' value: {conn[field]!r}"
                )

        src = conn["from"]
        dst = conn["to"]

        if src not in devices_dict:
            raise ValueError(
                f"Connection at index {index} references unknown device: '{src}'"
            )
        if dst not in devices_dict:
            raise ValueError(
                f"Connection at index {index} references unknown device: '{dst}'"
            )

        if src == dst:
            raise ValueError(
                f"Connection at index {index} is a self-loop: '{src}' connects to itself."
            )

        connections.append((src, dst))

    return connections