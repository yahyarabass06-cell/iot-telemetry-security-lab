"""Strict loading of the public demonstration device registry."""

import json
import re
from pathlib import Path

from iot_security.models import DEVICE_PATTERN

MAX_CONFIGURATION_BYTES = 65_536


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate configuration key.")
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError("Non-finite configuration value.")


def load_demo_registry(path: Path) -> dict[str, bytes]:
    with Path(path).open("rb") as source:
        raw = source.read(MAX_CONFIGURATION_BYTES + 1)
    if len(raw) > MAX_CONFIGURATION_BYTES:
        raise ValueError("Configuration exceeds the byte limit.")
    data = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_unique_object,
        parse_constant=_reject_constant,
    )
    if not isinstance(data, dict) or set(data) != {
        "schema_version",
        "key_purpose",
        "devices",
    }:
        raise ValueError("Unexpected registry fields.")
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise ValueError("Unsupported registry schema.")
    if data["key_purpose"] != "public_synthetic_demo_only":
        raise ValueError("This loader supports demonstration keys only.")

    devices = data["devices"]
    if not isinstance(devices, list) or not 1 <= len(devices) <= 100:
        raise ValueError("Invalid device collection.")

    registry = {}
    for entry in devices:
        if not isinstance(entry, dict) or set(entry) != {"device_id", "key_hex"}:
            raise ValueError("Invalid device fields.")
        device_id = entry["device_id"]
        key_hex = entry["key_hex"]
        if (
            not isinstance(device_id, str)
            or not DEVICE_PATTERN.fullmatch(device_id)
            or device_id in registry
        ):
            raise ValueError("Invalid or duplicate device identifier.")
        if not isinstance(key_hex, str) or not re.fullmatch(
            r"(?:[0-9a-f]{2}){32,64}", key_hex
        ):
            raise ValueError("Invalid demonstration key encoding.")
        registry[device_id] = bytes.fromhex(key_hex)

    return registry
