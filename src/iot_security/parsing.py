"""Parse bounded telemetry JSON without silently accepting extra fields."""

import json
from datetime import datetime

from iot_security.models import SignedTelemetry, TelemetryPayload

MAX_MESSAGE_CHARACTERS = 4_096


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key.")
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError("Non-finite JSON constant.")


def parse_message(text: str) -> SignedTelemetry:
    if (
        not isinstance(text, str)
        or not text.strip()
        or len(text) > MAX_MESSAGE_CHARACTERS
    ):
        raise ValueError("Message is empty or exceeds the character limit.")
    data = json.loads(
        text,
        object_pairs_hook=_unique_object,
        parse_constant=_reject_constant,
    )
    expected = {
        "schema_version",
        "device_id",
        "timestamp",
        "sequence",
        "temperature_c",
        "vibration_mm_s",
        "signature",
    }
    if not isinstance(data, dict) or set(data) != expected:
        raise ValueError("Unexpected message fields.")
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise ValueError("Unsupported message schema.")
    if not isinstance(data["timestamp"], str):
        raise ValueError("Timestamp must be a string.")

    payload = TelemetryPayload(
        device_id=data["device_id"],
        timestamp=datetime.fromisoformat(data["timestamp"]),
        sequence=data["sequence"],
        temperature_c=data["temperature_c"],
        vibration_mm_s=data["vibration_mm_s"],
    )
    return SignedTelemetry(payload=payload, signature=data["signature"])
