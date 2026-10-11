"""Generate ordered synthetic messages and independent expected decisions."""

import argparse
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from iot_security.models import TelemetryPayload
from iot_security.signing import payload_fields, sign_payload

KEY = bytes(range(32))
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def signed_fields(*, sequence=1, timestamp=NOW, device_id="sensor-01", temperature=25):
    payload = TelemetryPayload(
        device_id=device_id,
        timestamp=timestamp,
        sequence=sequence,
        temperature_c=temperature,
        vibration_mm_s=2,
    )
    fields = payload_fields(payload)
    fields["signature"] = sign_payload(payload, key=KEY).signature
    return fields


def generate(destination: Path):
    destination.mkdir(parents=True, exist_ok=False)
    messages = []
    expectations = []

    def add(name, message, status, reason, alerts=()):
        messages.append(message if isinstance(message, str) else json.dumps(message))
        expectations.append(
            {
                "scenario": name,
                "line_number": len(messages),
                "expected_status": status,
                "expected_reason": reason,
                "expected_measurement_alerts": list(alerts),
            }
        )

    add(
        "valid",
        signed_fields(),
        "accepted",
        "authenticated_new_message",
    )

    tampered = signed_fields(sequence=100)
    tampered["temperature_c"] = 99
    add("modified_payload", tampered, "rejected", "invalid_signature")

    incorrect = signed_fields(sequence=101)
    incorrect["signature"] = "0" * 64
    add("incorrect_signature", incorrect, "rejected", "invalid_signature")

    add(
        "unknown_device",
        signed_fields(device_id="unregistered"),
        "rejected",
        "unknown_device",
    )
    add("repeated_message", signed_fields(), "rejected", "replay_or_out_of_order")
    add(
        "lower_sequence",
        signed_fields(sequence=0),
        "rejected",
        "replay_or_out_of_order",
    )
    add(
        "stale",
        signed_fields(sequence=100, timestamp=NOW - timedelta(seconds=301)),
        "rejected",
        "stale_timestamp",
    )
    add(
        "future",
        signed_fields(sequence=100, timestamp=NOW + timedelta(seconds=31)),
        "rejected",
        "future_timestamp",
    )
    add(
        "authenticated_unusual_measurement",
        signed_fields(sequence=2, temperature=100),
        "accepted",
        "authenticated_new_message",
        ("temperature_outside_lab_bounds",),
    )
    add("malformed_json", "{", "rejected", "invalid_input")

    raw = ("\n".join(messages) + "\n").encode("utf-8")
    with (destination / "messages.jsonl").open("xb") as output:
        output.write(raw)

    manifest = {
        "schema_version": 1,
        "data_kind": "synthetic",
        "evaluation_time": NOW.isoformat(),
        "state_requirement": "fresh replay state before the first record",
        "messages_sha256": hashlib.sha256(raw).hexdigest(),
        "scenarios": expectations,
    }
    with (destination / "manifest.json").open("x", encoding="utf-8") as output:
        json.dump(manifest, output, indent=2)
        output.write("\n")
    print(f"Ten ordered scenarios written to {destination}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("data/synthetic/v1"))
    generate(parser.parse_args().output)


if __name__ == "__main__":
    main()
