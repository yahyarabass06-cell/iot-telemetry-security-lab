"""Evaluate generated ordered scenarios against separate expected labels."""

import hashlib
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from iot_security.configuration import load_demo_registry
from iot_security.state import ReplayState
from iot_security.validation import TelemetryValidator

ROOT = Path(__file__).resolve().parents[2]


def test_generated_scenarios_match_independent_expectations(tmp_path):
    destination = tmp_path / "generated"
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/generate_scenarios.py"),
            "--output",
            str(destination),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    raw = (destination / "messages.jsonl").read_bytes()
    manifest = json.loads((destination / "manifest.json").read_text())
    assert hashlib.sha256(raw).hexdigest() == manifest["messages_sha256"]
    messages = raw.decode("utf-8").splitlines()
    assert len(messages) == len(manifest["scenarios"]) == 10

    registry = load_demo_registry(ROOT / "config/devices-demo.json")
    now = datetime.fromisoformat(manifest["evaluation_time"])
    with ReplayState(tmp_path / "state.sqlite") as state:
        receiver = TelemetryValidator(keys=registry, state=state)
        for message, expected in zip(messages, manifest["scenarios"], strict=True):
            result = receiver.validate(message, now=now)
            assert result.status == expected["expected_status"]
            assert result.reason == expected["expected_reason"]
            assert (
                list(result.measurement_alerts)
                == (expected["expected_measurement_alerts"])
            )
