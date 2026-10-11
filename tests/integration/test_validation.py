"""Verify security decisions and persistent replay boundaries."""

import json
from datetime import datetime, timedelta, timezone

import pytest

from iot_security.models import TelemetryPayload
from iot_security.signing import payload_fields, sign_payload
from iot_security.state import ReplayState
from iot_security.validation import TelemetryValidator

KEY = bytes(range(32))
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def wire(*, sequence=1, timestamp=NOW, device_id="sensor-01", temperature=25):
    payload = TelemetryPayload(
        device_id=device_id,
        timestamp=timestamp,
        sequence=sequence,
        temperature_c=temperature,
        vibration_mm_s=2,
    )
    fields = payload_fields(payload)
    fields["signature"] = sign_payload(payload, key=KEY).signature
    return json.dumps(fields)


def validator(state):
    return TelemetryValidator(keys={"sensor-01": KEY}, state=state)


def test_repeated_and_lower_sequences_are_rejected(tmp_path):
    with ReplayState(tmp_path / "state.sqlite") as state:
        receiver = validator(state)
        assert receiver.validate(wire(sequence=5), now=NOW).status == "accepted"
        for sequence in (5, 4):
            assert receiver.validate(wire(sequence=sequence), now=NOW).reason == (
                "replay_or_out_of_order"
            )


def test_replay_is_rejected_after_reopening_store(tmp_path):
    path = tmp_path / "state.sqlite"
    with ReplayState(path) as state:
        assert validator(state).validate(wire(), now=NOW).status == "accepted"
    with ReplayState(path) as state:
        assert validator(state).validate(wire(), now=NOW).reason == (
            "replay_or_out_of_order"
        )


def test_invalid_signature_does_not_advance_state(tmp_path):
    modified = json.loads(wire(sequence=100))
    modified["temperature_c"] = 90
    with ReplayState(tmp_path / "state.sqlite") as state:
        receiver = validator(state)
        assert receiver.validate(json.dumps(modified), now=NOW).reason == (
            "invalid_signature"
        )
        assert receiver.validate(wire(sequence=1), now=NOW).status == "accepted"


@pytest.mark.parametrize(
    ("offset", "reason"),
    [(-301, "stale_timestamp"), (31, "future_timestamp")],
)
def test_invalid_timestamp_does_not_advance_state(tmp_path, offset, reason):
    with ReplayState(tmp_path / "state.sqlite") as state:
        receiver = validator(state)
        result = receiver.validate(
            wire(sequence=100, timestamp=NOW + timedelta(seconds=offset)),
            now=NOW,
        )
        assert result.reason == reason
        assert receiver.validate(wire(sequence=1), now=NOW).status == "accepted"


@pytest.mark.parametrize("offset", [-300, 30])
def test_timestamp_boundaries_are_inclusive(tmp_path, offset):
    with ReplayState(tmp_path / "state.sqlite") as state:
        result = validator(state).validate(
            wire(timestamp=NOW + timedelta(seconds=offset)), now=NOW
        )
        assert result.status == "accepted"


def test_unknown_device_is_rejected(tmp_path):
    with ReplayState(tmp_path / "state.sqlite") as state:
        assert (
            validator(state).validate(wire(device_id="unknown"), now=NOW).reason
            == "unknown_device"
        )


def test_authenticated_unusual_measurement_is_separate(tmp_path):
    with ReplayState(tmp_path / "state.sqlite") as state:
        result = validator(state).validate(wire(temperature=100), now=NOW)
        assert result.status == "accepted"
        assert result.measurement_alerts == ("temperature_outside_lab_bounds",)


def test_closed_store_is_analysis_error(tmp_path):
    state = ReplayState(tmp_path / "state.sqlite")
    receiver = validator(state)
    state.close()
    result = receiver.validate(wire(), now=NOW)
    assert result.status == "error"
    assert result.reason == "storage_failure"


def test_two_connections_share_committed_state(tmp_path):
    path = tmp_path / "state.sqlite"
    with ReplayState(path) as first, ReplayState(path) as second:
        assert first.accept_if_new("sensor-01", 1)
        assert not second.accept_if_new("sensor-01", 1)
        assert second.accept_if_new("sensor-01", 2)
        assert not first.accept_if_new("sensor-01", 2)


def test_invalid_input_is_rejected(tmp_path):
    with ReplayState(tmp_path / "state.sqlite") as state:
        result = validator(state).validate("{", now=NOW)
        assert result.reason == "invalid_input"
