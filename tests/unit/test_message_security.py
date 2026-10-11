"""Verify canonical representation, tampering and strict parsing."""

import hashlib
import hmac
import json
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone

import pytest

from iot_security.models import TelemetryPayload
from iot_security.parsing import parse_message
from iot_security.signing import (
    canonical_bytes,
    payload_fields,
    sign_payload,
    verify_signature,
)

# Public synthetic test keys; never reuse in production.
KEY = bytes(range(32))
OTHER_KEY = bytes(range(1, 33))


@pytest.fixture
def payload():
    return TelemetryPayload(
        device_id="sensor-01",
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        sequence=1,
        temperature_c=25,
        vibration_mm_s=2,
    )


def test_canonical_representation_is_explicit(payload):
    expected = (
        b"iot-telemetry-security-lab:v1\n"
        b'{"device_id":"sensor-01","schema_version":1,"sequence":1,'
        b'"temperature_c":25.0,'
        b'"timestamp":"2026-01-01T00:00:00.000000+00:00",'
        b'"vibration_mm_s":2.0}'
    )
    assert canonical_bytes(payload) == expected
    signature = hmac.new(KEY, expected, hashlib.sha256).hexdigest()
    assert sign_payload(payload, key=KEY).signature == signature


def test_valid_signature_and_wrong_key(payload):
    message = sign_payload(payload, key=KEY)
    assert verify_signature(message, key=KEY)
    assert not verify_signature(message, key=OTHER_KEY)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("device_id", "sensor-02"),
        ("sequence", 2),
        ("temperature_c", 80),
        ("vibration_mm_s", 20),
        ("timestamp", datetime(2026, 1, 2, tzinfo=timezone.utc)),
    ],
)
def test_payload_tampering_invalidates_signature(payload, field, value):
    message = sign_payload(payload, key=KEY)
    changed = replace(message, payload=replace(payload, **{field: value}))
    assert not verify_signature(changed, key=KEY)


def test_equivalent_timezone_has_same_canonical_bytes(payload):
    shifted = replace(
        payload,
        timestamp=payload.timestamp.astimezone(timezone(timedelta(hours=2))),
    )
    assert canonical_bytes(shifted) == canonical_bytes(payload)


def test_signed_message_round_trip(payload):
    message = sign_payload(payload, key=KEY)
    fields = payload_fields(payload)
    fields["signature"] = message.signature
    parsed = parse_message(json.dumps(fields))
    assert parsed == message
    assert verify_signature(parsed, key=KEY)


def test_payload_is_immutable(payload):
    with pytest.raises(FrozenInstanceError):
        payload.sequence = 2


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("device_id", "../sensor"),
        ("timestamp", datetime(2026, 1, 1)),
        ("sequence", True),
        ("sequence", -1),
        ("sequence", 2**63),
        ("temperature_c", float("nan")),
        ("temperature_c", True),
        ("vibration_mm_s", float("inf")),
        ("vibration_mm_s", 1_000_001),
    ],
)
def test_invalid_payload_is_rejected(payload, field, value):
    with pytest.raises(ValueError):
        replace(payload, **{field: value})


@pytest.mark.parametrize("key", [b"", b"x" * 31, b"x" * 65, "not-bytes"])
def test_invalid_key_is_rejected(payload, key):
    with pytest.raises(ValueError):
        sign_payload(payload, key=key)


@pytest.mark.parametrize(
    "text",
    [
        "{",
        '{"schema_version": 1, "schema_version": 1}',
        '{"schema_version": NaN}',
        "[]",
        "x" * 4097,
    ],
)
def test_invalid_json_is_rejected(text):
    with pytest.raises(ValueError):
        parse_message(text)
