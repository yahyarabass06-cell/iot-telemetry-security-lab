"""HMAC-SHA256 with a documented laboratory canonical representation."""

import hashlib
import hmac
import json

from iot_security.models import SignedTelemetry, TelemetryPayload

DOMAIN_PREFIX = b"iot-telemetry-security-lab:v1\n"


def payload_fields(payload: TelemetryPayload) -> dict:
    if not isinstance(payload, TelemetryPayload):
        raise ValueError("A validated payload is required.")
    return {
        "schema_version": 1,
        "device_id": payload.device_id,
        "timestamp": payload.timestamp.isoformat(timespec="microseconds"),
        "sequence": payload.sequence,
        "temperature_c": payload.temperature_c,
        "vibration_mm_s": payload.vibration_mm_s,
    }


def canonical_bytes(payload: TelemetryPayload) -> bytes:
    encoded = json.dumps(
        payload_fields(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return DOMAIN_PREFIX + encoded


def _validate_key(key: bytes) -> None:
    if type(key) is not bytes or not 32 <= len(key) <= 64:
        raise ValueError("Key must contain 32-64 bytes.")


def sign_payload(payload: TelemetryPayload, *, key: bytes) -> SignedTelemetry:
    _validate_key(key)
    signature = hmac.new(key, canonical_bytes(payload), hashlib.sha256).hexdigest()
    return SignedTelemetry(payload=payload, signature=signature)


def verify_signature(message: SignedTelemetry, *, key: bytes) -> bool:
    _validate_key(key)
    if not isinstance(message, SignedTelemetry):
        raise ValueError("A validated signed message is required.")
    expected = hmac.new(
        key, canonical_bytes(message.payload), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, message.signature)
