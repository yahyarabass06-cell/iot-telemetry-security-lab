"""Validated immutable telemetry messages."""

import math
import re
from dataclasses import dataclass
from datetime import datetime, timezone

MAX_SEQUENCE = 2**63 - 1
DEVICE_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
SIGNATURE_PATTERN = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class TelemetryPayload:
    device_id: str
    timestamp: datetime
    sequence: int
    temperature_c: float
    vibration_mm_s: float

    def __post_init__(self):
        if not isinstance(self.device_id, str) or not DEVICE_PATTERN.fullmatch(
            self.device_id
        ):
            raise ValueError("Invalid device identifier.")
        if (
            not isinstance(self.timestamp, datetime)
            or self.timestamp.tzinfo is None
            or self.timestamp.utcoffset() is None
        ):
            raise ValueError("Timestamp must be timezone-aware.")
        object.__setattr__(self, "timestamp", self.timestamp.astimezone(timezone.utc))
        if type(self.sequence) is not int or not 0 <= self.sequence <= MAX_SEQUENCE:
            raise ValueError("Sequence is outside supported integer bounds.")

        for field in ("temperature_c", "vibration_mm_s"):
            value = getattr(self, field)
            if type(value) not in (int, float):
                raise ValueError("Measurements must be numeric.")
            try:
                normalized = float(value)
            except OverflowError as exc:
                raise ValueError("Measurement exceeds numeric bounds.") from exc
            if not math.isfinite(normalized) or abs(normalized) > 1_000_000:
                raise ValueError("Measurement is non-finite or too large.")
            # Normalize negative zero to avoid two encodings of zero.
            object.__setattr__(self, field, normalized if normalized else 0.0)


@dataclass(frozen=True)
class SignedTelemetry:
    payload: TelemetryPayload
    signature: str

    def __post_init__(self):
        if not isinstance(self.payload, TelemetryPayload):
            raise ValueError("A validated payload is required.")
        if not isinstance(self.signature, str) or not SIGNATURE_PATTERN.fullmatch(
            self.signature
        ):
            raise ValueError("Signature must contain 64 lowercase hex digits.")
