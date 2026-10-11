"""Authenticate telemetry before advancing persistent replay state."""

import sqlite3
from dataclasses import dataclass
from datetime import datetime

from iot_security.models import DEVICE_PATTERN
from iot_security.parsing import parse_message
from iot_security.signing import verify_signature
from iot_security.state import ReplayState


@dataclass(frozen=True)
class ValidationPolicy:
    max_age_seconds: int = 300
    max_future_seconds: int = 30

    def __post_init__(self):
        for value in (self.max_age_seconds, self.max_future_seconds):
            if type(value) is not int or not 0 <= value <= 86_400:
                raise ValueError("Invalid timestamp tolerance.")


@dataclass(frozen=True)
class ValidationDecision:
    status: str
    reason: str
    device_id: str | None = None
    sequence: int | None = None
    measurement_alerts: tuple[str, ...] = ()


class TelemetryValidator:
    def __init__(
        self,
        *,
        keys: dict[str, bytes],
        state: ReplayState,
        policy: ValidationPolicy = ValidationPolicy(),
    ):
        if not isinstance(keys, dict) or not keys:
            raise ValueError("A non-empty device registry is required.")
        for device_id, key in keys.items():
            if (
                not isinstance(device_id, str)
                or not DEVICE_PATTERN.fullmatch(device_id)
                or type(key) is not bytes
                or not 32 <= len(key) <= 64
            ):
                raise ValueError("Invalid device registry.")
        if not isinstance(state, ReplayState):
            raise ValueError("A replay-state store is required.")
        if not isinstance(policy, ValidationPolicy):
            raise ValueError("A validated policy is required.")
        self._keys = dict(keys)
        self._state = state
        self._policy = policy

    def validate(self, text: str, *, now: datetime) -> ValidationDecision:
        if (
            not isinstance(now, datetime)
            or now.tzinfo is None
            or now.utcoffset() is None
        ):
            raise ValueError("Evaluation clock must be timezone-aware.")
        try:
            message = parse_message(text)
        except ValueError:
            return ValidationDecision("rejected", "invalid_input")

        payload = message.payload

        def decision(status, reason, alerts=()):
            return ValidationDecision(
                status, reason, payload.device_id, payload.sequence, alerts
            )

        key = self._keys.get(payload.device_id)
        if key is None:
            return decision("rejected", "unknown_device")
        if not verify_signature(message, key=key):
            return decision("rejected", "invalid_signature")

        age = (now - payload.timestamp).total_seconds()
        if age > self._policy.max_age_seconds:
            return decision("rejected", "stale_timestamp")
        if age < -self._policy.max_future_seconds:
            return decision("rejected", "future_timestamp")

        try:
            is_new = self._state.accept_if_new(payload.device_id, payload.sequence)
        except sqlite3.Error:
            return decision("error", "storage_failure")
        if not is_new:
            return decision("rejected", "replay_or_out_of_order")

        alerts = []
        if not -40 <= payload.temperature_c <= 85:
            alerts.append("temperature_outside_lab_bounds")
        if not 0 <= payload.vibration_mm_s <= 10:
            alerts.append("vibration_outside_lab_bounds")

        return decision("accepted", "authenticated_new_message", tuple(alerts))
