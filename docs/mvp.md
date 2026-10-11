# MVP Scope and Threat Model

## Goal

Build a defensive laboratory for simulated IoT telemetry.
Validate message authenticity, detect replay and preserve auditable decisions.

No physical device, cloud account or live industrial system is required.

## Synthetic Message

Each message contains:

- Schema version.
- Device identifier.
- UTC timestamp.
- Monotonically increasing sequence number.
- Temperature and vibration measurements.
- HMAC-SHA256 signature over a documented canonical payload.

Keys are supplied separately through trusted laboratory configuration.
Documented demonstration keys are public test fixtures, not production secrets.

## Trust Boundaries

Device identifiers and timestamps in incoming messages are untrusted.
A device must be registered before its configured key is used.

Validate structure and resource limits before signature verification.
Verify signatures before updating replay state.
Use constant-time signature comparison.

Store accepted sequence state transactionally in SQLite.
Rejected messages must not advance that state.

## Security Decisions

Distinguish:

- Accepted authenticated message.
- Unknown device.
- Invalid signature.
- Replay or out-of-order sequence.
- Stale or excessively future timestamp.
- Invalid input.
- Storage or analysis failure.

Failures must never be reported as successful security validation.

## Measurement Decisions

Evaluate measurement bounds only after security validation.
An unusual measurement is not proof of an attack.

A compromised device possessing its key can sign fabricated measurements.
HMAC does not establish sensor truth or provide confidentiality.

## Replay Policy

The initial policy requires a strictly increasing per-device sequence.
This rejects delayed legitimate messages as well as repeated messages.

Device sequence resets require explicit administrative handling.
Do not silently reset state when an incoming sequence is lower.

The receiver uses a trusted evaluation clock with documented tolerance.
Timestamp checks do not replace persistent sequence tracking.

## Evaluation

Use independently defined synthetic scenarios:

- Valid message.
- Modified payload without a new signature.
- Incorrect signature.
- Unknown device.
- Repeated message.
- Out-of-order sequence.
- Replay after process restart.
- Stale and future timestamps.
- Authenticated unusual measurement.
- Invalid input and storage failure.

Measure classification outcomes, rejection reasons, state persistence
and processing latency. Do not invent detection or performance results.

## Boundaries

- Offline simulated telemetry in the initial version.
- No active scanning or device exploitation.
- No physical actuation or automatic industrial response.
- No production key provisioning or rotation.
- No claim of complete IoT security or industrial certification.

## Optional Extensions

- Local MQTT transport in an isolated laboratory.
- Controlled sequence-reset workflow.
- Key rotation with explicit compatibility rules.
- Statistical telemetry detection after baseline validation.
