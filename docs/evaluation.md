# Evaluation

## Protocol

Ten independently specified scenarios are generated in a fixed order.
The manifest holds expected decisions separately from incoming messages.
Input SHA-256 and evaluation time are recorded.

Evaluation time: 2026-01-01T00:00:00+00:00.
Default maximum age: 300 seconds.
Default future tolerance: 30 seconds.
Timestamp boundary values are accepted.

## Observed First Execution

| Reason | Count |
| --- | ---: |
| Authenticated new message | 2 |
| Invalid signature | 2 |
| Unknown device | 1 |
| Replay or out-of-order | 2 |
| Stale timestamp | 1 |
| Future timestamp | 1 |
| Invalid input | 1 |

One accepted message generated a temperature measurement alert.

## Observed Second Execution

The same ten messages were processed with the same persistent state.
All ten were rejected, including four replay or out-of-order decisions.
Other rejection reasons retained their first-run counts.

## Tested Properties

The local suite passed 50 tests, covering:

- Explicit canonical representation and signature verification.
- Payload tampering and wrong-key rejection.
- Strict parsing and registry validation.
- Rejected signature/timestamp messages not advancing state.
- State persistence across reopening and separate CLI executions.
- Two connections observing committed sequence state.
- Storage failure remaining an explicit analysis error.
- Authenticated unusual measurements receiving separate alerts.
- Output collision rejection before state creation.

The two-connection test is sequential, not a concurrent stress test.
No throughput, latency ceiling or production reliability is claimed.

## Interpretation and Future Measurements

These deterministic fixtures assess specified software behavior.
They are insufficient to estimate real-world precision or recall.

For performance evaluation, define message counts and device distributions,
record hardware and Python versions, repeat measurements, and report
latency distributions, peak memory and storage contention.

Measure failure recovery separately from normal execution.
