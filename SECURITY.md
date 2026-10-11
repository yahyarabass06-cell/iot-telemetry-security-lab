# Security Considerations

## Authorized Use

Use synthetic or explicitly authorized telemetry.
No live devices or industrial actuation are part of this laboratory.

## Demonstration Keys

The bundled keys are public fixtures.
They provide no real security against anyone who can access the repository.

The registry loader deliberately accepts demonstration configuration only.
Production provisioning, secret storage and key rotation are out of scope.

## Message Trust

HMAC authenticates possession of a shared key, not sensor truth.
A compromised key allows forged telemetry.
Payloads are not encrypted.

The canonical representation is specific to this laboratory.
Interoperating producers must implement its exact versioned representation.

## Persistent State

Protect the SQLite database and its parent directory.
Do not delete, replace or roll back state to bypass sequence rejection.

Strict ordering can reject legitimate delayed messages.
Device sequence resets require an explicit reviewed workflow.

Accepted state updates remain committed after later output failures.
The tool must not promise atomicity between the database and report export.

## Clock and Input Trust

The CLI evaluation time is for fixture replay.
Production validation requires an independently trusted clock.

Input and registry files must remain stable during analysis.
Input hashes do not prove authenticity.

## Filesystem and Reports

Run with ordinary user privileges in directories you control.
Path checks do not prevent races in attacker-controlled directories.

SQLite permissions depend on the host configuration.
Reports use owner-only temporary files and exclusive hard-link publication.

Do not commit real keys, private telemetry, databases or generated reports.

## Reporting Issues

Provide minimized synthetic reproductions without secrets or device identifiers
from confidential environments.
