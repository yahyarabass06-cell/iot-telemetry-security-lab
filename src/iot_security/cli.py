"""Offline validation of synthetic telemetry with persistent replay state."""

import argparse
import hashlib
import json
import sqlite3
import sys
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from iot_security.configuration import load_demo_registry
from iot_security.exporting import write_new_report
from iot_security.state import ReplayState
from iot_security.validation import TelemetryValidator, ValidationPolicy

MAX_INPUT_BYTES = 1_000_000
MAX_INPUT_RECORDS = 1_000


def evaluation_time(value):
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError
        return parsed.astimezone(timezone.utc)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "Use an ISO timestamp with an explicit timezone."
        ) from exc


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--registry", required=True, type=Path)
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--evaluation-time", required=True, type=evaluation_time)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)

    try:
        paths = [args.input, args.registry, args.state]
        if args.output is not None:
            paths.append(args.output)
        resolved = [path.resolve() for path in paths]
        if len(set(resolved)) != len(resolved):
            raise ValueError("Input, registry, state and output must differ.")
        if args.output is not None:
            if args.output.exists() or args.output.is_symlink():
                raise FileExistsError("Output already exists.")
            if not args.output.parent.is_dir():
                raise ValueError("Output directory must exist.")
        if args.state.is_symlink():
            raise ValueError("State must not be a symbolic link.")

        keys = load_demo_registry(args.registry)
        with args.input.open("rb") as source:
            raw = source.read(MAX_INPUT_BYTES + 1)
        if len(raw) > MAX_INPUT_BYTES:
            raise ValueError("Input exceeds the byte limit.")
        lines = raw.decode("utf-8").splitlines()
        if not 1 <= len(lines) <= MAX_INPUT_RECORDS:
            raise ValueError("Invalid input record count.")

        policy = ValidationPolicy()
        decisions = []
        with ReplayState(args.state) as state:
            receiver = TelemetryValidator(keys=keys, state=state, policy=policy)
            for number, line in enumerate(lines, 1):
                decision = receiver.validate(line, now=args.evaluation_time)
                decisions.append({"line_number": number, **asdict(decision)})
                if decision.status == "error":
                    break

        complete = len(decisions) == len(lines) and all(
            decision["status"] != "error" for decision in decisions
        )
        report = {
            "schema_version": 1,
            "analysis_status": "complete" if complete else "incomplete",
            "evaluation_time": args.evaluation_time.isoformat(),
            "evaluation_time_source": "explicit_lab_replay",
            "input": {
                "file_name": args.input.name,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "size_bytes": len(raw),
                "records": len(lines),
            },
            "configuration": {
                "key_purpose": "public_synthetic_demo_only",
                "registered_devices": sorted(keys),
                "timestamp_policy": asdict(policy),
                "state_file": args.state.name,
                "measurement_lab_bounds": {
                    "temperature_c": [-40, 85],
                    "vibration_mm_s": [0, 10],
                },
            },
            "summary": {
                "processed": len(decisions),
                "by_status": dict(Counter(d["status"] for d in decisions)),
                "by_reason": dict(Counter(d["reason"] for d in decisions)),
                "measurement_alert_records": sum(
                    bool(d["measurement_alerts"]) for d in decisions
                ),
            },
            "decisions": decisions,
            "limitations": [
                "Demonstration keys are public and provide no real trust.",
                "Explicit evaluation time is for laboratory replay.",
                "Accepted state updates are not rolled back on export failure.",
                "HMAC does not prove measurement truth or confidentiality.",
            ],
        }
        content = json.dumps(report, indent=2, allow_nan=False) + "\n"
        if args.output is None:
            sys.stdout.write(content)
        else:
            write_new_report(args.output, content)
            print("Report saved.", file=sys.stderr)
        return 0 if complete else 2

    except (OSError, ValueError, sqlite3.Error) as exc:
        print(
            f"Analysis failed ({type(exc).__name__}). "
            "Previously committed replay state may remain.",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
