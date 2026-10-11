"""Verify CLI reports, persistent replay and output collision behavior."""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def run_cli(state, *extra):
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "iot_security.cli",
            "--input",
            str(ROOT / "data/synthetic/v1/messages.jsonl"),
            "--registry",
            str(ROOT / "config/devices-demo.json"),
            "--state",
            str(state),
            "--evaluation-time",
            "2026-01-01T00:00:00+00:00",
            *extra,
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def test_fresh_state_matches_fixture_and_second_run_rejects_replay(tmp_path):
    state = tmp_path / "state.sqlite"
    first = run_cli(state)
    assert first.returncode == 0
    report = json.loads(first.stdout)
    assert report["analysis_status"] == "complete"
    assert report["summary"]["by_status"] == {"accepted": 2, "rejected": 8}
    assert report["summary"]["measurement_alert_records"] == 1

    second = run_cli(state)
    assert second.returncode == 0
    replay = json.loads(second.stdout)
    assert replay["summary"]["by_status"] == {"rejected": 10}
    assert replay["summary"]["by_reason"]["replay_or_out_of_order"] == 4


def test_exported_report_is_complete(tmp_path):
    output = tmp_path / "report.json"
    result = run_cli(tmp_path / "state.sqlite", "--output", str(output))
    assert result.returncode == 0
    assert result.stdout == ""
    assert json.loads(output.read_text())["summary"]["processed"] == 10


def test_existing_output_does_not_create_state(tmp_path):
    output = tmp_path / "report.json"
    state = tmp_path / "state.sqlite"
    output.write_text("original")
    result = run_cli(state, "--output", str(output))
    assert result.returncode == 2
    assert result.stdout == ""
    assert output.read_text() == "original"
    assert not state.exists()


def test_naive_evaluation_time_is_rejected(tmp_path):
    result = run_cli(
        tmp_path / "state.sqlite",
        "--evaluation-time",
        "2026-01-01T00:00:00",
    )
    assert result.returncode == 2
    assert result.stdout == ""
