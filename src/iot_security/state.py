"""Transactional persistent sequence tracking."""

import sqlite3
from pathlib import Path

from iot_security.models import DEVICE_PATTERN, MAX_SEQUENCE


class ReplayState:
    """Persist the greatest accepted sequence for each device."""

    def __init__(self, path: Path):
        self._connection = sqlite3.connect(str(path), timeout=5, isolation_level=None)
        try:
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS device_sequences (
                    device_id TEXT PRIMARY KEY,
                    sequence INTEGER NOT NULL CHECK(sequence >= 0)
                )
                """
            )
        except sqlite3.Error:
            self._connection.close()
            raise

    def accept_if_new(self, device_id: str, sequence: int) -> bool:
        if (
            not isinstance(device_id, str)
            or not DEVICE_PATTERN.fullmatch(device_id)
            or type(sequence) is not int
            or not 0 <= sequence <= MAX_SEQUENCE
        ):
            raise ValueError("Invalid replay-state input.")

        self._connection.execute("BEGIN IMMEDIATE")
        try:
            row = self._connection.execute(
                "SELECT sequence FROM device_sequences WHERE device_id = ?",
                (device_id,),
            ).fetchone()
            if row is not None and sequence <= row[0]:
                self._connection.execute("ROLLBACK")
                return False

            self._connection.execute(
                """
                INSERT INTO device_sequences(device_id, sequence)
                VALUES (?, ?)
                ON CONFLICT(device_id)
                DO UPDATE SET sequence = excluded.sequence
                """,
                (device_id, sequence),
            )
            self._connection.execute("COMMIT")
            return True
        except BaseException:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise

    def close(self):
        self._connection.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
