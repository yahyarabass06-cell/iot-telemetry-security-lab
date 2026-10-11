"""Publish complete local reports without replacing existing files."""

import os
import tempfile
from pathlib import Path


def write_new_report(destination: Path, content: str) -> None:
    """Publish an owner-only report using an exclusive hard link."""
    destination = Path(destination)
    temporary = None

    try:
        descriptor, name = tempfile.mkstemp(
            prefix=".flow-report-",
            suffix=".tmp",
            dir=destination.parent,
        )
        temporary = Path(name)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())

        os.link(temporary, destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
