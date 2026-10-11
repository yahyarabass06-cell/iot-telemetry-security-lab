"""Validate public demonstration registry boundaries."""

import json

import pytest

from iot_security.configuration import load_demo_registry


@pytest.fixture
def registry():
    return {
        "schema_version": 1,
        "key_purpose": "public_synthetic_demo_only",
        "devices": [
            {
                "device_id": "sensor-01",
                "key_hex": bytes(range(32)).hex(),
            }
        ],
    }


def test_demo_registry_loads(tmp_path, registry):
    path = tmp_path / "devices.json"
    path.write_text(json.dumps(registry))
    assert load_demo_registry(path) == {"sensor-01": bytes(range(32))}


@pytest.mark.parametrize("change", ["purpose", "duplicate", "short_key", "extra"])
def test_invalid_registry_is_rejected(tmp_path, registry, change):
    if change == "purpose":
        registry["key_purpose"] = "production"
    elif change == "duplicate":
        registry["devices"].append(dict(registry["devices"][0]))
    elif change == "short_key":
        registry["devices"][0]["key_hex"] = "ab"
    else:
        registry["unexpected"] = True

    path = tmp_path / "devices.json"
    path.write_text(json.dumps(registry))
    with pytest.raises(ValueError):
        load_demo_registry(path)
