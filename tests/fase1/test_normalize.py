"""Valida normalize_event: defaults, descarte de claves desconocidas, rechazo de no-dict."""
import pytest

from fase1_cerebro.event_schema import normalize_event


def test_defaults_applied():
    out = normalize_event({
        "event_id": "x", "source": "email",
        "timestamp": "2026-11-03T00:00:00Z", "summary": "test",
    })
    assert out["src"] == "unknown"
    assert out["dst"] == "unknown"
    assert out["iocs"] == []
    assert out["raw"] == {}


def test_unknown_keys_dropped():
    out = normalize_event({
        "event_id": "x", "source": "email",
        "timestamp": "2026-11-03T00:00:00Z", "summary": "test",
        "hacker_field": "should disappear",
    })
    assert "hacker_field" not in out


def test_not_a_dict():
    with pytest.raises(ValueError):
        normalize_event("not a dict")