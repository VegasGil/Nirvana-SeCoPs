"""Valida que VERDICT_SCHEMA rechaza outputs inválidos del modelo."""
import json

import pytest
from jsonschema import ValidationError, validate

from bot1_cerebro.config import VERDICT_SCHEMA


def _validate(payload: dict):
    validate(instance=payload, schema=VERDICT_SCHEMA)


def test_happy_path():
    _validate({
        "verdict": "malicious", 
        "severity": "high", 
        "mitre_technique": "T1059: Command and Scripting Interpreter",
        "reason": "invoice.exe from external domain",
        "dfir_actions": "Isolate host, block sender.",
        "recommendation": "Isolate the host and block the sender."
    })


def test_enum_invalid():
    with pytest.raises(ValidationError):
        _validate({"verdict": "evil", "severity": "high", "reason": "bad enum"})


def test_extra_key():
    with pytest.raises(ValidationError):
        _validate({"verdict": "benign", "severity": "low", "reason": "ok", "extra": 1})


def test_missing_key():
    with pytest.raises(ValidationError):
        _validate({"verdict": "benign", "severity": "low"})


def test_empty_reason():
    with pytest.raises(ValidationError):
        _validate({"verdict": "benign", "severity": "low", "reason": ""})