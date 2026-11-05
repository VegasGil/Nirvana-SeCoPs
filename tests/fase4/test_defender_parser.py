import json
import pytest
from bot5_endpoint.defender_parser import parse_defender_alert
from bot1_cerebro.event_schema import INPUT_SCHEMA
from jsonschema import validate

def test_parse_defender_alert():
    # Lee el archivo local que creamos en data/samples/
    with open("data/samples/defender_alert.json", "r") as f:
        raw_alert = json.load(f)

    event = parse_defender_alert(raw_alert)

    # Valida que el resultado cumpla con las reglas del proyecto
    validate(instance=event, schema=INPUT_SCHEMA)
    
    # Verifica que los datos se extrajeron bien
    assert event["source"] == "endpoint"
    assert "PC-VICTIMA-01" in event["src"]
    assert "Ransomware behavior detected" in event["summary"]