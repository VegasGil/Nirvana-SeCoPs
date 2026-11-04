import pytest
from bot4_human_vector.email_parser import parse_eml, extract_iocs
from bot1_cerebro.event_schema import INPUT_SCHEMA
from jsonschema import validate

def test_extract_iocs():
    text = "Contacta a 192.168.1.1 y visita http://evil.com/malware.exe"
    iocs = extract_iocs(text)
    assert "192.168.1.1" in iocs
    assert "http://evil.com/malware.exe" in iocs

def test_parse_eml():
    # Usamos el archivo de prueba que ya tienes en data/samples
    event = parse_eml("data/samples/test_email.eml")
    
    # 1. Validar el esquema
    validate(instance=event, schema=INPUT_SCHEMA)
    
    # 2. Validar extracción
    assert event["source"] == "email"
    assert "hacker@evil-corp.com" in event["src"]
    assert "Factura urgente" in event["summary"]
    assert "192.168.1.100" in event["iocs"]