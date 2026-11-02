from jsonschema import validate, ValidationError

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "event_id": {"type": "string"},
        "source": {"type": "string"},
        "timestamp": {"type": "string"},
        "summary": {"type": "string"}
    },
    "required": ["event_id", "source", "timestamp", "summary"]
}

def normalize_event(raw_event):
    # Rellena campos por defecto si faltan
    if "summary" not in raw_event:
        raw_event["summary"] = raw_event.get("_raw", "No summary")[:500]
    return raw_event
