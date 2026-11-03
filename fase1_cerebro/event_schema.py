"""Contrato de entrada canónico para todos los eventos del pipeline Nirvana-SeCoPs."""

INPUT_SCHEMA = {
    "type": "object",
    "required": ["event_id", "source", "timestamp", "summary"],
    "additionalProperties": False,
    "properties": {
        "event_id": {"type": "string", "minLength": 1},
        "source": {"enum": ["email", "network", "endpoint", "manual"]},
        "timestamp": {"type": "string", "minLength": 10},
        "src": {"type": "string"},
        "dst": {"type": "string"},
        "summary": {"type": "string", "minLength": 3, "maxLength": 500},
        "iocs": {"type": "array", "items": {"type": "string"}, "maxItems": 50},
        "raw": {"type": "object"},
    },
}

DEFAULTS = {
    "src": "unknown",
    "dst": "unknown",
    "iocs": [],
    "raw": {},
}


def normalize_event(event: dict) -> dict:
    """Rellena defaults, descarta claves desconocidas, devuelve evento canónico."""
    if not isinstance(event, dict):
        raise ValueError("event must be a dict")
    canonical = {k: event[k] for k in INPUT_SCHEMA["properties"] if k in event}
    for k, v in DEFAULTS.items():
        canonical.setdefault(k, v)
    return canonical