"""Fase 1: Cerebro del SOC. Recibe evento canónico, consulta a Ollama, devuelve veredicto validado."""

import json
import logging
import time

import requests
from jsonschema import ValidationError, validate

# Importamos la configuración centralizada
from bot1_cerebro.config import OLLAMA_URL, MODEL, SYSTEM_PROMPT, VERDICT_SCHEMA

log = logging.getLogger("soc_assistant")

MAX_RETRIES = 3
BACKOFF_BASE = 1.5


def _call_ollama(event: dict) -> str:
    payload = {
        "model": MODEL,
        "format": "json",
        "stream": False,
        "options": {"temperature": 0},
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(event)},
        ],
    }
    r = requests.post(OLLAMA_URL, json=payload, timeout=120)
    r.raise_for_status()
    return r.json()["message"]["content"]


def triage(event: dict) -> dict:
    """Llama a Ollama con retries + backoff. Devuelve dict validado o lanza RuntimeError."""
    last_error = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            raw = _call_ollama(event)
            parsed = json.loads(raw)
            validate(instance=parsed, schema=VERDICT_SCHEMA)
            log.info("Triage OK on attempt %d", attempt)
            return parsed
        except (json.JSONDecodeError, ValidationError, requests.RequestException) as e:
            last_error = e
            log.warning("Attempt %d/%d failed: %s", attempt, MAX_RETRIES, e)
            if attempt < MAX_RETRIES:
                time.sleep(BACKOFF_BASE ** attempt)
    raise RuntimeError(f"Triage failed after {MAX_RETRIES} attempts: {last_error}")