"""Proveedores de IA: Ollama, Mock (Demo) y preparado para OpenAI."""
import os
import json
import logging
import requests
import jsonschema
from bot1_cerebro.config import OLLAMA_URL, MODEL, SYSTEM_PROMPT, VERDICT_SCHEMA

log = logging.getLogger("ai_providers")

class BaseAI:
    def generate_verdict(self, event_text: str) -> dict:
        raise NotImplementedError

class OllamaAI(BaseAI):
    def generate_verdict(self, event_text: str) -> dict:
        payload = {
            "model": MODEL, "format": "json", "stream": False,
            "options": {"temperature": 0},
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT}, 
                {"role": "user", "content": event_text}
            ],
        }
        # Petición a Ollama
        r = requests.post(OLLAMA_URL, json=payload, timeout=120)
        r.raise_for_status()
        result = json.loads(r.json()["message"]["content"])
        
        # Validación estricta del JSON
        jsonschema.validate(instance=result, schema=VERDICT_SCHEMA)
        return result

class MockAI(BaseAI):
    """IA Falsa para Demos en computadoras sin GPU."""
    def generate_verdict(self, event_text: str) -> dict:
        log.info("🤖 [MOCK AI] Simulando análisis de IA...")
        is_malicious = any(x in event_text.lower() for x in ["vssadmin", "xmrig", "or 1=1", "/dev/tcp", "powershell"])
        
        if is_malicious:
            return {
                "verdict": "malicious", "severity": "high",
                "mitre_technique": "T1059: Command and Scripting Interpreter",
                "reason": "Mocked response: The event contains suspicious patterns indicating a malicious payload.",
                "recommendation": "Mocked response: Block the IP and isolate the host."
            }
        return {
            "verdict": "benign", "severity": "low", "mitre_technique": "N/A",
            "reason": "Mocked response: Normal traffic.", "recommendation": "Ignore."
        }

def get_ai_provider() -> BaseAI:
    """Fábrica que decide qué IA usar basándose en el .env"""
    provider = os.getenv("AI_PROVIDER", "ollama").lower()
    if provider == "mock":
        return MockAI()
    return OllamaAI()