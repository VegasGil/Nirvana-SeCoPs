"""Fase 1: Cerebro del SOC. Delega la IA al proveedor configurado."""
import logging
import time
from bot1_cerebro.ai_providers import get_ai_provider

log = logging.getLogger("soc_assistant")
MAX_RETRIES = 3
BACKOFF_BASE = 1.5

# Instanciamos el proveedor (Ollama o Mock)
ai_engine = get_ai_provider()

def triage(event: dict) -> dict:
    """Llama al proveedor de IA con retries + backoff."""
    event_text = str(event)
    last_error = None
    
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            # ¡Aquí ocurre la magia! No importa si es Ollama o Mock
            return ai_engine.generate_verdict(event_text)
        except Exception as e:
            last_error = e
            log.warning("Attempt %d/%d failed: %s", attempt, MAX_RETRIES, e)
            if attempt < MAX_RETRIES:
                time.sleep(BACKOFF_BASE ** attempt)
                
    raise RuntimeError(f"Triage failed after {MAX_RETRIES} attempts: {last_error}")