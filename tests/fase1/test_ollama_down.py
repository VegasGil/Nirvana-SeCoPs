"""Simula Ollama caido: triage() debe agotar retries y lanzar RuntimeError."""
import pytest
import bot1_cerebro.soc_assistant as sa
import bot1_cerebro.ai_providers as ai

def test_ollama_down_raises_runtime_error(monkeypatch):
    # Forzamos a que use Ollama y que falle la URL
    monkeypatch.setenv("AI_PROVIDER", "ollama")
    monkeypatch.setattr(ai, "OLLAMA_URL", "http://127.0.0.1:1/api/chat")
    monkeypatch.setattr(sa.time, "sleep", lambda *_: None)

    # Re-instanciamos el engine para que tome la URL falsa
    sa.ai_engine = ai.OllamaAI()

    with pytest.raises(RuntimeError, match="Triage failed after 3 attempts"):
        sa.triage({"event_type": "email", "sender": "ceo@evil.tld"})