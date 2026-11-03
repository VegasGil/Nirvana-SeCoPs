"""Simula Ollama caído: triage() debe agotar retries y lanzar RuntimeError."""
import pytest

import bot1_cerebro.soc_assistant as sa


def test_ollama_down_raises_runtime_error(monkeypatch):
    monkeypatch.setattr(sa, "OLLAMA_URL", "http://127.0.0.1:1/api/chat")
    monkeypatch.setattr(sa.time, "sleep", lambda *_: None)  # no esperar en tests

    with pytest.raises(RuntimeError, match="Triage failed after 3 attempts"):
        sa.triage({"event_type": "email", "sender": "ceo@evil.tld"})