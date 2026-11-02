import json
import sys
import requests

OLLAMA_URL = "http://localhost:11434/api/chat"
MODEL = "qwen2.5:3b"

SYSTEM_PROMPT = """You are a SOC triage assistant. You receive a security event as JSON.
You MUST respond ONLY with a JSON object with this exact schema:
{
  "verdict": "malicious" | "suspicious" | "benign",
  "severity": "critical" | "high" | "medium" | "low",
  "reason": "short explanation (max 2 sentences)"
}
No markdown, no prose, no extra keys."""


def triage(event: dict) -> dict:
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
    content = r.json()["message"]["content"]
    return json.loads(content)


if __name__ == "__main__":
    raw = sys.stdin.read() if not sys.stdin.isatty() else None
    if not raw:
        raw = '{"event_type":"email","sender":"ceo@evil-domain.tld","subject":"Urgent invoice","attachment":"invoice.exe"}'
    event = json.loads(raw)
    result = triage(event)
    print(json.dumps(result, indent=2))