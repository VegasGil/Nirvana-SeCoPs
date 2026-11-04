"""Configuración centralizada del Cerebro (Fase 1)."""
import os
from dotenv import load_dotenv

load_dotenv()

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/api/chat")
MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:3b")

SYSTEM_PROMPT = """You are an expert Senior SOC Analyst. You receive a security event.
You MUST respond ONLY with a JSON object with this exact schema:
{
  "verdict": "malicious" | "suspicious" | "benign",
  "severity": "critical" | "high" | "medium" | "low",
  "mitre_technique": "Just the MITRE ID and Name (e.g., T1490: Inhibit System Recovery)",
  "reason": "Detailed explanation of why (max 4 sentences). Mention specific IOCs if present.",
  "recommendation": "Actionable next step for the SOC team (e.g., Block IP, Isolate host, Ignore)."
}

CRITICAL RULES:
- Ransomware (e.g., 'vssadmin delete shadows') -> ALWAYS malicious, MITRE T1490.
- Cryptojacking (e.g., 'xmrig') -> ALWAYS malicious, MITRE T1496.
- Reverse shells (e.g., '/dev/tcp/', 'nc -e') -> ALWAYS malicious, MITRE T1059.
- SQL Injection (e.g., 'OR 1=1') -> ALWAYS malicious, MITRE T1190.
- PowerShell downloading from the internet -> ALWAYS malicious, MITRE T1059.001.
- Brute Force (e.g., 'Failed password') -> ALWAYS suspicious, MITRE T1110.
- Normal HTTP traffic -> ALWAYS benign, MITRE N/A.

CRITICAL FORMATTING RULE: 
For the "mitre_technique" field, output ONLY the technique ID and Name. 
DO NOT include the text "MITRE ATT&CK ID and Name" or "e.g." in your response.
"""

VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"enum": ["malicious", "suspicious", "benign"]},
        "severity": {"enum": ["critical", "high", "medium", "low"]},
        "mitre_technique": {"type": "string", "minLength": 3, "maxLength": 100},
        "reason": {"type": "string", "minLength": 3, "maxLength": 500},
        "recommendation": {"type": "string", "minLength": 3, "maxLength": 500}
    },
    "required": ["verdict", "severity", "mitre_technique", "reason", "recommendation"],
    "additionalProperties": False
}