"""Configuración centralizada del Cerebro (Fase 1)."""
import os
from dotenv import load_dotenv

load_dotenv()

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/api/chat")
MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:3b")

SYSTEM_PROMPT = """You are an expert Senior SOC Analyst and DFIR (Digital Forensics and Incident Response) specialist.
You receive a security event. You MUST respond ONLY with a JSON object with this exact schema:
{
  "verdict": "malicious" | "suspicious" | "benign",
  "severity": "critical" | "high" | "medium" | "low",
  "mitre_technique": "Just the MITRE ID and Name (e.g., T1490: Inhibit System Recovery)",
  "reason": "Forensic explanation of why (max 3 sentences). DO NOT repeat the alert text. Explain the technical impact.",
  "dfir_actions": "Actionable DFIR steps separated by commas (e.g., Isolate host, check connections to port 4444, review cron).",
  "recommendation": "Immediate next step for the SOC team."
}

CRITICAL RULES:
- DO NOT COPY the alert description. Write your own forensic reasoning.
- If it's an Email with malicious attachments/URLs -> ALWAYS malicious (MITRE T1566).
- If it's an EDR alert (HackTool, Cryptominer, Ransomware) -> Focus on technical impact and DFIR steps.
- Provide concrete DFIR commands or steps to investigate in 'dfir_actions'.
- For Benign events, dfir_actions can be "None".
"""

VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"enum": ["malicious", "suspicious", "benign"]},
        "severity": {"enum": ["critical", "high", "medium", "low"]},
        "mitre_technique": {"type": "string", "minLength": 3, "maxLength": 100},
        "reason": {"type": "string", "minLength": 3, "maxLength": 500},
        "dfir_actions": {"type": "string", "minLength": 3, "maxLength": 500},
        "recommendation": {"type": "string", "minLength": 3, "maxLength": 200}
    },
    "required": ["verdict", "severity", "mitre_technique", "reason", "dfir_actions", "recommendation"],
    "additionalProperties": False
}