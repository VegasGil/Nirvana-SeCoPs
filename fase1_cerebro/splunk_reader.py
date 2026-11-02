import requests
import urllib3
import json
import os
from dotenv import load_dotenv

load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SPLUNK_HOST = os.getenv("SPLUNK_HOST")
SPLUNK_PORT = os.getenv("SPLUNK_PORT", "8089")
SPLUNK_USER = os.getenv("SPLUNK_USER", "admin")
SPLUNK_PASS = os.getenv("SPLUNK_PASS")

# --- LEEMOS SLACK DEL .ENV (Seguro para GitHub) ---
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")

OLLAMA_URL = "http://localhost:11434/api/chat"
MODEL = "qwen2.5:3b"

SYSTEM_PROMPT = """You are a SOC triage assistant. You receive a security event.
You MUST respond ONLY with a JSON object with this exact schema:
{
  "verdict": "malicious" | "suspicious" | "benign",
  "severity": "critical" | "high" | "medium" | "low",
  "reason": "short explanation (max 2 sentences)"
}"""

def ask_ollama(event_text):
    print("[*] Enviando evento a la IA (Ollama)...")
    payload = {
        "model": MODEL, "format": "json", "stream": False,
        "options": {"temperature": 0},
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": event_text},
        ],
    }
    try:
        r = requests.post(OLLAMA_URL, json=payload, timeout=120)
        r.raise_for_status()
        content = r.json()["message"]["content"]
        return json.loads(content)
    except Exception as e:
        print(f"❌ Error al consultar a Ollama: {e}")
        return None

def send_to_slack(event_text, ai_verdict):
    if not SLACK_WEBHOOK_URL:
        print("⚠️ No se configuró SLACK_WEBHOOK_URL en el archivo .env. Saltando envío.")
        return

    print("[*] Enviando alerta a Slack...")
    
    message = {
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "🚨 Nueva Alerta SOC - Nirvana"}
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Evento detectado:*\n`{event_text}`"}
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Veredicto IA:* {ai_verdict['verdict'].upper()}\n*Severidad:* {ai_verdict['severity'].upper()}\n*Razón:* {ai_verdict['reason']}"}
            },
            {
                "type": "actions",
                "elements": [
                    {"type": "button", "text": {"type": "plain_text", "text": "✅ Aprobar"}, "style": "primary", "value": "approve"},
                    {"type": "button", "text": {"type": "plain_text", "text": "🚫 Ignorar"}, "style": "danger", "value": "ignore"},
                    {"type": "button", "text": {"type": "plain_text", "text": "⚠️ Escalar"}, "value": "escalate"}
                ]
            }
        ]
    }
    
    try:
        response = requests.post(SLACK_WEBHOOK_URL, json=message)
        if response.status_code == 200:
            print("✅ Alerta enviada a Slack con éxito.")
        else:
            print(f"❌ Error al enviar a Slack: {response.status_code}")
    except Exception as e:
        print(f"❌ Error de conexión con Slack: {e}")

def get_recent_alerts():
    print(f"[*] Conectando a Splunk en {SPLUNK_HOST}:{SPLUNK_PORT}...")
    url = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}/services/search/jobs/export"
    
    spl = 'search index=* sourcetype=soc_test | head 1'
    
    data = {
        "search": spl,
        "output_mode": "json",
        "earliest_time": "-30d",
        "latest_time": "now"
    }
    
    try:
        response = requests.post(url, data=data, auth=(SPLUNK_USER, SPLUNK_PASS), verify=False)
        
        if response.status_code == 200:
            lines = response.text.strip().split('\n')
            found = False
            for line in lines:
                if line:
                    parsed = json.loads(line)
                    if "result" in parsed and "_raw" in parsed["result"]:
                        raw_event = parsed["result"]["_raw"]
                        print(f"\n[+] Evento encontrado en Splunk:")
                        print(f"    {raw_event}")
                        
                        ai_verdict = ask_ollama(raw_event)
                        
                        if ai_verdict:
                            print("\n=== 🤖 VEREDICTO DE LA IA ===")
                            print(json.dumps(ai_verdict, indent=2))
                            send_to_slack(raw_event, ai_verdict)
                        found = True
                        break
            if not found:
                print("[-] No se encontraron eventos válidos en soc_test.")
        else:
            print(f"❌ Error en la petición: {response.status_code}")
            
    except Exception as e:
        print(f"❌ Error de conexión: {e}")

if __name__ == "__main__":
    get_recent_alerts()