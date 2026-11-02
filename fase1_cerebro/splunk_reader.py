import jsonschema
import requests
import urllib3
import json
import os
import time
import hashlib
from dotenv import load_dotenv

load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SPLUNK_HOST = os.getenv("SPLUNK_HOST")
SPLUNK_PORT = os.getenv("SPLUNK_PORT", "8089")
SPLUNK_USER = os.getenv("SPLUNK_USER", "admin")
SPLUNK_PASS = os.getenv("SPLUNK_PASS")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")

OLLAMA_URL = "http://localhost:11434/api/chat"
MODEL = "qwen2.5:3b"

# Memoria a largo plazo (JSON)
DB_FILE = "sent_alerts.json"

SYSTEM_PROMPT = """You are a SOC triage assistant. You receive a security event.
You MUST respond ONLY with a JSON object with this exact schema:
{
  "verdict": "malicious" | "suspicious" | "benign",
  "severity": "critical" | "high" | "medium" | "low",
  "reason": "short explanation (max 2 sentences)"
}"""

VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["malicious", "suspicious", "benign"]},
        "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
        "reason": {"type": "string"}
    },
    "required": ["verdict", "severity", "reason"],
    "additionalProperties": False  # Bloquea cualquier clave extra
}

def load_sent_alerts():
    if os.path.exists(DB_FILE):
        with open(DB_FILE, "r") as f:
            return json.load(f)
    return []

def save_sent_alert(alert_id):
    sent_alerts = load_sent_alerts()
    sent_alerts.append(alert_id)
    if len(sent_alerts) > 1000:
        sent_alerts = sent_alerts[-1000:]
    with open(DB_FILE, "w") as f:
        json.dump(sent_alerts, f, indent=2)

def generate_alert_id(raw_event, event_time):
    # Usamos la hora que da Splunk y el texto para crear un ID único
    unique_string = f"{event_time}_{raw_event}"
    return hashlib.md5(unique_string.encode()).hexdigest()

def ask_ollama(event_text, max_retries=3):
    print("[*] Enviando evento a la IA (Ollama)...")
    payload = {
        "model": MODEL, "format": "json", "stream": False,
        "options": {"temperature": 0},
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": event_text},
        ],
    }

    for attempt in range(max_retries):
        try:
            r = requests.post(OLLAMA_URL, json=payload, timeout=120)
            r.raise_for_status()
            content = r.json()["message"]["content"]
            
            # Parseamos el JSON
            parsed_result = json.loads(content)
            
            # Validamos contra el Schema estricto
            jsonschema.validate(instance=parsed_result, schema=VERDICT_SCHEMA)
            
            # Si llega aquí, es 100% válido
            return parsed_result

        except json.JSONDecodeError:
            print(f"⚠️ Intento {attempt+1}/{max_retries}: La IA devolvió JSON roto. Reintentando...")
        except jsonschema.ValidationError as e:
            print(f"⚠️ Intento {attempt+1}/{max_retries}: La IA alucinó (Schema inválido: {e.message}). Reintentando...")
        except Exception as e:
            print(f"❌ Error de conexión con Ollama: {e}")
        
        time.sleep(2) # Espera 2 segundos antes de reintentar

    # Si agota los reintentos, falla de forma controlada
    print("🚨 ERROR CRÍTICO: La IA no devolvió un veredicto válido tras varios intentos.")
    return None

def send_to_slack(event_text, ai_verdict):
    if not SLACK_WEBHOOK_URL:
        return

    print("[*] Enviando alerta a Slack...")
    message = {
        "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": "🚨 Nueva Alerta SOC - Nirvana"}},
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*Evento detectado:*\n`{event_text}`"}},
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*Veredicto IA:* {ai_verdict['verdict'].upper()}\n*Severidad:* {ai_verdict['severity'].upper()}\n*Razón:* {ai_verdict['reason']}"}},
            {"type": "actions", "elements": [
                {"type": "button", "text": {"type": "plain_text", "text": "✅ Aprobar"}, "style": "primary", "value": "approve"},
                {"type": "button", "text": {"type": "plain_text", "text": "🚫 Ignorar"}, "style": "danger", "value": "ignore"},
                {"type": "button", "text": {"type": "plain_text", "text": "⚠️ Escalar"}, "value": "escalate"}
            ]}
        ]
    }
    
    try:
        response = requests.post(SLACK_WEBHOOK_URL, json=message)
        if response.status_code == 200:
            print("✅ Alerta enviada a Slack con éxito.")
    except Exception as e:
        print(f"❌ Error de conexión con Slack: {e}")

def get_recent_alerts():
    print(f"\n[*] Revisando Splunk en {SPLUNK_HOST}:{SPLUNK_PORT}...")
    url = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}/services/search/jobs/export"
    
    # Buscamos solo los últimos 5 minutos. 
    spl = 'search index=* sourcetype=soc_test earliest=-5m | head 20'
    
    data = {
        "search": spl,
        "output_mode": "json",
        "latest_time": "now"
    }
    
    try:
        response = requests.post(url, data=data, auth=(SPLUNK_USER, SPLUNK_PASS), verify=False)
        
        if response.status_code == 200:
            lines = response.text.strip().split('\n')
            sent_alerts = load_sent_alerts()
            new_alerts_count = 0
            
            for line in lines:
                if line:
                    parsed = json.loads(line)
                    if "result" in parsed and "_raw" in parsed["result"]:
                        raw_event = parsed["result"]["_raw"]
                        event_time = parsed["result"].get("_time", "unknown")
                        
                        # Generamos el ID. Si ya lo enviamos (está en el JSON), lo saltamos.
                        alert_id = generate_alert_id(raw_event, event_time)
                        if alert_id in sent_alerts:
                            continue
                            
                        print(f"\n[+] Evento NUEVO encontrado en Splunk ({event_time}):")
                        print(f"    {raw_event}")
                        
                        ai_verdict = ask_ollama(raw_event)
                        
                        if ai_verdict:
                            print("\n=== 🤖 VEREDICTO DE LA IA ===")
                            print(json.dumps(ai_verdict, indent=2))
                            send_to_slack(raw_event, ai_verdict)
                            
                            # Guardamos el ID para no repetirlo nunca más
                            save_sent_alert(alert_id)
                            new_alerts_count += 1
            
            if new_alerts_count == 0:
                print("[-] No hay alertas nuevas en los últimos 5 minutos.")
        else:
            print(f"❌ Error en la petición: {response.status_code}")
            
    except Exception as e:
        print(f"❌ Error de conexión: {e}")

if __name__ == "__main__":
    print("[*] Iniciando SOC Assistant (Validación JSON + Reintentos)...")
    print("[*] Presiona Ctrl+C para detenerlo.")
    
    while True:
        try:
            get_recent_alerts()
        except Exception as e:
            print(f"Error en el ciclo: {e}")
            
        print("\n[*] Esperando 60 segundos para la siguiente revisión...")
        time.sleep(60)