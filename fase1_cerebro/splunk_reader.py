import requests
import urllib3
import json
import os
from dotenv import load_dotenv

# 1. Cargar variables de entorno
load_dotenv()

# Desactivar advertencias de SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 2. Configuración
SPLUNK_HOST = os.getenv("SPLUNK_HOST")
SPLUNK_PORT = os.getenv("SPLUNK_PORT", "8089")
SPLUNK_USER = os.getenv("SPLUNK_USER", "admin")
SPLUNK_PASS = os.getenv("SPLUNK_PASS")

if not SPLUNK_HOST or not SPLUNK_PASS:
    print("❌ ERROR: Faltan credenciales en el archivo .env")
    exit(1)

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
        "model": MODEL,
        "format": "json",
        "stream": False,
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

def get_recent_alerts():
    print(f"[*] Conectando a Splunk en {SPLUNK_HOST}:{SPLUNK_PORT}...")
    url = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}/services/search/jobs/export"
    
    # Búsqueda en soc_test en los últimos 30 días
    spl = 'search index=* sourcetype=soc_test | head 1'
    
    data = {
        "search": spl,
        "output_mode": "json",
        "earliest_time": "-30d", # Modificado a 30 días
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
                    # Extraemos el log real
                    if "result" in parsed and "_raw" in parsed["result"]:
                        raw_event = parsed["result"]["_raw"]
                        print(f"\n[+] Evento encontrado en Splunk:")
                        print(f"    {raw_event}")
                        
                        # Enviamos el log a la IA
                        ai_verdict = ask_ollama(raw_event)
                        
                        if ai_verdict:
                            print("\n=== 🤖 VEREDICTO DE LA IA ===")
                            print(json.dumps(ai_verdict, indent=2))
                        found = True
                        break
            
            if not found:
                print("[-] No se encontraron eventos válidos en soc_test (últimos 30 días).")
                print("[*] Verifica que hayas generado un log recientemente con el comando 'echo' en tu VM de Oracle.")
        else:
            print(f"❌ Error en la petición: {response.status_code}")
            
    except Exception as e:
        print(f"❌ Error de conexión: {e}")

if __name__ == "__main__":
    get_recent_alerts()