import requests
import urllib3
import json
import os
import time
import hashlib
import urllib.request
import ssl
import jsonschema
import threat_intel
from dotenv import load_dotenv

# --- IMPORTACIÓN MODULAR ---
from config import OLLAMA_URL, MODEL, SYSTEM_PROMPT, VERDICT_SCHEMA
# ---------------------------

load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SPLUNK_HOST = os.getenv("SPLUNK_HOST")
SPLUNK_PORT = os.getenv("SPLUNK_PORT", "8089")
SPLUNK_USER = os.getenv("SPLUNK_USER", "admin")
SPLUNK_PASS = os.getenv("SPLUNK_PASS")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")
HEC_TOKEN = os.getenv("HEC_TOKEN")

DB_FILE = "sent_alerts.json"

# ==========================================
# 1. CONECTORES (SPLUNK, OLLAMA, SLACK)
# ==========================================
def search_splunk(query, earliest="-5m"):
    url = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}/services/search/jobs/export"
    data = {"search": query, "output_mode": "json", "earliest_time": earliest, "latest_time": "now"}
    try:
        r = requests.post(url, data=data, auth=(SPLUNK_USER, SPLUNK_PASS), verify=False)
        r.raise_for_status()
        lines = r.text.strip().split('\n')
        return [json.loads(line)["result"] for line in lines if line and "result" in json.loads(line)]
    except Exception as e:
        print(f"❌ Error buscando en Splunk: {e}")
        return []

def send_to_splunk(event_data, sourcetype="nirvana:secops:verdict"):
    if not HEC_TOKEN:
        print("⚠️ No hay HEC_TOKEN configurado.")
        return False
    url = f"https://{SPLUNK_HOST}:8088/services/collector/event"
    payload = {"event": event_data, "sourcetype": sourcetype}
    req = urllib.request.Request(url, method="POST")
    req.add_header("Authorization", f"Splunk {HEC_TOKEN}")
    req.add_header("Content-Type", "application/json")
    context = ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(req, data=json.dumps(payload).encode(), context=context) as response:
            return response.status == 200
    except Exception as e:
        print(f"❌ Error enviando a HEC: {e}")
        return False

def ask_ollama(event_text, max_retries=3):
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
            parsed_result = json.loads(content)
            jsonschema.validate(instance=parsed_result, schema=VERDICT_SCHEMA)
            return parsed_result
        except Exception as e:
            print(f"⚠️ Intento {attempt+1}/{max_retries}: {e}")
            time.sleep(2)
    print("🚨 ERROR: La IA no devolvió un veredicto válido.")
    return None

def send_to_slack(event_text, ai_verdict, source):
    if not SLACK_WEBHOOK_URL:
        return
    print(f"[*] Enviando alerta a Slack ({source})...")
    message = {
        "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": f"🚨 Alerta SOC - {source}"}},
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*Evento:*\n`{event_text}`"}},
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*Veredicto:* {ai_verdict['verdict'].upper()}\n*Severidad:* {ai_verdict['severity'].upper()}\n*Razón:* {ai_verdict['reason']}"}},
            {"type": "actions", "elements": [
                {"type": "button", "text": {"type": "plain_text", "text": "✅ Aprobar"}, "style": "primary", "value": "approve"},
                {"type": "button", "text": {"type": "plain_text", "text": "🚫 Ignorar"}, "style": "danger", "value": "ignore"},
                {"type": "button", "text": {"type": "plain_text", "text": "⚠️ Escalar"}, "value": "escalate"}
            ]}
        ]
    }
    try:
        requests.post(SLACK_WEBHOOK_URL, json=message)
        print("✅ Alerta enviada a Slack con éxito.")
    except Exception as e:
        print(f"❌ Error de conexión con Slack: {e}")

# ==========================================
# 2. MEMORIA Y LÓGICA DE PROCESAMIENTO
# ==========================================
def load_sent_alerts():
    if os.path.exists(DB_FILE):
        with open(DB_FILE, "r") as f:
            return json.load(f)
    return []

def save_sent_alert(alert_id):
    sent_alerts = load_sent_alerts()
    sent_alerts.append(alert_id)
    with open(DB_FILE, "w") as f:
        json.dump(sent_alerts[-1000:], f, indent=2)

def generate_alert_id(raw_event, event_time):
    # Generamos el ID solo con el texto del evento para evitar duplicados por la hora
    unique_string = raw_event.strip() 
    return hashlib.md5(unique_string.encode()).hexdigest()

def procesar_eventos(rows, tipo):
    if not rows:
        return 0

    sent_alerts = load_sent_alerts()
    procesados_en_este_ciclo = [] # Memoria volátil para evitar duplicados en la misma pasada
    processed_count = 0

    for row in rows:
        raw_data = row.get("_raw", "")
        parsed_data = {}
        
        # --- MAGIA PARA PARSEAR EL JSON ---
        try:
            if isinstance(raw_data, str):
                if raw_data.strip().startswith("{"):
                    parsed_data = json.loads(raw_data)
                elif "{" in raw_data and "}" in raw_data:
                    start = raw_data.find("{")
                    end = raw_data.rfind("}") + 1
                    parsed_data = json.loads(raw_data[start:end])
        except Exception as e:
            pass
            
        # 1. Extracción inteligente según el tipo
        if tipo == "log":
            raw_event = raw_data
            source_name = "Linux Log"
            
        elif tipo == "edr":
            title = parsed_data.get('AlertTitle', 'Unknown')
            desc = parsed_data.get('Description', '')
            raw_event = f"EDR Alert: {title} - {desc}"
            source_name = "MS Defender"
            
        elif tipo == "vuln":
            cve_id = parsed_data.get('VulnerabilityID', 'Unknown')
            pkg_name = parsed_data.get('PkgName', 'Unknown')
            sev = parsed_data.get('Severity', 'Unknown')
            
            if cve_id != 'Unknown':
                epss, is_kev = threat_intel.check_vulnerability(cve_id)
                kev_str = "SÍ (¡Peligro!)" if is_kev else "No"
                raw_event = f"Vulnerability {cve_id} in {pkg_name}. " \
                            f"Severity: {sev}. " \
                            f"EPSS Score: {epss:.2f}. " \
                            f"In CISA KEV: {kev_str}."
            else:
                raw_event = f"Vulnerability found: {raw_data[:100]}"
            source_name = "Trivy ASPM"
            
        else:
            raw_event = raw_data
            source_name = "Unknown"

        if not raw_event.strip():
            continue

        event_time = row.get("_time", "unknown")
        alert_id = generate_alert_id(raw_event, event_time)

        # Si ya lo procesamos (en disco o en este ciclo), lo saltamos
        if alert_id in sent_alerts or alert_id in procesados_en_este_ciclo:
            continue

        print(f"\n[+] Evento NUEVO ({source_name}) encontrado:")
        print(f"    {raw_event[:100]}...")

        ai_verdict = ask_ollama(raw_event)

        if ai_verdict:
            print("\n=== 🤖 VEREDICTO DE LA IA ===")
            print(json.dumps(ai_verdict, indent=2))

            # --- LÓGICA DE FILTRADO INTELIGENTE ---
            if ai_verdict['verdict'] == 'benign':
                print("[-] FALSO POSITIVO: La IA determinó que es BENIGNO. Ignorando.")
                save_sent_alert(alert_id)
                procesados_en_este_ciclo.append(alert_id)
                continue

            elif ai_verdict['verdict'] == 'malicious':
                print(f"🚨 ¡ATAQUE DETECTADO! Enviando a Slack y guardando en Splunk.")
                send_to_slack(raw_event, ai_verdict, source_name)
                
                output = {
                    "event_id": alert_id,
                    "source": source_name,
                    "original_event": raw_event,
                    "verdict": ai_verdict['verdict'],
                    "severity": ai_verdict['severity'],
                    "reason": ai_verdict['reason']
                }
                if send_to_splunk(output):
                    print("✅ Veredicto guardado en Splunk con éxito.")

            elif ai_verdict['verdict'] == 'suspicious':
                print(f"⚠️ SOSPECHOSO: Guardando en Splunk para investigación (sin alertar a Slack).")
                output = {
                    "event_id": alert_id,
                    "source": source_name,
                    "original_event": raw_event,
                    "verdict": ai_verdict['verdict'],
                    "severity": ai_verdict['severity'],
                    "reason": ai_verdict['reason']
                }
                send_to_splunk(output)

            save_sent_alert(alert_id)
            procesados_en_este_ciclo.append(alert_id)
            processed_count += 1

    return processed_count

# ==========================================
# 3. ORQUESTADOR PRINCIPAL
# ==========================================
def get_recent_alerts():
    print(f"\n[*] Revisando Splunk en {SPLUNK_HOST}:{SPLUNK_PORT}...")
    total_procesados = 0

    query_logs = 'search index=* sourcetype="soc_test" earliest=-5m'
    rows_logs = search_splunk(query_logs)
    total_procesados += procesar_eventos(rows_logs, tipo="log")

    query_defender = 'search index=* sourcetype="ms-defender" earliest=-5m'
    rows_defender = search_splunk(query_defender)
    total_procesados += procesar_eventos(rows_defender, tipo="edr")

    query_trivy = 'search index=* sourcetype="trivy" earliest=-5m'
    rows_trivy = search_splunk(query_trivy)
    total_procesados += procesar_eventos(rows_trivy, tipo="vuln")

    if total_procesados == 0:
        print("[-] No hay alertas nuevas en ninguna de las fuentes.")

# ==========================================
# 4. PUNTO DE ENTRADA (EL BUCLE)
# ==========================================
if __name__ == "__main__":
    print("[*] Iniciando SOC Assistant (Multi-Fuente: Logs, Defender, Trivy)...")
    print("[*] Presiona Ctrl+C para detenerlo.")
    
    while True:
        try:
            get_recent_alerts()
        except Exception as e:
            print(f"Error en el ciclo: {e}")
            
        print("\n[*] Esperando 60 segundos para la siguiente revisión...")
        time.sleep(60)