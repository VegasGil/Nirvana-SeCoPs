"""Cliente Splunk: HEC (escritura) + REST export (lectura)."""

import json
import logging
import os
import time

import requests
import urllib3
from dotenv import load_dotenv

load_dotenv()
log = logging.getLogger("splunk_client")

HOST = os.getenv("SPLUNK_HOST", "https://localhost")
REST_HOST = HOST.replace("http://", "https://") if HOST.startswith("http://") else HOST

HEC_PORT = os.getenv("SPLUNK_PORT", "8088")
REST_PORT = os.getenv("SPLUNK_REST_PORT", "8089")
HEC_TOKEN = os.getenv("HEC_TOKEN", "")
USER = os.getenv("SPLUNK_USER", "admin")
PASS = os.getenv("SPLUNK_PASS", "")
INDEX = os.getenv("SPLUNK_INDEX", "main")

VERIFY = os.getenv("SPLUNK_VERIFY_TLS", "false").lower() == "true"

if not VERIFY:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEC_URL = f"{HOST}:{HEC_PORT}/services/collector/event"
REST_URL = f"{REST_HOST}:{REST_PORT}/services/search/jobs/export"


def hec_send(event: dict, sourcetype: str = "nirvana:secops:verdict",
             source: str = "soc_assistant", max_retries=15) -> bool:
    if not HEC_TOKEN:
        raise RuntimeError("HEC_TOKEN no configurado en .env")
    
    body = {"index": INDEX, "sourcetype": sourcetype, "source": source, "event": event}
    
    for attempt in range(max_retries):
        try:
            r = requests.post(
                HEC_URL,
                data=json.dumps(body),
                headers={"Authorization": f"Splunk {HEC_TOKEN}"},
                verify=VERIFY if HOST.startswith("https") else True,
                timeout=15,
            )
            r.raise_for_status()
            resp = r.json()
            if resp.get("code") != 0:
                raise RuntimeError(f"HEC error: {resp}")
            return True
        except requests.exceptions.ConnectionError:
            if attempt == max_retries - 1:
                raise
            log.warning(f"⏳ Esperando a que Splunk HEC arranque (Intento {attempt+1}/{max_retries})...")
            time.sleep(5)


def search(query: str, earliest: str = "-15m", latest: str = "now", max_retries=15) -> list[dict]:
    if not query.strip().lower().startswith("search "):
        query = "search " + query.strip()
        
    data = {
        "search": query,
        "output_mode": "json",
        "earliest_time": earliest,
        "latest_time": latest,
    }
    
    for attempt in range(max_retries):
        try:
            r = requests.post(
                REST_URL,
                data=data,
                auth=(USER, PASS),
                verify=VERIFY if REST_HOST.startswith("https") else True,
                timeout=60,
            )
            
            # Si hay error 400, imprimimos el motivo exacto
            if r.status_code == 400:
                log.error(f"❌ Splunk rechazó la búsqueda: {r.text}")
                r.raise_for_status()
                
            r.raise_for_status()
            break
        except requests.exceptions.ConnectionError:
            if attempt == max_retries - 1:
                raise
            log.warning(f"⏳ Esperando a que Splunk arranque (Intento {attempt+1}/{max_retries})...")
            time.sleep(5)

    results = []
    for line in r.text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "result" in obj:
            results.append(obj["result"])
    return results