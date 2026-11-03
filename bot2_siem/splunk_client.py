"""Cliente Splunk: HEC (escritura) + REST export (lectura). Sin estado, testeable."""

import json
import logging
import os

import requests
import urllib3
from dotenv import load_dotenv

load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger("splunk_client")

HOST = os.getenv("SPLUNK_HOST", "https://localhost")
HEC_PORT = os.getenv("SPLUNK_PORT", "8088")  # ajusta si HEC usa 8088
REST_PORT = os.getenv("SPLUNK_REST_PORT", "8089")
HEC_TOKEN = os.getenv("HEC_TOKEN", "")
USER = os.getenv("SPLUNK_USER", "admin")
PASS = os.getenv("SPLUNK_PASS", "")
INDEX = os.getenv("SPLUNK_INDEX", "main")
VERIFY = os.getenv("SPLUNK_VERIFY_TLS", "false").lower() == "true"

HEC_URL = f"{HOST}:{HEC_PORT}/services/collector/event"
REST_URL = f"{HOST}:{REST_PORT}/services/search/jobs/export"


def hec_send(event: dict, sourcetype: str = "nirvana:secops:verdict",
             source: str = "soc_assistant") -> bool:
    """Envia un evento a Splunk via HEC. Devuelve True si code == 0."""
    if not HEC_TOKEN:
        raise RuntimeError("HEC_TOKEN no configurado en .env")
    body = {"index": INDEX, "sourcetype": sourcetype, "source": source, "event": event}
    r = requests.post(
        HEC_URL,
        data=json.dumps(body),
        headers={"Authorization": f"Splunk {HEC_TOKEN}"},
        verify=VERIFY,
        timeout=15,
    )
    r.raise_for_status()
    resp = r.json()
    if resp.get("code") != 0:
        raise RuntimeError(f"HEC error: {resp}")
    return True


def search(query: str, earliest: str = "-15m", latest: str = "now") -> list[dict]:
    """Ejecuta busqueda via export streaming. Devuelve lista de dicts."""
    if not query.strip().lower().startswith("search "):
        query = "search " + query.strip()
    data = {
        "search": query,
        "output_mode": "json",
        "earliest_time": earliest,
        "latest_time": latest,
    }
    r = requests.post(
        REST_URL,
        data=data,
        auth=(USER, PASS),
        verify=VERIFY,
        timeout=60,
    )
    r.raise_for_status()
    results = []
    for line in r.text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            log.debug("Skipping non-JSON line: %.80s", line)
            continue
        if "result" in obj:
            results.append(obj["result"])
    return results