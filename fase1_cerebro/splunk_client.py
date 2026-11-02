import os
import requests
import urllib3
import json
from dotenv import load_dotenv

load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SPLUNK_HOST = os.getenv("SPLUNK_HOST")
SPLUNK_PORT = os.getenv("SPLUNK_PORT", "8089")
SPLUNK_USER = os.getenv("SPLUNK_USER", "admin")
SPLUNK_PASS = os.getenv("SPLUNK_PASS")
HEC_TOKEN = os.getenv("HEC_TOKEN") # Para escribir de vuelta a Splunk

def search(query, earliest="-5m"):
    url = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}/services/search/jobs/export"
    data = {"search": query, "output_mode": "json", "earliest_time": earliest, "latest_time": "now"}
    try:
        r = requests.post(url, data=data, auth=(SPLUNK_USER, SPLUNK_PASS), verify=False)
        r.raise_for_status()
        lines = r.text.strip().split('\n')
        return [json.loads(line)["result"] for line in lines if line and "result" in json.loads(line)]
    except Exception as e:
        print(f"Error buscando en Splunk: {e}")
        return []

def hec_send(event, sourcetype="nirvana:secops:verdict"):
    url = f"https://{SPLUNK_HOST}:8088/services/collector/event"
    payload = {"event": event, "sourcetype": sourcetype}
    headers = {"Authorization": f"Splunk {HEC_TOKEN}"}
    try:
        r = requests.post(url, json=payload, headers=headers, verify=False)
        return r.status_code == 200
    except Exception as e:
        print(f"Error enviando a HEC: {e}")
        return False