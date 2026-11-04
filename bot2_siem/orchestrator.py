"""Orquestador Bot 2: Lee de Splunk -> Pide veredicto a Bot 1 (Ollama) -> Notifica a Slack -> Guarda en Splunk."""

import json
import logging
import os
import time
import requests
from pathlib import Path
from jsonschema import ValidationError, validate

from bot5_endpoint.defender_parser import parse_defender_alert
from bot1_cerebro.event_schema import INPUT_SCHEMA, normalize_event
from bot1_cerebro.soc_assistant import triage
from bot2_siem.splunk_client import hec_send, search

log = logging.getLogger("orchestrator")

SRC_SOURCETYPE = "nirvana:secops:event"
VERDICT_SOURCETYPE = "nirvana:secops:verdict"
STATE_FILE = Path("state.json")
VERDICT_LOOKBACK = "-24h"
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")

# ==========================================
# 1. CHECKPOINT
# ==========================================
def load_checkpoint() -> str:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text()).get("last_time", "-15m")
    return "-15m"

def save_checkpoint(last_time: str) -> None:
    STATE_FILE.write_text(json.dumps({"last_time": last_time}))

# ==========================================
# 2. SLACK
# ==========================================
def send_to_slack(event_text, ai_verdict, source_name):
    if not SLACK_WEBHOOK_URL:
        log.warning("⚠️ No hay SLACK_WEBHOOK_URL configurado.")
        return

    log.info(f"[*] Enviando alerta a Slack ({source_name})...")
    message = {
        "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": f"🚨 Alerta SOC - {source_name}"}},
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*Evento:*\n`{event_text}`"}},
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*Veredicto:* {ai_verdict['verdict'].upper()}\n*Severidad:* {ai_verdict['severity'].upper()}\n*MITRE ATT&CK:* {ai_verdict.get('mitre_technique', 'N/A')}\n*Razón:* {ai_verdict['reason']}"}},
            {"type": "actions", "elements": [
                {"type": "button", "text": {"type": "plain_text", "text": "✅ Aprobar"}, "style": "primary", "value": "approve"},
                {"type": "button", "text": {"type": "plain_text", "text": "🚫 Ignorar"}, "style": "danger", "value": "ignore"}
            ]}
        ]
    }
    try:
        r = requests.post(SLACK_WEBHOOK_URL, json=message, timeout=10)
        r.raise_for_status()
        log.info("✅ Alerta enviada a Slack con éxito.")
    except Exception as e:
        log.error(f"❌ Error enviando a Slack: {e}")

# ==========================================
# 3. LÓGICA DE PROCESAMIENTO (Testeable)
# ==========================================
def splunk_to_event(row: dict) -> dict:
    """Convierte una fila cruda de Splunk al evento canónico del Bot 1."""
    return normalize_event({
        "event_id": row.get("event_id") or row.get("_cd") or (row.get("_raw", "")[:32]),
        "source": row.get("source_kind", "manual"),
        "timestamp": row.get("_time", ""),
        "src": row.get("src", "unknown"),
        "dst": row.get("dst", "unknown"),
        "summary": row.get("summary", (row.get("_raw", "") or "")[:500]),
        "iocs": row.get("iocs", []),
        "raw": {k: v for k, v in row.items() if not k.startswith("_")},
    })

def verdict_exists(event_id: str) -> bool:
    """Evita duplicados consultando si ya existe el veredicto en Splunk."""
    q = f'index=* sourcetype="{VERDICT_SOURCETYPE}" event_id="{event_id}" | head 1'
    return len(search(q, earliest=VERDICT_LOOKBACK)) > 0

def process_batch(rows: list[dict]) -> dict:
    """Procesa una lista de filas y devuelve estadísticas."""
    stats = {"processed": 0, "skipped_dup": 0, "skipped_invalid": 0, "failed": 0, "last_time": None}
    if not rows:
        return stats

    for row in rows:
        try:
            # --- ROUTING DE MULTI-FUENTE ---
            # Si viene de Defender (con el nombre exacto que vimos en Splunk), usamos su parser
            if row.get("sourcetype") in ["ms-defender", "ms:defender:atp", "ms:defender:atp:alerts"]:
                event = parse_defender_alert(row)
            else:
                # Si es un evento nuestro normal, usamos el mapeo estándar
                event = splunk_to_event(row)
                
            validate(instance=event, schema=INPUT_SCHEMA)
        except (ValidationError, ValueError) as e:
            log.warning("Invalid event skipped: %s", e)
            stats["skipped_invalid"] += 1
            continue

        eid = event["event_id"]
        try:
            if verdict_exists(eid):
                log.info("Already processed: %s", eid)
                stats["skipped_dup"] += 1
                continue

            # Llamamos a la IA del Bot 1
            verdict = triage(event)
            event_text = event.get("summary", "")
            
            # Enviar a Slack (si es malicioso o sospechoso)
            if verdict['verdict'] in ['malicious', 'suspicious']:
                send_to_slack(event_text, verdict, event.get("source", "Unknown"))
            
            # Guardar en Splunk
            output = {
                "event_id": eid,
                "source_kind": event["source"],
                "verdict": verdict["verdict"],
                "severity": verdict["severity"],
                "mitre_technique": verdict.get("mitre_technique", "N/A"),
                "reason": verdict["reason"],
                "recommendation": verdict.get("recommendation", "None"),
                "model": "qwen2.5:3b",
            }
            hec_send(output, sourcetype=VERDICT_SOURCETYPE)
            log.info("Verdict written: %s -> %s/%s", eid, verdict["verdict"], verdict["severity"])
            stats["processed"] += 1

        except Exception as e:
            log.error("Failed processing %s: %s", eid, e)
            stats["failed"] += 1

    # Actualizar checkpoint
    times = [r["_time"] for r in rows if "_time" in r]
    if times:
        stats["last_time"] = max(times)
        save_checkpoint(stats["last_time"])

    return stats

# ==========================================
# 4. CICLO PRINCIPAL
# ==========================================
def run_once() -> dict:
    last_time = load_checkpoint()
    # Buscamos nuestros eventos normales O las alertas reales de Defender
    q = f'index=* (sourcetype="{SRC_SOURCETYPE}" OR sourcetype="ms:defender:atp:alerts") | sort 0 _time'
    rows = search(q, earliest=last_time)
    return process_batch(rows)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    log.info("Orchestrator Bot 2 started. Polling every 10s.")
    while True:
        try:
            res = run_once()
            if res["processed"] > 0:
                log.info("Batch processed: %d event(s)", res["processed"])
        except Exception as e:
            log.error("Poll error: %s", e)
        time.sleep(10)