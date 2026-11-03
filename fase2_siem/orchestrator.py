"""Orquestador Fase 2: poll Splunk -> triage IA -> escribir veredicto. Sin bucle (lo pone el runner)."""

import json
import logging
from pathlib import Path

from jsonschema import ValidationError, validate

from fase1_cerebro.event_schema import INPUT_SCHEMA, normalize_event
from fase1_cerebro.soc_assistant import triage
from fase2_siem.splunk_client import hec_send, search

log = logging.getLogger("orchestrator")

SRC_SOURCETYPE = "nirvana:secops:event"
VERDICT_SOURCETYPE = "nirvana:secops:verdict"
STATE_FILE = Path("state.json")
VERDICT_LOOKBACK = "-24h"


# ---------------- Checkpoint ----------------

def load_checkpoint() -> str:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text()).get("last_time", "-15m")
    return "-15m"


def save_checkpoint(last_time: str) -> None:
    STATE_FILE.write_text(json.dumps({"last_time": last_time}))


# ---------------- Mapeo Splunk -> canonico ----------------

def splunk_to_event(row: dict) -> dict:
    """Mapea una fila de Splunk al contrato canonico de Fase 1."""
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


# ---------------- Idempotencia ----------------

def verdict_exists(event_id: str) -> bool:
    q = f'index=* sourcetype="{VERDICT_SOURCETYPE}" event_id="{event_id}" | head 1'
    return len(search(q, earliest=VERDICT_LOOKBACK)) > 0


# ---------------- Procesar un batch ----------------

def process_batch(rows: list[dict]) -> dict:
    """
    Procesa una lista de filas. Devuelve stats:
      {"processed": int, "skipped_dup": int, "skipped_invalid": int, "failed": int, "last_time": str|None}
    """
    stats = {"processed": 0, "skipped_dup": 0, "skipped_invalid": 0, "failed": 0, "last_time": None}
    if not rows:
        return stats

    for row in rows:
        try:
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

            verdict = triage(event)
            output = {
                "event_id": eid,
                "phase": "2.2",
                "source_kind": event["source"],
                "verdict": verdict["verdict"],
                "severity": verdict["severity"],
                "reason": verdict["reason"],
                "model": "qwen2.5:3b",
            }
            hec_send(output, sourcetype=VERDICT_SOURCETYPE)
            log.info("Verdict written: %s -> %s/%s", eid, verdict["verdict"], verdict["severity"])
            stats["processed"] += 1
        except Exception as e:
            log.error("Failed processing %s: %s", eid, e)
            stats["failed"] += 1

    # Actualizar checkpoint con el _time más reciente
    times = [r["_time"] for r in rows if "_time" in r]
    if times:
        stats["last_time"] = max(times)
        save_checkpoint(stats["last_time"])

    return stats


def run_once() -> dict:
    """Un solo ciclo: lee desde checkpoint, procesa, guarda. Devuelve stats."""
    last_time = load_checkpoint()
    q = f'index=* sourcetype="{SRC_SOURCETYPE}" | sort 0 _time'
    rows = search(q, earliest=last_time)
    return process_batch(rows)