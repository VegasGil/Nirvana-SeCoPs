"""Orquestador del Bot 4: Lee correos, enriquece con Intel, IA y notifica."""

import logging
import shutil
from pathlib import Path

from bot4_human_vector.email_parser import parse_eml
from bot4_human_vector.slack_client import send_alert_to_slack
from bot3_intel.threat_intel import enrich_event_iocs
from bot1_cerebro.soc_assistant import triage
from bot2_siem.splunk_client import hec_send

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("bot4_orchestrator")

INBOX_DIR = Path("data/inbox")
PROCESSED_DIR = Path("data/processed")

def process_inbox():
    INBOX_DIR.mkdir(parents=True, exist_ok=True)
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    eml_files = list(INBOX_DIR.glob("*.eml"))
    if not eml_files:
        log.info("No hay correos nuevos en data/inbox.")
        return

    for file_path in eml_files:
        log.info(f"📧 Procesando correo: {file_path.name}")
        
        try:
            # 1. Parsear
            event = parse_eml(str(file_path))
            
            # 2. Threat Intel
            log.info("   -> Consultando VirusTotal...")
            _, vt_context = enrich_event_iocs(event["iocs"])
            event["raw"]["threat_intel_context"] = vt_context
            
            # 3. IA
            log.info("   -> Solicitando veredicto a la IA...")
            verdict = triage(event)
            log.info(f"   -> Veredicto: {verdict['verdict'].upper()} ({verdict['severity']})")
            
            # 4. Enviar a Splunk
            output = {
                "event_id": event["event_id"],
                "source": "email",
                "sender": event.get("src", "unknown"),
                "subject": event["summary"],
                "verdict": verdict["verdict"],
                "severity": verdict["severity"],
                "reason": verdict["reason"],
                "recommendation": verdict["recommendation"],
                "iocs_found": event["iocs"]
            }
            hec_send(output, sourcetype="nirvana:secops:verdict")
            log.info("   -> Veredicto guardado en Splunk.")
            
            # 5. Enviar a Slack (Human-in-the-loop)
            send_alert_to_slack(event, verdict)
            
            # 6. Mover a procesados
            shutil.move(str(file_path), str(PROCESSED_DIR / file_path.name))
            log.info(f"✅ Correo movido a data/processed.\n")

        except Exception as e:
            log.error(f"❌ Error procesando {file_path.name}: {e}")
            # Lo movemos a una carpeta de error para no bloquear el bucle
            ERROR_DIR = Path("data/errors")
            ERROR_DIR.mkdir(exist_ok=True)
            shutil.move(str(file_path), str(ERROR_DIR / file_path.name))

if __name__ == "__main__":
    log.info("Iniciando Orquestador de Correos (Bot 4)...")
    process_inbox()