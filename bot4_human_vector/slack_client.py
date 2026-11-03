"""Módulo para enviar alertas a Slack y permitir Human-in-the-loop."""

import os
import logging
import requests
from dotenv import load_dotenv

load_dotenv()
log = logging.getLogger("slack_client")

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")

def send_alert_to_slack(event: dict, verdict: dict) -> bool:
    """Envía una alerta formateada a Slack con botones de acción."""
    if not SLACK_WEBHOOK_URL:
        log.warning("SLACK_WEBHOOK_URL no configurada.")
        return False

    # Si la IA dice que es benigno, no molestamos al analista en Slack.
    if verdict["verdict"] == "benign":
        log.info("El veredicto es benigno. No se envía a Slack.")
        return True

    # Formatear los IOCs
    iocs_str = ", ".join(event.get("iocs", [])) or "Ninguno"

    payload = {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🚨 Alerta SOC: {verdict['verdict'].upper()} (Severity: {verdict['severity'].upper()})"
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Evento:*\n{event['summary']}"},
                    {"type": "mrkdwn", "text": f"*Remitente:*\n{event.get('src', 'Desconocido')}"},
                    {"type": "mrkdwn", "text": f"*IOCs:*\n`{iocs_str}`"}
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*🧠 Razonamiento de la IA:*\n{verdict['reason']}\n\n*🛡️ Recomendación:*\n{verdict['recommendation']}"
                }
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "✅ Aprobar Bloqueo"},
                        "style": "primary",
                        "value": "approve"
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "🚫 Ignorar (Falso Positivo)"},
                        "style": "danger",
                        "value": "ignore"
                    }
                ]
            }
        ]
    }

    try:
        r = requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=10)
        r.raise_for_status()
        log.info("Alerta enviada a Slack correctamente.")
        return True
    except Exception as e:
        log.error(f"Error enviando a Slack: {e}")
        return False