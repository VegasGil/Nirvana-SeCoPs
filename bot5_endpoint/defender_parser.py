"""Parser para alertas de Microsoft Defender (Soporta API de Azure y formato de Splunk)."""

import hashlib
import json
import logging

log = logging.getLogger("defender_parser")

def parse_defender_alert(alert: dict) -> dict:
    """
    Transforma una alerta cruda de Defender al evento canónico de Nirvana.
    """
    # 1. EL TRUCO: Si viene de Splunk y está todo dentro de '_raw', lo extraemos
    if "_raw" in alert and isinstance(alert["_raw"], str):
        try:
            parsed_raw = json.loads(alert["_raw"])
            alert.update(parsed_raw)
        except json.JSONDecodeError:
            log.warning("No se pudo parsear el _raw de Defender como JSON.")

    # 2. Extraer campos
    alert_id = alert.get("id", "")
    title = alert.get("title", "Unknown Defender Alert")
    description = alert.get("description", "")
    severity = alert.get("severity", "medium").lower()
    
    timestamp = alert.get("createdDateTime") or alert.get("alertCreationTime") or "1970-01-01T00:00:00Z"
    
    # Host
    if "devices" in alert and isinstance(alert["devices"], list) and len(alert["devices"]) > 0:
        device_name = alert["devices"][0].get("deviceDnsName", "UnknownHost")
    else:
        device_name = alert.get("computerDnsName", "UnknownHost")

    # MITRE ATT&CK
    mitre_techniques = alert.get("mitreTechniques", [])
    if isinstance(mitre_techniques, list):
        mitre_str = ", ".join(filter(None, mitre_techniques))
    else:
        mitre_str = str(mitre_techniques)

    # IOCs (Filtrando valores nulos o vacíos)
    iocs = []
    evidence = alert.get("evidence", [])
    if isinstance(evidence, list):
        for ev in evidence:
            if isinstance(ev, dict):
                ip = ev.get("ipAddress")
                if ip and isinstance(ip, str):
                    iocs.append(ip)
                
                sha = ev.get("fileSha256")
                if sha and isinstance(sha, str):
                    iocs.append(sha)
            
    threat_name = alert.get("threatName")
    if threat_name and isinstance(threat_name, str):
        iocs.append(threat_name)

    # Generar un ID único
    event_id = hashlib.md5(f"{alert_id}-{device_name}-{title}".encode()).hexdigest()

    # 3. TRUCO PARA EL LÍMITE DE 500 CARACTERES
    # Cortamos la descripción si es muy larga para que el schema no falle
    short_description = description[:300] + "..." if len(description) > 300 else description
    summary = f"EDR Alert: {title}. {short_description} (Host: {device_name})"
    
    # Nos aseguramos de que el summary final no pase de 490 caracteres
    summary = summary[:490] + "..." if len(summary) > 490 else summary

    return {
        "event_id": event_id,
        "source": "endpoint",
        "timestamp": timestamp,
        "src": device_name,
        "dst": "unknown",
        "summary": summary,
        "iocs": iocs,
        "raw": {
            "alert_title": title,
            "severity_from_edr": severity,
            "mitre_from_edr": mitre_str,
            "description": description
        }
    }