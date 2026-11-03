"""Módulo de Threat Intelligence: consulta VirusTotal para IOCs."""

import os
import logging
import base64
import vt
from dotenv import load_dotenv

load_dotenv()
log = logging.getLogger("threat_intel")

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")


def check_ioc_vt(ioc: str) -> dict:
    """
    Consulta VirusTotal para una IP, dominio o hash.
    Devuelve un dict con el resultado o vacío si falla.
    """
    if not VT_API_KEY:
        log.warning("VIRUSTOTAL_API_KEY no configurada.")
        return {}

    # Determinar el tipo de IOC
    ioc_type = "unknown"
    if ioc.count(".") == 3 and not ioc.startswith("http"):
        ioc_type = "ip_address"
    elif ioc.startswith("http"):
        ioc_type = "url"
    elif len(ioc) in (32, 64) and all(c in "0123456789abcdefABCDEF" for c in ioc):
        ioc_type = "file"
    else:
        ioc_type = "domain"

    try:
        with vt.Client(VT_API_KEY) as client:
            if ioc_type == "ip_address":
                obj = client.get_object(f"/ip_addresses/{ioc}")
                stats = obj.last_analysis_stats
            elif ioc_type == "url":
                # Para URLs, VT pide un ID codificado (base64 sin padding)
                url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
                obj = client.get_object(f"/urls/{url_id}")
                stats = obj.last_analysis_stats
            elif ioc_type == "file":
                obj = client.get_object(f"/files/{ioc}")
                stats = obj.last_analysis_stats
            else:
                obj = client.get_object(f"/domains/{ioc}")
                stats = obj.last_analysis_stats

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            
            return {
                "ioc": ioc,
                "type": ioc_type,
                "malicious": malicious,
                "suspicious": suspicious,
                "verdict": "malicious" if malicious > 0 else "clean"
            }
            
    except vt.error.APIError as e:
        # Si VT no conoce el IOC (NotFoundError) u otro error de API (como Rate Limit)
        log.warning("VT API no tiene reportes para %s (%s)", ioc, e.code)
        return {"ioc": ioc, "type": ioc_type, "verdict": "unknown"}
    except Exception as e:
        log.error("Error consultando VT para %s: %s", ioc, e)
        return {"ioc": ioc, "type": ioc_type, "verdict": "error"}


def enrich_event_iocs(iocs: list[str]) -> tuple[list[dict], str]:
    """
    Enriquece una lista de IOCs.
    Devuelve (resultados, texto_extra_para_ollama).
    """
    results = []
    vt_context = ""
    
    for ioc in iocs:
        res = check_ioc_vt(ioc)
        if res:
            results.append(res)
            if res["verdict"] == "malicious":
                vt_context += f"\n[VT ALERT] IOC {ioc} is MALICIOUS ({res['malicious']} engines)."
            elif res["verdict"] == "clean":
                vt_context += f"\n[VT CLEAN] IOC {ioc} is clean."
            else:
                vt_context += f"\n[VT UNKNOWN] IOC {ioc} has no reports."
                
    return results, vt_context