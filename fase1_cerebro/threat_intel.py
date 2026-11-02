import json
import urllib.request
import gzip
from pathlib import Path

DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)

EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def update_threat_intel():
    print("[*] Actualizando Threat Intel (EPSS + KEV)...")
    
    # Descargar EPSS
    try:
        with urllib.request.urlopen(EPSS_URL, timeout=60) as resp:
            with gzip.open(resp, "rt", encoding="utf-8") as f:
                epss = {}
                for line in f:
                    if line.startswith("#") or line.startswith("cve,"): continue
                    parts = line.strip().split(",")
                    if len(parts) >= 2: epss[parts[0]] = float(parts[1])
        (DATA_DIR / "epss.json").write_text(json.dumps(epss))
    except Exception as e:
        print(f"⚠️ Error descargando EPSS: {e}")

    # Descargar KEV
    try:
        with urllib.request.urlopen(KEV_URL, timeout=60) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            kev = {v["cveID"] for v in data.get("vulnerabilities", [])}
        (DATA_DIR / "kev.json").write_text(json.dumps(list(kev)))
    except Exception as e:
        print(f"⚠️ Error descargando KEV: {e}")

def check_vulnerability(cve_id):
    """Devuelve (epss_score, is_in_kev)"""
    epss_score = 0.0
    is_in_kev = False

    epss_file = DATA_DIR / "epss.json"
    kev_file = DATA_DIR / "kev.json"

    if epss_file.exists():
        epss_data = json.loads(epss_file.read_text())
        epss_score = epss_data.get(cve_id, 0.0)

    if kev_file.exists():
        kev_data = set(json.loads(kev_file.read_text()))
        is_in_kev = cve_id in kev_data

    return epss_score, is_in_kev