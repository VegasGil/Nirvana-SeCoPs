import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from bot3_intel.threat_intel import enrich_event_iocs


# IOCs reales que quieres probar
iocs_to_test = ["82.202.170.126", "https://djpeepsproductions.com/"]

print(f"[*] Consultando VirusTotal para: {iocs_to_test}...")
resultados, contexto_para_ia = enrich_event_iocs(iocs_to_test)

print("\n=== 📊 REPORTE DE INTELIGENCIA (VirusTotal) ===")
for res in resultados:
    print(f" - {res['ioc']} ({res['type']}): {res['verdict'].upper()}")

print("\n=== 🧠 CONTEXTO QUE RECIBIRÁ LA IA (Ollama) ===")
print(contexto_para_ia)