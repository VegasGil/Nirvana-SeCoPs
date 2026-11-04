import sys
import os
import json

# Arreglo de rutas
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from bot2_siem.splunk_client import search
from bot2_siem.orchestrator import process_batch

def run():
    print("🔍 Buscando alertas de Defender en las últimas 24h...")
    # Usamos comillas simples en la consulta para evitar problemas
    query = 'index=* sourcetype="ms:defender:atp:alerts"'
    rows = search(query, earliest="-24h")
    
    print(f"✅ Encontradas {len(rows)} alertas en Splunk.")
    
    if len(rows) > 0:
        print("🧠 Enviando a la IA y Slack...")
        stats = process_batch(rows)
        print(json.dumps(stats, indent=2))
    else:
        print("⚠️ No se encontraron alertas en ese rango de tiempo.")

if __name__ == "__main__":
    run()