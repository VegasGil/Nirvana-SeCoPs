"""Herramienta para probar el flujo E2E de alertas de Microsoft Defender."""

import sys
import os
import json

# Arreglo de rutas para ejecutar desde la raíz
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from bot5_endpoint.defender_parser import parse_defender_alert
from bot2_siem.splunk_client import hec_send
from bot1_cerebro.soc_assistant import triage

def run_defender_test():
    print("🛡️  Iniciando prueba de Endpoint (Microsoft Defender)...")
    
    # 1. Leer la alerta de ejemplo
    file_path = "data/samples/defender_alert.json"
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            alert_data = json.load(f)
    except FileNotFoundError:
        print(f"❌ Error: No se encontró el archivo {file_path}")
        return

    # 2. Parsear al formato canónico
    event = parse_defender_alert(alert_data)
    
    # 3. Enviar al SIEM (Oracle o Local, según tu .env)
    print("   -> Enviando evento crudo a Splunk...")
    try:
        hec_send(event, sourcetype="nirvana:secops:event")
        print("   ✅ Evento inyectado en Splunk.")
    except Exception as e:
        print(f"   ⚠️ Error enviando a Splunk: {e}")

    # 4. Consultar a la IA (Ollama)
    print("   -> Solicitando análisis a la IA (Ollama)...")
    try:
        verdict = triage(event)
        print("\n=== 🧠 VEREDICTO DE LA IA ===")
        print(json.dumps(verdict, indent=2))
    except Exception as e:
        print(f"   ❌ Error en la IA: {e}")

if __name__ == "__main__":
    run_defender_test()