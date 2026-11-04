import sys
import os
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from bot5_endpoint.defender_parser import parse_defender_alert
from bot2_siem.orchestrator import send_to_slack
from bot1_cerebro.soc_assistant import triage

def run_test():
    print("🧠 Leyendo alerta de Defender y analizando con IA...")
    with open("data/samples/defender_alert.json", "r", encoding="utf-8") as f:
        alert = json.load(f)
        
    evt = parse_defender_alert(alert)
    verdict = triage(evt)

    # Imprimimos el JSON en consola para que veas la magia
    print("\n=== 🧠 VEREDICTO DE LA IA ===")
    print(json.dumps(verdict, indent=2))
    print("=============================\n")

    print("💬 Enviando alerta a Slack...")
    send_to_slack(evt["summary"], verdict, "Microsoft Defender EDR")
    print("✅ Prueba finalizada.")

if __name__ == "__main__":
    run_test()