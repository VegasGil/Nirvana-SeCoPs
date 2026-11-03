import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import json
from bot4_human_vector.email_parser import parse_eml
from bot3_intel.threat_intel import enrich_event_iocs
from bot1_cerebro.soc_assistant import triage

def run_test():
    print("[*] 1. Parseando correo (data/samples/test_email.eml)...")
    # CAMBIO AQUÍ: Ahora busca en data/samples/
    evt = parse_eml('data/samples/test_email.eml')
    
    # Forzamos los IOCs reales que sabes que son maliciosos para la prueba
    evt['iocs'] = ["82.202.170.126", "https://djpeepsproductions.com/"]
    
    print("[*] 2. Consultando VirusTotal...")
    res, vt_context = enrich_event_iocs(evt['iocs'])
    print(vt_context)
    
    evt['raw']['threat_intel_context'] = vt_context
    
    print("\n[*] 3. Enviando a Ollama (qwen2.5:3b) para el veredicto final...")
    verdict = triage(evt)
    
    print("\n=== 🧠 VEREDICTO FINAL DE LA IA (OLLAMA) ===")
    print(json.dumps(verdict, indent=2))

if __name__ == "__main__":
    run_test()