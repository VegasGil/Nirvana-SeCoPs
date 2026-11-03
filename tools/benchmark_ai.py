import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import json
import logging
from bot1_cerebro.soc_assistant import triage

logging.basicConfig(level=logging.WARNING) # Silenciar los logs INFO de Ollama para ver mejor los resultados

def run_benchmark():
    with open("tests/fixtures/benchmark_events.json", "r") as f:
        tests = json.load(f)

    print(f"\n🚀 Iniciando Benchmark de IA ({len(tests)} eventos)...\n")
    
    passed = 0
    
    for t in tests:
        # Creamos un evento canónico falso para pasárselo a la IA
        event = {
            "event_id": t["id"],
            "source": "endpoint",
            "timestamp": "2026-11-03T00:00:00Z",
            "summary": t["event"]
        }
        
        print(f"[{t['id']}] {t['name']}...", end=" ", flush=True)
        
        try:
            # Llamamos a Ollama
            result = triage(event)
            verdict = result['verdict']
            
            if verdict == t['expected_verdict']:
                print(f"✅ OK ({verdict})")
                passed += 1
            else:
                print(f"❌ FALLO. Esperado: {t['expected_verdict']}, IA dijo: {verdict}")
                print(f"      Razón IA: {result['reason']}")
        except Exception as e:
            print(f"💥 ERROR: {e}")

    print(f"\n📊 RESULTADO FINAL: {passed}/{len(tests)} acertados ({(passed/len(tests))*100:.1f}%)\n")

if __name__ == "__main__":
    run_benchmark()