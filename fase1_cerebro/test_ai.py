import json
import requests
import urllib3
import time
from dotenv import load_dotenv
from config import OLLAMA_URL, MODEL, SYSTEM_PROMPT

load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def test_ai():
    print("[*] Iniciando pruebas de validación de la IA (Golden Dataset)...")
    
    with open("test_events/test_events.json", "r", encoding="utf-8") as f:
        tests = json.load(f)

    passed = 0
    total = len(tests)

    for t in tests:
        print(f"\n--- Prueba {t['id']}: {t['name']} ---")
        print(f"Input: {t['event']}")
        
        payload = {
            "model": MODEL, "format": "json", "stream": False,
            "options": {"temperature": 0},
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": t['event']},
            ],
        }

        try:
            r = requests.post(OLLAMA_URL, json=payload, timeout=120)
            r.raise_for_status()
            result = json.loads(r.json()["message"]["content"])
            
            print(f"IA Output: {json.dumps(result, indent=2)}")
            
            if result['verdict'] == t['expected_verdict']:
                print(f"✅ PASÓ: La IA clasificó correctamente como '{t['expected_verdict']}'.")
                passed += 1
            else:
                print(f"❌ FALLÓ: Se esperaba '{t['expected_verdict']}' pero la IA dijo '{result['verdict']}'.")
                
        except Exception as e:
            print(f"❌ Error en la petición a Ollama: {e}")
            
        time.sleep(1)

    print(f"\n=== RESULTADO FINAL: {passed}/{total} pruebas superadas ===")
    if passed == total:
        print("🏆 ¡El modelo de IA está listo para producción!")

if __name__ == "__main__":
    test_ai()