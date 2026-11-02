import subprocess
import requests
import yaml
import argparse
import urllib3
import urllib.parse

# Desactivar advertencias de certificados SSL (común en laboratorios)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def convert_sigma_to_splunk(rule_path):
    print(f"[*] Convirtiendo regla Sigma: {rule_path}")
    result = subprocess.run(
        ["sigma", "convert", "-t", "splunk", "--without-pipeline", rule_path],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"Error al convertir: {result.stderr}")
        return None
    
    query = result.stdout.strip()
    print(f"[*] Consulta SPL generada: {query}")
    return query

def deploy_to_splunk(query, rule_path, splunk_host, splunk_port, username, password):
    with open(rule_path, 'r', encoding='utf-8') as f:
        rule_data = yaml.safe_load(f)
    rule_title = f"Sigma - {rule_data.get('title', 'Custom Rule')}"

    print(f"[*] Procesando alerta '{rule_title}'...")

    base_url = f"https://{splunk_host}:{splunk_port}/services/saved/searches"
    encoded_name = urllib.parse.quote(rule_title)
    specific_url = f"{base_url}/{encoded_name}"

    payload = {
        "search": f"index=* {query}",
        "cron_schedule": "*/5 * * * *",
        "is_scheduled": "1",
        "alert_type": "number of events",
        "alert_comparator": "greater than",
        "alert_threshold": "0",
        "alert.severity": "4",
        "action.email": "0",
        # Estas dos líneas son las que envían la alerta a la pestaña "Triggered Alerts"
        "action.notable": "1", 
        "action.notable.param.severity": "high"
    }

    # 1. Verificar si la alerta ya existe (GET)
    check_response = requests.get(specific_url, auth=(username, password), verify=False)

    if check_response.status_code == 200:
        # SI EXISTE: Actualizar (POST a la URL específica sin el parámetro "name")
        print(f"[*] La alerta ya existe en Splunk. Actualizando configuración...")
        response = requests.post(
            specific_url,
            auth=(username, password),
            data=payload,
            verify=False
        )
    else:
        # NO EXISTE: Crear (POST a la URL base incluyendo el "name")
        print(f"[*] La alerta no existe. Creándola por primera vez...")
        payload["name"] = rule_title
        response = requests.post(
            base_url,
            auth=(username, password),
            data=payload,
            verify=False
        )

    # 3. Verificar resultado
    if response.status_code in [200, 201]:
        print(f"✅ ¡Alerta '{rule_title}' desplegada/actualizada con éxito en Splunk!")
    else:
        print(f"❌ Error al desplegar la alerta: {response.status_code}")
        print(response.text)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Despliega reglas Sigma en Splunk de forma idempotente.")
    parser.add_argument("--rule", required=True, help="Ruta al archivo YAML de Sigma")
    parser.add_argument("--host", required=True, help="IP o dominio de Splunk")
    parser.add_argument("--port", default="8089", help="Puerto de la API (por defecto 8089)")
    parser.add_argument("--user", default="admin", help="Usuario de Splunk")
    parser.add_argument("--password", required=True, help="Contraseña de Splunk")

    args = parser.parse_args()

    # 1. Convertir
    splunk_query = convert_sigma_to_splunk(args.rule)
    
    # 2. Desplegar
    if splunk_query:
        deploy_to_splunk(splunk_query, args.rule, args.host, args.port, args.user, args.password)