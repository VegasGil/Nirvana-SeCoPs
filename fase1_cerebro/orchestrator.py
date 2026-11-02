# # import time
# # import logging
# # import json
# # from splunk_client import search, hec_send
# # from event_schema import INPUT_SCHEMA, normalize_event
# # from config import SYSTEM_PROMPT, VERDICT_SCHEMA, OLLAMA_URL, MODEL
# # import requests
# # import jsonschema

# # logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# # def triage(event_text):
# #     # Lógica para llamar a Ollama (igual que en tu script actual)
# #     payload = {
# #         "model": MODEL, "format": "json", "stream": False,
# #         "options": {"temperature": 0},
# #         "messages": [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": event_text}],
# #     }
# #     try:
# #         r = requests.post(OLLAMA_URL, json=payload, timeout=120)
# #         result = json.loads(r.json()["message"]["content"])
# #         jsonschema.validate(instance=result, schema=VERDICT_SCHEMA)
# #         return result
# #     except Exception as e:
# #         logging.error(f"Error IA: {e}")
# #         return None

# # def run_once():
# #     # Buscamos logs de Defender (o cualquier otro) en los últimos 5 minutos
# #     query = 'search index=* sourcetype="ms-defender" earliest=-5m'
# #     rows = search(query)
    
# #     for row in rows:
# #         # Normalizamos el evento
# #         event = normalize_event(row)
# #         event_text = event.get("summary", "")
        
# #         if not event_text:
# #             continue
            
# #         logging.info(f"Analizando: {event_text[:50]}...")
# #         verdict = triage(event_text)
        
# #         if verdict and verdict['verdict'] in ['malicious', 'suspicious']:
# #             logging.warning(f"¡Alerta! {verdict['verdict'].upper()} - {verdict['reason']}")
# #             # Guardamos el veredicto en Splunk
# #             hec_send({"event_id": event.get("event_id"), "verdict": verdict['verdict'], "reason": verdict['reason']})
# #         else:
# #             logging.info("Evento benigno. Ignorando.")

# # if __name__ == "__main__":
# #     logging.info("Iniciando Orquestador de SOC...")
# #     while True:
# #         try:
# #             run_once()
# #         except Exception as e:
# #             logging.error(f"Error en el ciclo: {e}")
# #         time.sleep(60)



# import time
# import logging
# import json
# import requests
# import jsonschema
# import os
# from dotenv import load_dotenv

# # Importaciones locales
# from splunk_client import search, hec_send
# from event_schema import INPUT_SCHEMA, normalize_event
# from config import SYSTEM_PROMPT, VERDICT_SCHEMA, OLLAMA_URL, MODEL

# load_dotenv()

# # --- CONFIGURACIÓN DE LOGGING (Para ver todo en la terminal) ---
# logging.basicConfig(
#     level=logging.INFO,
#     format="%(asctime)s [%(levelname)s] %(message)s",
#     force=True # Obliga a Python a mostrar los logs en la consola
# )
# log = logging.getLogger("orchestrator")

# def triage(event_text):
#     payload = {
#         "model": MODEL, "format": "json", "stream": False,
#         "options": {"temperature": 0},
#         "messages": [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": event_text}],
#     }
#     try:
#         r = requests.post(OLLAMA_URL, json=payload, timeout=120)
#         r.raise_for_status()
#         result = json.loads(r.json()["message"]["content"])
#         jsonschema.validate(instance=result, schema=VERDICT_SCHEMA)
#         return result
#     except Exception as e:
#         log.error(f"Error en la IA (Ollama): {e}")
#         return None

# def run_once():
#     # BUSCAMOS SOC_TEST (El que está usando en tu VM)
#     query = 'search index=* sourcetype="soc_test" earliest=-15m'
#     rows = search(query)
    
#     if not rows:
#         return 0
        
#     log.info(f"Se encontraron {len(rows)} eventos en Splunk. Procesando...")
    
#     count = 0
#     for row in rows:
#         event = normalize_event(row)
#         event_text = event.get("summary", "")
        
#         if not event_text:
#             continue
            
#         log.info(f"Analizando: {event_text[:60]}...")
#         verdict = triage(event_text)
        
#         if verdict:
#             log.warning(f"🚨 ALERTA: {verdict['verdict'].upper()} | Severidad: {verdict['severity']} | {verdict['reason']}")
            
#             # Guardamos el veredicto en Splunk (HEC)
#             output = {
#                 "event_id": event.get("event_id", "unknown"),
#                 "verdict": verdict['verdict'],
#                 "severity": verdict['severity'],
#                 "reason": verdict['reason']
#             }
#             exito = hec_send(output, sourcetype="nirvana:secops:verdict")
#             if exito:
#                 log.info("✅ Veredicto guardado en Splunk.")
#             else:
#                 log.error("❌ Falló el envío del veredicto a Splunk.")
                
#         count += 1
#     return count

# if __name__ == "__main__":
#     log.info("Iniciando Orquestador de SOC (Modo Debug)...")
#     while True:
#         try:
#             n = run_once()
#             if n == 0:
#                 log.info("[-] No hay alertas nuevas en los últimos 15 minutos.")
#         except Exception as e:
#             log.error(f"Error en el ciclo: {e}")
        
#         time.sleep(10) # Espera 10 segundos