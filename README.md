#  Nirvana-SeCoPs: AI-Assisted SOC Triage & Enrichment Platform

[![Python](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/)
[![Ollama](https://img.shields.io/badge/AI-Ollama%20(Local)-orange.svg)](https://ollama.com/)
[![Splunk](https://img.shields.io/badge/SIEM-Splunk-green.svg)](https://www.splunk.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Nirvana-SeCoPs** es un proyecto de portafolio que demuestra la construcción de una arquitectura SOC moderna, integrando **Detección (SIEM), Automatización (SOAR) e Inteligencia Artificial (LLM)** local para la clasificación, enriquecimiento y triaje de alertas de seguridad, manteniendo siempre al humano en el bucle de decisión (*Human-in-the-loop*).

##  Arquitectura del Flujo

El proyecto está diseñado de forma modular para procesar telemetría de múltiples fuentes y enriquecerla con inteligencia de amenazas.

```mermaid
graph LR
    A[Linux Logs] -->|Ingesta| B(Splunk)
    C[MS Defender] -->|Ingesta| B
    D[Trivy ASPM] -->|Ingesta| B
    B -->|Extrae Eventos| E(Orquestador Python)
    E <-->|API| F[EPSS & CISA KEV]
    E -->|Analiza Contexto| G(IA Local - Ollama)
    G -->|Veredicto JSON| E
    E -->|Guarda Evidencia| B
    E -->|Alerta HITL| H[Slack]

 Componentes Principales

    Orquestador (splunk_reader.py): El núcleo del sistema. Busca alertas en Splunk (Logs de Linux, Defender, Trivy), evita duplicados usando memoria local (sent_alerts.json) y coordina el flujo.

    Cerebro IA (config.py / Ollama): Utiliza el LLM local qwen2.5:3b. Recibe el evento, lo analiza basándose en reglas heurísticas (MITRE ATT&CK) y devuelve un JSON estricto (verdict, severity, reason).

    Threat Intel (threat_intel.py): Enriquecimiento automático cruzando las vulnerabilidades (CVEs) con las bases de datos de EPSS (probabilidad de exploit) y CISA KEV (explotación activa).

    Feedback Loop (Splunk HEC): Los veredictos generados por la IA se inyectan de vuelta en Splunk para auditoría y compliance.

    Human-in-the-loop (Slack): Notificación en tiempo real con botones de acción (Aprobar / Ignorar / Escalar) para evitar la fatiga de alertas.

 Estado del Proyecto (Roadmap)

    ☑

    Fase 1 (El Cerebro): Integración con Ollama, validación de esquemas JSON estrictos y resiliencia (retries).
    ☑

    Fase 2 (El SIEM): Conexión con Splunk, lectura por ventana de tiempo (checkpointing) e inyección de veredictos vía HEC.
    ☑

    Fase 3 (Multi-Fuente e Intel): Ingesta de Logs, Defender y Trivy. Enriquecimiento con CISA KEV/EPSS y notificaciones a Slack.
    □

    Fase 4 (Red/Endpoint): Integración en vivo con Suricata (IDS) y Microsoft Defender (Live Response API).
    □

    Fase 5 (Acciones Automáticas): Implementación de un endpoint (Webhook) para recibir las respuestas de Slack y automatizar bloqueos o aislamientos de máquinas.

 Evaluación de la IA (Golden Dataset)

El prompt del LLM ha sido evaluado contra un dataset de 7 eventos que simulan técnicas MITRE ATT&CK (Ransomware, SQLi, Reverse Shells, Cryptojacking, etc.) mediante el script test_ai.py.

    Precisión: 7/7 (100%)

    Falsos Positivos: 0

    Latencia: ~4 segundos por evento en GPU (RTX 3050 Ti).

 Instalación y Uso (Entorno Local)

    Clona el repositorio e instala las dependencias:
    bash

    pip install -r requirements.txt

    Configura tus variables de entorno en un archivo .env:
    env

    SPLUNK_HOST=82.70.86.75
    SPLUNK_PORT=8089
    SPLUNK_USER=admin
    SPLUNK_PASS=tu_contraseña
    HEC_TOKEN=tu_hec_token
    SLACK_WEBHOOK_URL=tu_webhook

    Inicia Ollama y asegúrate de tener el modelo descargado:
    bash

    ollama run qwen2.5:3b

    Ejecuta el orquestador principal:
    bash

    cd fase1_cerebro
    python splunk_reader.py

 Testing y CI/CD

El proyecto cuenta con un pipeline de GitHub Actions (.github/workflows/nirvana-ci.yml) que valida:

    Pytest: 24 tests unitarios (Mocks para Splunk y Ollama).

    Semgrep (SAST): Análisis estático de seguridad en el código Python.

    Sigma/Trivy: Validación de reglas de detección y escaneo de vulnerabilidades (SCA).

Desarrollado por Freddy Vegas como parte de su portafolio de Seguridad y DevSecOps.