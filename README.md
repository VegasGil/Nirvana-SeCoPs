# 🛡️ Nirvana-SeCoPs: AI-Assisted SOC & SOAR Platform

[![Python](https://img.shields.io/badge/Python-3.11-blue.svg)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://www.docker.com/)
[![Ollama](https://img.shields.io/badge/AI-Ollama%20(Local)-orange.svg)](https://ollama.com/)
[![Splunk](https://img.shields.io/badge/SIEM-Splunk-green.svg)](https://www.splunk.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Nirvana-SeCoPs** es una plataforma de automatización de SOC (SOAR) que integra **SIEM (Splunk)**, **Inteligencia Artificial Local (Ollama)** y **Threat Intelligence** para clasificar, enriquecer y responder a alertas de seguridad, manteniendo siempre al humano en el bucle de decisión (*Human-in-the-loop*).

> 🎥 **[Mira el video demo aquí]** *(Próximamente - YouTube/Loom)*

## 🏗️ Arquitectura del Flujo (Microservicios)

El proyecto está diseñado de forma modular. Cada "Bot" tiene una responsabilidad única, lo que permite escalarlo sin romper el sistema.

```mermaid
graph LR
    A[Email / Logs] -->|Ingesta| B(Bot 4: Human Vector)
    B -->|Extrae IOCs| C(Bot 3: Threat Intel)
    C <-->|API| VT[VirusTotal]
    B -->|Envía Contexto| D(Bot 1: Cerebro / Ollama)
    D -->|Veredicto JSON| E(Bot 2: SIEM / Splunk)
    E -->|Indexa Alerta| E
    D -->|Alerta HITL| F[Slack / Human-in-the-loop]

🤖 Los Bots (Componentes)

    Bot 1 (Cerebro): Utiliza el LLM local qwen2.5:3b vía Ollama. Recibe el evento, lo analiza con reglas MITRE ATT&CK y devuelve un JSON estricto (verdict, severity, reason, recommendation).

    Bot 2 (SIEM): Cliente en Python para interactuar con la API REST y el HEC de Splunk. Lee eventos, procesa veredictos y evita duplicados usando checkpointing.

    Bot 3 (Threat Intel): Integración con la API de VirusTotal para el enriquecimiento de IOCs.

    Bot 4 (Human Vector): Parser de correos electrónicos (.eml), extracción de IOCs e integración con Slack.

🚀 Despliegue Rápido (Docker)

Este proyecto está 100% dockerizado. Puedes levantar todo el laboratorio (Splunk local + Bots) en tu propia computadora con un solo comando.
Opción A: Modo Demo (Sin GPU / Sin Ollama)

Ideal para probar el flujo rápidamente. Usa una IA simulada (Mock) para generar veredictos.

    Clona el repositorio:
    bash

    git clone https://github.com/tu-usuario/nirvana-secops.git
    cd nirvana-secops

    Levanta el laboratorio:
    bash

    docker compose up -d

    Accede a Splunk en tu navegador: http://localhost:8000 (User: admin, Pass: TuPasswordSeguro123).

    Ejecuta el simulador de ataques:
    bash

    docker compose run --rm app python -m tools.simulator

Opción B: Modo Producción (Con IA Real)

Si tienes Ollama instalado y una GPU, puedes usar el modelo real qwen2.5:3b.

    En el archivo .env.demo, cambia AI_PROVIDER=mock por AI_PROVIDER=ollama.

    Levanta el laboratorio:
    bash

    docker compose up -d --build

🧠 Evaluación de la IA (Golden Dataset)

El prompt del LLM ha sido evaluado contra un dataset de 7 eventos MITRE ATT&CK (Ransomware, SQLi, Reverse Shells, Cryptojacking, etc.) mediante tools/benchmark_ai.py.

    Precisión: 7/7 (100%)

    Falsos Positivos: 0

    Latencia: ~4 segundos por evento en GPU (RTX 3050 Ti).

🧪 Testing y CI/CD

El proyecto cuenta con un pipeline de GitHub Actions (.github/workflows/nirvana-ci.yml) que valida:

    Pytest: 24 tests unitarios (Mocks para Splunk y Ollama).

    Semgrep (SAST): Análisis estático de seguridad en el código Python.

    Sigma/Trivy: Validación de reglas de detección y escaneo de vulnerabilidades.

Desarrollado por Freddy Vegas como parte de su portafolio de Ciberseguridad y DevSecOps.