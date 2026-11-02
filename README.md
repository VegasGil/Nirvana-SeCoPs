# Nirvana-SeCoPs: AI-Assisted SOC Triage & Enrichment Platform

[![Python](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/)
[![Ollama](https://img.shields.io/badge/AI-Ollama%20(Local)-orange.svg)](https://ollama.com/)
[![Splunk](https://img.shields.io/badge/SIEM-Splunk-green.svg)](https://www.splunk.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Nirvana-SeCoPs** es un proyecto de portafolio que demuestra la construcción de una arquitectura SOC moderna, integrando **Detección (SIEM), Automatización (SOAR) e Inteligencia Artificial (LLM)** local para la clasificación, enriquecimiento y triaje de alertas de seguridad, manteniendo siempre al humano en el bucle de decisión (*Human-in-the-loop*).

## 🏗️ La Visión (Arquitectura del Flujo)

El objetivo final es automatizar el flujo desde que salta una alerta hasta que el analista toma una decisión:

1.  **Recolección:** Ingesta de eventos (Logs de red con Suricata, alertas de Endpoint con Defender, o correos de Phishing).
2.  **SIEM (Splunk):** Centralización de la telemetría y correlación básica.
3.  **Cerebro (SOAR + IA):** Un script en Python lee la alerta, extrae los Indicadores de Compromiso (IOCs) y utiliza un LLM local (`qwen2.5:3b` vía Ollama) para generar un veredicto estructurado en JSON (Severidad, Explicación, Recomendación).
4.  **Decisión Humana (Slack):** El veredicto se envía a un canal de Slack con botones interactivos para que el analista apruebe, rechace o escale.
5.  **Feedback:** La decisión se registra de vuelta en Splunk para mejorar las detecciones futuras.

## 📦 Estructura del Repositorio y Plantillas Base

Este proyecto no empieza de cero. Se apoya en herramientas modulares previamente desarrolladas (ubicadas en la carpeta `templates/`) para garantizar la seguridad del código y la infraestructura:

-   **`templates/fase1-detection`:** Plantilla de Detection-as-Code. Contiene reglas Sigma, tests unitarios (pytest) y despliegue automatizado a Splunk vía CI/CD.
-   **`templates/fase2-devsecops`:** Plantilla de DevSecOps. Pipeline de GitHub Actions con SAST (Semgrep) y SCA (Trivy) que bloquea código vulnerable y envía reportes al SIEM.
-   **`templates/fase3-aspm`:** Plantilla de Application Security Posture Management. Motor de priorización de vulnerabilidades usando inteligencia de amenazas (EPSS y CISA KEV).

## 🚀 Estado del Proyecto (Fases de Desarrollo)

El desarrollo de Nirvana se está realizando de forma incremental:

-   [x] **Configuración del entorno:** Instalación de Ollama local y despliegue del modelo `qwen2.5:3b` en GPU.
-   [x] **Integración de Plantillas:** Estructura base y reutilización de las fases 1, 2 y 3.
-   [ ] **Fase 1 (El Cerebro):** Desarrollo del script `soc_assistant.py` para la comunicación con la IA local y validación de respuestas JSON.
-   [ ] **Fase 2 (El SIEM):** Conexión del script a la API REST de Splunk.
-   [ ] **Fase 3 (Vector Humano):** Ingesta de correos e IOCs.
-   [ ] **Fase 4 (Red/Endpoint):** Integración con Suricata y simulación de Defender.
-   [ ] **Fase 5 (Human-in-the-loop):** Integración de Slack y feedback.

## 🛠️ Instalación y Uso (Entorno Local)

Para replicar este entorno, se necesita:
1.  [Ollama](https://ollama.com/) instalado y el modelo descargado (`ollama run qwen2.5:3b`).
2.  Python 3.12+
3.  Docker (para Splunk)

*(Las instrucciones detalladas para cada fase se irán añadiendo a medida que avance el proyecto).*

## 📄 Licencia

Este proyecto está bajo la Licencia MIT. Consulta el archivo `LICENSE` para más detalles.

---
*Desarrollado por Freddy Vegas como parte de su portafolio de Seguridad y DevSecOps.*