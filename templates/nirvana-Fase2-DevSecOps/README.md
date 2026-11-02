# SecureCloud-Pipeline - Fase 2 (DevSecOps)

[![Detection CI](https://github.com/VegasGil/SecureCloud-Pipeline_v1/actions/workflows/detection-ci.yml/badge.svg)](https://github.com/VegasGil/SecureCloud-Pipeline_v1/actions/workflows/detection-ci.yml)
[![SAST CI](https://github.com/VegasGil/Template-Fase2-DevSecOps/actions/workflows/sast-ci.yml/badge.svg)](https://github.com/VegasGil/Template-Fase2-DevSecOps/actions/workflows/sast-ci.yml)
[![SCA CI](https://github.com/VegasGil/Template-Fase2-DevSecOps/actions/workflows/sca-ci.yml/badge.svg)](https://github.com/VegasGil/Template-Fase2-DevSecOps/actions/workflows/sca-ci.yml)
[![IaC CI](https://github.com/VegasGil/SecureCloud-Pipeline_v1/actions/workflows/iac-ci.yml/badge.svg)](https://github.com/VegasGil/SecureCloud-Pipeline_v1/actions/workflows/iac-ci.yml)

Pipeline incremental de seguridad que combina **Detection-as-Code**, **DevSecOps** y **gestión de exposición** sobre un stack Terraform + Kubernetes + Python.

## 📌 Sobre esta plantilla (Fase 2)
Esta plantilla está diseñada para añadir análisis de seguridad a proyectos en Node.js/React y enviar los resultados a un SIEM (Splunk) para monitorización **ASPM** (Application Security Posture Management).

### ¿Qué incluye?
- **SAST (Semgrep):** Analiza el código fuente buscando malas prácticas y vulnerabilidades (ej. inyecciones de comandos).
- **SCA (Trivy):** Analiza `package.json` y dependencias buscando CVEs conocidos en librerías (ej. Express, Lodash).
- **Integración SIEM:** Si se encuentra una vulnerabilidad HIGH o CRITICAL, el workflow bloquea el código (rojo) y envía un JSON con los detalles a Splunk para que el equipo de seguridad lo visualice.

---

## 🚀 Cómo usar esta plantilla en tu proyecto

1. Haz clic en el botón **"Use this template"** en GitHub para crear un nuevo repositorio.
2. Borra la carpeta `sample-app/` (es solo un entorno de prueba para validar que los escáneres funcionan).
3. Copia tu carpeta `frontend/` (React) y `backend/` (Node).
4. En los archivos `.github/workflows/sast-ci.yml` y `sca-ci.yml`, cambia las rutas `sample-app/` por las rutas reales de tu proyecto (`backend/ frontend/`).
5. **Configuración de Splunk:**
   - Ve a `Settings -> Secrets and variables -> Actions` en tu repositorio.
   - Crea un nuevo secreto llamado `SPLUNK_HOST` con la IP de tu servidor Splunk (ej. `82.70.86.75`).
6. Sube los cambios (`git push`).

---

## ⚠️ Nota importante sobre los Badges (Colores)
Es normal ver los badges de **SAST CI** y **SCA CI** en rojo (`failing`). Esto es **intencional y demuestra que el pipeline funciona**:
- La carpeta `sample-app/` contiene vulnerabilidades diseñadas a propósito (inyección de comandos y dependencias antiguas).
- Los escáneres las detectan, bloquean el despliegue y notifican a Splunk.
- Una vez que uses esta plantilla con tu código limpio, los badges se pondrán en verde automáticamente.