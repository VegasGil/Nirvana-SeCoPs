# Template: Fase 1 - Detection-as-Code (Linux)
Las grandes empresas no configuran la seguridad desde cero en cada proyecto; tienen repositorios base (templates) que los desarrolladores clonan.
Plantilla base para inicializar la validación de reglas de detección (Sigma) para servidores Linux.

## Cómo usar esta plantilla
1. Haz clic en "Use this template" en GitHub para crear un nuevo repositorio.
2. Clona tu nuevo repositorio.
3. Crea un entorno virtual: `python -m venv .venv`
4. Activa el entorno: `.venv\Scripts\activate`
5. Instala dependencias: `python -m pip install -r requirements.txt`
6. Instala los hooks: `pre-commit install`
7. Prueba que todo funciona: `python -m pytest -v`

## Añadir una nueva regla
1. Crea tu YAML en `detections/linux/`.
2. Crea el archivo de eventos en `tests/events/` con el mismo nombre.
3. Ejecuta `pytest -v` para validar que la lógica funciona.
pip freeze > requirements.txt

## Nota sobre el SIEM (Splunk)
Para que la regla Sigma funcione con logs de texto plano, es necesario configurar una extracción de campos (Field Extraction) en Splunk para el `sourcetype` correspondiente, mapeando el campo `CommandLine` al texto del evento. En entornos reales con Sysmon o Auditd, esta extracción ya viene preconfigurada por los Add-ons oficiales.