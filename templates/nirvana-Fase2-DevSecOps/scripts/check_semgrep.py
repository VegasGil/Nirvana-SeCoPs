import subprocess
import sys

print("Ejecutando Semgrep...")
result = subprocess.run(
    ["semgrep", "--config=p/javascript", "--config=p/nodejs", "sample-app/"],
    capture_output=True, text=True
)

print(result.stdout)
print(result.stderr)

# Si Semgrep encuentra las palabras clave de vulnerabilidad, forzamos el fallo
if "dangerous" in result.stdout or "injection" in result.stdout or "exec" in result.stdout or "eval" in result.stdout:
    print("🚨 VULNERABILIDADES ENCONTRADAS. Bloqueando el pipeline.")
    sys.exit(1)

print("✅ No se encontraron vulnerabilidades.")
sys.exit(0)