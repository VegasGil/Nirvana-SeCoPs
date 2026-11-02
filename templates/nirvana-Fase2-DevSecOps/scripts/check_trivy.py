import subprocess
import sys

print("Ejecutando Trivy...")
result = subprocess.run(
    ["trivy", "fs", "--scanners", "vuln", "--severity", "HIGH,CRITICAL", "sample-app/"],
    capture_output=True, text=True
)

print(result.stdout)
print(result.stderr)

# Si Trivy detecta CVEs (buscando el total de vulnerabilidades)
if "Total:" in result.stdout and "0 (" not in result.stdout:
    print("🚨 VULNERABILIDADES ENCONTRADAS. Bloqueando el pipeline.")
    sys.exit(1)

print("✅ No se encontraron vulnerabilidades.")
sys.exit(0)