FROM python:3.11-slim-bullseye

WORKDIR /app

# Instalar dependencias de Python (ya no necesitamos curl)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el código
COPY . .

# Comando por defecto
CMD ["python", "-m", "tools.simulator"]