"""Parser de correos electrónicos: extrae cuerpo, remitentes e IOCs."""

import email
import hashlib
import re
from email import policy

# Regex básicos para IOCs
IP_REGEX = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
URL_REGEX = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
HASH_REGEX = r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{64}\b' # MD5 o SHA256

def extract_iocs(text: str) -> list[str]:
    """Busca IPs, URLs y Hashes en un texto."""
    iocs = set()
    iocs.update(re.findall(IP_REGEX, text))
    iocs.update(re.findall(URL_REGEX, text))
    iocs.update(re.findall(HASH_REGEX, text))
    return list(iocs)

def parse_eml(file_path: str) -> dict:
    """Lee un archivo .eml y devuelve un diccionario canónico para el pipeline."""
    with open(file_path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=policy.default)

    body = ""
    attachments = []

    # Recorrer las partes del correo (multipart)
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))

            if "attachment" in content_disposition:
                filename = part.get_filename()
                if filename:
                    payload = part.get_payload(decode=True)
                    sha256 = hashlib.sha256(payload).hexdigest()
                    attachments.append({"filename": filename, "sha256": sha256})
            elif content_type == "text/plain":
                body += part.get_content()
    else:
        body = msg.get_content()

    # Extraer IOCs del asunto + cuerpo
    full_text = f"{msg.get('Subject', '')} {body}"
    iocs = extract_iocs(full_text)
    
    # Añadir hashes de adjuntos a los IOCs
    for att in attachments:
        iocs.append(att["sha256"])

    # Generar un ID único basado en el Message-ID o un hash del cuerpo
    msg_id = msg.get("Message-ID", "")
    event_id = hashlib.md5((msg_id + body).encode()).hexdigest()

    return {
        "event_id": event_id,
        "source": "email",
        "timestamp": msg.get("Date", ""),
        "src": msg.get("From", "unknown"),
        "dst": msg.get("To", "unknown"),
        "summary": f"Email: {msg.get('Subject', 'No Subject')}",
        "iocs": iocs,
        "raw": {
            "subject": msg.get("Subject", ""),
            "body_snippet": body[:500] + ("..." if len(body) > 500 else ""),
            "attachments": attachments
        }
    }