"""Inyecta N eventos de prueba en Splunk con sourcetype=nirvana:secops:event."""

import argparse
import time

from bot2_siem.splunk_client import hec_send

EVENT_TEMPLATE = {
    "event_id": None,           # se rellena por iteracion
    "source_kind": "email",
    "timestamp": None,          # se rellena
    "src": "ceo@evil-domain.tld",
    "dst": "cfo@corp.local",
    "summary": "Urgent invoice with invoice.exe attachment",
    "iocs": ["evil-domain.tld", "invoice.exe"],
}


def main(n: int, prefix: str) -> None:
    for i in range(n):
        eid = f"{prefix}-{int(time.time())}-{i:03d}"
        payload = dict(EVENT_TEMPLATE)
        payload["event_id"] = eid
        payload["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        hec_send(payload, sourcetype="nirvana:secops:event", source="injector")
        print(f"✅ Injected {eid}")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("n", type=int, nargs="?", default=1, help="numero de eventos")
    p.add_argument("--prefix", default="evt-smoke", help="prefijo de event_id")
    args = p.parse_args()
    main(args.n, args.prefix)