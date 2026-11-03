"""Runner Fase 2: bucle de polling contra Splunk. Ctrl+C para salir limpio."""

import logging
import time

from bot2_siem.orchestrator import run_once

POLL_INTERVAL_SECONDS = 30

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("run_fase2")


def main() -> None:
    log.info("Fase 2 runner started. Polling every %ds. Ctrl+C to stop.", POLL_INTERVAL_SECONDS)
    try:
        while True:
            try:
                stats = run_once()
                if any(stats[k] for k in ("processed", "skipped_dup", "skipped_invalid", "failed")):
                    log.info("Cycle stats: %s", stats)
            except Exception as e:
                log.error("Cycle failed: %s", e)
            time.sleep(POLL_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        log.info("Stopped by user. Bye.")


if __name__ == "__main__":
    main()