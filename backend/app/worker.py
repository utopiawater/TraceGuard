import logging
import signal
import time
from typing import Optional

from app.core.settings import settings
from app.repositories import SQLiteRepository

LOGGER = logging.getLogger("traceguard.worker")


class Worker:
    """Persistent worker boundary for ingestion, correlation and Agent jobs."""

    def __init__(self, repository: SQLiteRepository) -> None:
        self.repository = repository
        self.running = True

    def stop(self, *_args) -> None:
        self.running = False

    def run_once(self) -> int:
        # Job handlers are registered here as their final modules are enabled.
        # Returning zero is an explicit idle state, never a simulated success.
        return 0

    def run_forever(self, interval_seconds: float = 1.0) -> None:
        signal.signal(signal.SIGINT, self.stop)
        signal.signal(signal.SIGTERM, self.stop)
        LOGGER.info("worker started")
        while self.running:
            if self.run_once() == 0:
                time.sleep(interval_seconds)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    settings.ensure_directories()
    Worker(SQLiteRepository(settings.database_path)).run_forever()


if __name__ == "__main__":
    main()
