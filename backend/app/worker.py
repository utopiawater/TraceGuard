import logging
import signal
import time
from typing import Optional

from app.core.settings import settings
from app.graph import RuntimeGraphProjector
from app.live import LiveRunService
from app.repositories import SQLiteRepository

LOGGER = logging.getLogger("traceguard.worker")


class Worker:
    """Persistent worker boundary for ingestion, correlation and Agent jobs."""

    def __init__(self, repository: SQLiteRepository, active_settings=settings, graph=None) -> None:
        self.repository = repository
        self.settings = active_settings
        self.graph = graph or RuntimeGraphProjector(active_settings.neo4j_uri, active_settings.neo4j_user, active_settings.neo4j_password, active_settings.neo4j_enabled)
        self.running = True

    def stop(self, *_args) -> None:
        self.running = False

    def run_once(self) -> int:
        service = LiveRunService(self.settings, self.repository, self.graph)
        return service.poll_once()

    def run_forever(self, interval_seconds: float = 1.0) -> None:
        signal.signal(signal.SIGINT, self.stop)
        signal.signal(signal.SIGTERM, self.stop)
        LOGGER.info("worker started")
        while self.running:
            started = time.monotonic()
            self.run_once()
            delay = max(interval_seconds - (time.monotonic() - started), 0.0)
            if delay > 0:
                time.sleep(delay)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    settings.ensure_directories()
    Worker(SQLiteRepository(settings.database_path), settings).run_forever(settings.live_poll_interval_seconds)


if __name__ == "__main__":
    main()
