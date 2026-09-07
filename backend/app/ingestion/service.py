from typing import Optional

from app.contracts import RawEventEnvelope
from app.repositories import SQLiteRepository

from .archive import RawArchive


class IngestionService:
    def __init__(self, repository: SQLiteRepository, archive: RawArchive) -> None:
        self.repository = repository
        self.archive = archive

    def accept(self, raw: RawEventEnvelope) -> Optional[RawEventEnvelope]:
        if self.repository.has_raw(raw.raw_id):
            return None
        archive_ref, _ = self.archive.append(raw)
        archived = raw.model_copy(update={"raw_ref": archive_ref})
        self.repository.put_raw(archived)
        return archived

