import json
from pathlib import Path
from typing import Tuple

from app.contracts import RawEventEnvelope


class RawArchive:
    """Append-only NDJSON archive. The returned ref includes the byte offset."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def append(self, envelope: RawEventEnvelope) -> Tuple[str, int]:
        day = envelope.observed_time.strftime("%Y-%m-%d")
        target = self.root / envelope.source.kind.value / (day + ".ndjson")
        target.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(envelope.model_dump(mode="json"), ensure_ascii=False, sort_keys=True) + "\n"
        with target.open("ab") as stream:
            offset = stream.tell()
            stream.write(line.encode("utf-8"))
            stream.flush()
        return "%s#byte=%d" % (target.as_posix(), offset), offset

