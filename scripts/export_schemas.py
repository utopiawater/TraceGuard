import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.contracts.schema import publish_json_schemas


if __name__ == "__main__":
    written = publish_json_schemas(ROOT / "artifacts" / "schemas")
    print(json.dumps({name: str(path.relative_to(ROOT)) for name, path in written.items()}, ensure_ascii=False, indent=2))
