from pathlib import Path
from typing import Literal
import os

from pydantic import BaseModel
from dotenv import load_dotenv


load_dotenv(Path(__file__).parents[3] / ".env")


class Settings(BaseModel):
    app_name: str = "TraceGuard"
    mode: Literal["live", "replay", "snapshot"] = os.getenv("TRACEGUARD_MODE", "replay")
    data_dir: Path = Path(os.getenv("TRACEGUARD_DATA_DIR", "data"))
    database_path: Path = Path(os.getenv("TRACEGUARD_DATABASE_PATH", "data/traceguard.db"))
    raw_archive_dir: Path = Path(os.getenv("TRACEGUARD_RAW_ARCHIVE_DIR", "data/raw"))
    attack_version: str = "19.2"
    neo4j_enabled: bool = os.getenv("TRACEGUARD_NEO4J_ENABLED", "true").lower() in {"1", "true", "yes"}
    neo4j_uri: str = os.getenv("TRACEGUARD_NEO4J_URI", "bolt://127.0.0.1:7687")
    neo4j_user: str = os.getenv("TRACEGUARD_NEO4J_USER", "neo4j")
    neo4j_password: str = os.getenv("TRACEGUARD_NEO4J_PASSWORD", "traceguard-dev")
    llm_base_url: str = os.getenv("LLM_BASE_URL", "")
    llm_api_key: str = os.getenv("LLM_API_KEY", "")
    llm_model: str = os.getenv("LLM_MODEL", "")
    llm_timeout_seconds: float = float(os.getenv("LLM_TIMEOUT_SECONDS", "180"))
    report_dir: Path = Path(os.getenv("TRACEGUARD_REPORT_DIR", "data/reports"))
    live_poll_interval_seconds: float = float(os.getenv("TRACEGUARD_LIVE_POLL_INTERVAL_SECONDS", "2"))
    live_micro_batch_size: int = int(os.getenv("TRACEGUARD_LIVE_MICRO_BATCH_SIZE", "50"))
    demo_bundle_path: str = os.getenv("TRACEGUARD_DEMO_BUNDLE_PATH", "")
    demo_replay_time_compression: float = float(os.getenv("TRACEGUARD_DEMO_REPLAY_TIME_COMPRESSION", "60"))
    live_replay_path: str = os.getenv("TRACEGUARD_LIVE_REPLAY_PATH", "")
    wazuh_jsonl_paths: str = os.getenv("TRACEGUARD_WAZUH_JSONL_PATHS", "")
    zeek_log_roots: str = os.getenv("TRACEGUARD_ZEEK_LOG_ROOTS", "")

    def ensure_directories(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.raw_archive_dir.mkdir(parents=True, exist_ok=True)
        self.report_dir.mkdir(parents=True, exist_ok=True)


settings = Settings()
