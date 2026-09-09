import json
import sqlite3
from pathlib import Path
from typing import Any, Iterable, List, Optional, Sequence, Type, TypeVar

from pydantic import BaseModel

from app.contracts import AgentResult, AgentTask, AttackChain, DetectionResult, Evidence, RawEventEnvelope, Session, UnifiedSecurityEvent
from app.core.time import utc_now

T = TypeVar("T", bound=BaseModel)


def _json(model: BaseModel) -> str:
    return model.model_dump_json()


class _ClosingConnection(sqlite3.Connection):
    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


class SQLiteRepository:
    def __init__(self, path: Path, migrations_dir: Optional[Path] = None) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.migrations_dir = migrations_dir or Path(__file__).parent / "migrations"
        self.migrate()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.path), factory=_ClosingConnection)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def migrate(self) -> None:
        with self.connect() as connection:
            connection.execute("CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TEXT NOT NULL)")
            for migration in sorted(self.migrations_dir.glob("*.sql")):
                version = migration.stem
                exists = connection.execute("SELECT 1 FROM schema_migrations WHERE version = ?", (version,)).fetchone()
                if exists:
                    continue
                connection.executescript(migration.read_text(encoding="utf-8"))
                connection.execute("INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)", (version, utc_now().isoformat()))

    def start_run(self, run_id: str, mode: str, manifest: Any, versions: Any) -> None:
        with self.connect() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO runs(run_id,mode,status,input_manifest_json,versions_json,started_at) VALUES (?,?,?,?,?,?)",
                (run_id, mode, "running", json.dumps(manifest, ensure_ascii=False), json.dumps(versions, ensure_ascii=False), utc_now().isoformat()),
            )

    def complete_run(self, run_id: str, status: str = "completed") -> None:
        with self.connect() as connection:
            connection.execute("UPDATE runs SET status=?, completed_at=? WHERE run_id=?", (status, utc_now().isoformat(), run_id))

    def put_raw(self, raw: RawEventEnvelope) -> bool:
        with self.connect() as connection:
            cursor = connection.execute(
                "INSERT OR IGNORE INTO raw_events VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (raw.raw_id, raw.source.kind.value, raw.source.sensor_id, raw.source_record_id,
                 str(raw.event_time_raw) if raw.event_time_raw is not None else None,
                 raw.observed_time.isoformat(), raw.ingested_time.isoformat(), raw.raw_ref,
                 raw.raw_sha256, json.dumps(raw.labels, ensure_ascii=False), _json(raw)),
            )
            return cursor.rowcount == 1

    def has_raw(self, raw_id: str) -> bool:
        with self.connect() as connection:
            return connection.execute("SELECT 1 FROM raw_events WHERE raw_id = ?", (raw_id,)).fetchone() is not None

    def counts(self, run_id: Optional[str] = None) -> dict:
        tables = ("raw_events", "normalized_events", "sessions", "evidence", "detections", "attack_chains", "agent_tasks", "reports", "dead_letters")
        with self.connect() as connection:
            if not run_id:
                return {table: connection.execute("SELECT COUNT(*) FROM %s" % table).fetchone()[0] for table in tables}
            counts = {table: 0 for table in tables}
            manifest_row = connection.execute("SELECT input_manifest_json FROM runs WHERE run_id = ?", (run_id,)).fetchone()
            if manifest_row:
                try:
                    manifest = json.loads(manifest_row[0])
                    counts["raw_events"] = len(manifest.get("raw_ids", []))
                except (TypeError, json.JSONDecodeError):
                    counts["raw_events"] = 0
            for table in ("normalized_events", "sessions", "evidence", "detections", "attack_chains", "reports"):
                counts[table] = connection.execute("SELECT COUNT(*) FROM %s WHERE run_id = ?" % table, (run_id,)).fetchone()[0]
            return counts

    def dashboard_aggregates(self, run_id: Optional[str] = None) -> dict:
        where = " WHERE run_id = ?" if run_id else ""
        params: tuple[Any, ...] = (run_id,) if run_id else ()
        with self.connect() as connection:
            sources = [
                {"source": row["source_kind"], "event_count": row["event_count"], "last_event_time": row["last_event_time"], "status": "ingested"}
                for row in connection.execute(
                    "SELECT source_kind, COUNT(*) AS event_count, MAX(event_time) AS last_event_time FROM normalized_events%s GROUP BY source_kind ORDER BY source_kind" % where,
                    params,
                ).fetchall()
            ]
            rows = connection.execute("SELECT event_json FROM normalized_events%s" % where, params).fetchall()
        time_quality = {"synced": 0, "other": 0}
        for row in rows:
            event = UnifiedSecurityEvent.model_validate_json(row[0])
            key = "synced" if event.time.quality == "synced" else "other"
            time_quality[key] += 1
        return {"sources": sources, "time_quality": time_quality}

    def list_runs(self, limit: int = 100) -> List[dict]:
        with self.connect() as connection:
            rows = connection.execute("SELECT * FROM runs ORDER BY started_at DESC LIMIT ?", (limit,)).fetchall()
        return [dict(row) for row in rows]

    def append_events(self, run_id: str, events: List[UnifiedSecurityEvent]) -> int:
        rows = [(e.event_id, run_id, e.event_time.isoformat(), e.source.kind.value, e.source.sensor_id,
                 e.host.entity_id if e.host else None, e.action, e.event_type, e.severity,
                 e.provenance.raw_id, _json(e)) for e in events]
        return self._insert_many("INSERT OR IGNORE INTO normalized_events VALUES (?,?,?,?,?,?,?,?,?,?,?)", rows)

    def put_evidence(self, run_id: str, evidence: List[Evidence]) -> int:
        rows = [(e.evidence_id, run_id, e.kind, e.source_ref,
                 e.observed_at.isoformat() if e.observed_at else None, e.reliability, _json(e)) for e in evidence]
        return self._insert_many("INSERT OR REPLACE INTO evidence VALUES (?,?,?,?,?,?,?)", rows)

    def put_sessions(self, run_id: str, sessions: List[Session]) -> int:
        rows = [(s.session_id, run_id, s.session_type, s.start_time.isoformat(),
                 s.end_time.isoformat() if s.end_time else None, s.host_id, s.user_id,
                 s.src_ip, s.dst_ip, s.state, _json(s)) for s in sessions]
        return self._insert_many("INSERT OR REPLACE INTO sessions VALUES (?,?,?,?,?,?,?,?,?,?,?)", rows)

    def put_detections(self, detections: List[DetectionResult]) -> int:
        rows = [(d.detection_id, d.run_id, d.rule_id, d.rule_version, d.severity,
                 d.confidence, d.status, d.created_at.isoformat(), _json(d)) for d in detections]
        return self._insert_many("INSERT OR REPLACE INTO detections VALUES (?,?,?,?,?,?,?,?,?)", rows)

    def put_chains(self, chains: List[AttackChain]) -> int:
        rows = [(c.chain_id, c.run_id, c.status, c.start_time.isoformat(), c.end_time.isoformat(), c.score, _json(c)) for c in chains]
        return self._insert_many("INSERT OR REPLACE INTO attack_chains VALUES (?,?,?,?,?,?,?)", rows)

    def _insert_many(self, sql: str, rows: Iterable[Any]) -> int:
        rows = list(rows)
        if not rows:
            return 0
        with self.connect() as connection:
            before = connection.total_changes
            connection.executemany(sql, rows)
            return connection.total_changes - before

    def _list_models(self, table: str, json_column: str, model: Type[T], limit: int = 100, offset: int = 0) -> List[T]:
        allowed = {"normalized_events", "evidence", "sessions", "detections", "attack_chains"}
        if table not in allowed:
            raise ValueError("table is not queryable")
        with self.connect() as connection:
            rows = connection.execute("SELECT %s FROM %s ORDER BY rowid DESC LIMIT ? OFFSET ?" % (json_column, table), (limit, offset)).fetchall()
        return [model.model_validate_json(row[0]) for row in rows]

    def _query_models(self, table: str, json_column: str, model: Type[T], where: List[str], params: List[Any], order_by: str, limit: int, offset: int = 0, descending: bool = False) -> List[T]:
        allowed = {
            ("normalized_events", "event_json", "event_time"),
            ("evidence", "evidence_json", "observed_at"),
            ("sessions", "session_json", "start_time"),
            ("detections", "detection_json", "created_at"),
            ("attack_chains", "chain_json", "start_time"),
        }
        if (table, json_column, order_by) not in allowed:
            raise ValueError("query is not allowed")
        clause = " WHERE " + " AND ".join(where) if where else ""
        direction = "DESC" if descending else "ASC"
        sql = "SELECT %s FROM %s%s ORDER BY %s %s LIMIT ? OFFSET ?" % (json_column, table, clause, order_by, direction)
        with self.connect() as connection:
            rows = connection.execute(sql, (*params, limit, offset)).fetchall()
        return [model.model_validate_json(row[0]) for row in rows]

    def _query_all_models(self, table: str, json_column: str, model: Type[T], where: List[str], params: List[Any], order_by: str, descending: bool = False) -> List[T]:
        allowed = {
            ("normalized_events", "event_json", "event_time"),
            ("sessions", "session_json", "start_time"),
            ("detections", "detection_json", "created_at"),
            ("attack_chains", "chain_json", "start_time"),
        }
        if (table, json_column, order_by) not in allowed:
            raise ValueError("query is not allowed")
        clause = " WHERE " + " AND ".join(where) if where else ""
        direction = "DESC" if descending else "ASC"
        sql = "SELECT %s FROM %s%s ORDER BY %s %s" % (json_column, table, clause, order_by, direction)
        with self.connect() as connection:
            rows = connection.execute(sql, params).fetchall()
        return [model.model_validate_json(row[0]) for row in rows]

    def count_table(self, table: str, run_id: Optional[str] = None) -> int:
        allowed = {"normalized_events", "evidence", "sessions", "detections", "attack_chains"}
        if table not in allowed:
            raise ValueError("table is not countable")
        with self.connect() as connection:
            if run_id:
                return int(connection.execute("SELECT COUNT(*) FROM %s WHERE run_id = ?" % table, (run_id,)).fetchone()[0])
            return int(connection.execute("SELECT COUNT(*) FROM %s" % table).fetchone()[0])

    def count_events(self, run_id: Optional[str] = None, actions: Optional[Sequence[str]] = None) -> int:
        where: List[str] = []
        params: List[Any] = []
        if run_id:
            where.append("run_id = ?")
            params.append(run_id)
        if actions:
            action_terms = []
            for action in actions:
                if action.endswith(".") or action.endswith("*"):
                    action_terms.append("action LIKE ?")
                    params.append(action.rstrip("*") + "%")
                else:
                    action_terms.append("action = ?")
                    params.append(action)
            where.append("(" + " OR ".join(action_terms) + ")")
        clause = " WHERE " + " AND ".join(where) if where else ""
        with self.connect() as connection:
            return int(connection.execute("SELECT COUNT(*) FROM normalized_events%s" % clause, params).fetchone()[0])

    def list_events(self, limit: int = 100, run_id: Optional[str] = None, offset: int = 0) -> List[UnifiedSecurityEvent]:
        if run_id:
            return self.query_events(run_id=run_id, limit=limit, offset=offset, descending=True)
        return self._list_models("normalized_events", "event_json", UnifiedSecurityEvent, limit, offset)

    def query_events(
        self,
        run_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        source_kinds: Optional[Sequence[str]] = None,
        host_id: Optional[str] = None,
        actions: Optional[Sequence[str]] = None,
        action_prefix: Optional[str] = None,
        entity_id: Optional[str] = None,
        process: Optional[str] = None,
        ip: Optional[str] = None,
        text: Optional[str] = None,
        descending: bool = False,
    ) -> List[UnifiedSecurityEvent]:
        where: List[str] = []
        params: List[Any] = []
        if run_id:
            where.append("run_id = ?")
            params.append(run_id)
        if start_time:
            where.append("event_time >= ?")
            params.append(start_time)
        if end_time:
            where.append("event_time <= ?")
            params.append(end_time)
        if source_kinds:
            where.append("source_kind IN (%s)" % ",".join("?" for _ in source_kinds))
            params.extend(source_kinds)
        if host_id:
            where.append("host_id = ?")
            params.append(host_id)
        action_terms = []
        if actions:
            for action in actions:
                if action.endswith(".") or action.endswith("*"):
                    action_terms.append("action LIKE ?")
                    params.append(action.rstrip("*") + "%")
                else:
                    action_terms.append("action = ?")
                    params.append(action)
        if action_prefix:
            action_terms.append("action LIKE ?")
            params.append(action_prefix.rstrip("*") + "%")
        if action_terms:
            where.append("(" + " OR ".join(action_terms) + ")")
        for value in (entity_id, process, ip):
            if value:
                where.append("event_json LIKE ?")
                params.append("%" + value + "%")
        if text:
            where.append("LOWER(event_json) LIKE ?")
            params.append("%" + text.lower() + "%")
        return self._query_models("normalized_events", "event_json", UnifiedSecurityEvent, where, params, "event_time", limit, offset, descending=descending)

    def all_events(self, run_id: Optional[str] = None, descending: bool = False) -> List[UnifiedSecurityEvent]:
        where: List[str] = []
        params: List[Any] = []
        if run_id:
            where.append("run_id = ?")
            params.append(run_id)
        return self._query_all_models("normalized_events", "event_json", UnifiedSecurityEvent, where, params, "event_time", descending=descending)

    def list_evidence(self, limit: int = 100, run_id: Optional[str] = None, offset: int = 0) -> List[Evidence]:
        if run_id:
            return self._query_models("evidence", "evidence_json", Evidence, ["run_id = ?"], [run_id], "observed_at", limit, offset, descending=True)
        return self._list_models("evidence", "evidence_json", Evidence, limit, offset)

    def get_evidence(self, evidence_id: str) -> Optional[Evidence]:
        with self.connect() as connection:
            row = connection.execute("SELECT evidence_json FROM evidence WHERE evidence_id = ?", (evidence_id,)).fetchone()
        return Evidence.model_validate_json(row[0]) if row else None

    def get_evidence_run_id(self, evidence_id: str) -> Optional[str]:
        with self.connect() as connection:
            row = connection.execute("SELECT run_id FROM evidence WHERE evidence_id = ?", (evidence_id,)).fetchone()
        return str(row[0]) if row else None

    def evidence_ids_for_run(self, run_id: str) -> List[str]:
        with self.connect() as connection:
            rows = connection.execute("SELECT evidence_id FROM evidence WHERE run_id = ?", (run_id,)).fetchall()
        return [str(row[0]) for row in rows]

    def get_event(self, event_id: str) -> Optional[UnifiedSecurityEvent]:
        return self._get_model("normalized_events", "event_id", event_id, "event_json", UnifiedSecurityEvent)

    def list_sessions(self, limit: int = 100, run_id: Optional[str] = None, offset: int = 0) -> List[Session]:
        if run_id:
            return self.query_sessions(run_id=run_id, limit=limit, offset=offset)
        return self._list_models("sessions", "session_json", Session, limit, offset)

    def query_sessions(
        self,
        run_id: Optional[str] = None,
        session_id: Optional[str] = None,
        host_id: Optional[str] = None,
        ip: Optional[str] = None,
        session_type: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Session]:
        where: List[str] = []
        params: List[Any] = []
        if run_id:
            where.append("run_id = ?")
            params.append(run_id)
        if session_id:
            where.append("session_id = ?")
            params.append(session_id)
        if host_id:
            where.append("host_id = ?")
            params.append(host_id)
        if ip:
            where.append("(src_ip = ? OR dst_ip = ?)")
            params.extend([ip, ip])
        if session_type:
            where.append("session_type = ?")
            params.append(session_type)
        return self._query_models("sessions", "session_json", Session, where, params, "start_time", limit, offset)

    def all_sessions(self, run_id: Optional[str] = None, descending: bool = False) -> List[Session]:
        where: List[str] = []
        params: List[Any] = []
        if run_id:
            where.append("run_id = ?")
            params.append(run_id)
        return self._query_all_models("sessions", "session_json", Session, where, params, "start_time", descending=descending)

    def get_session(self, session_id: str) -> Optional[Session]:
        return self._get_model("sessions", "session_id", session_id, "session_json", Session)

    def list_detections(self, limit: int = 100, run_id: Optional[str] = None, offset: int = 0) -> List[DetectionResult]:
        if run_id:
            return self._query_models("detections", "detection_json", DetectionResult, ["run_id = ?"], [run_id], "created_at", limit, offset, descending=True)
        return self._list_models("detections", "detection_json", DetectionResult, limit, offset)

    def all_detections(self, run_id: Optional[str] = None, descending: bool = False) -> List[DetectionResult]:
        where: List[str] = []
        params: List[Any] = []
        if run_id:
            where.append("run_id = ?")
            params.append(run_id)
        return self._query_all_models("detections", "detection_json", DetectionResult, where, params, "created_at", descending=descending)

    def get_detection(self, detection_id: str) -> Optional[DetectionResult]:
        return self._get_model("detections", "detection_id", detection_id, "detection_json", DetectionResult)

    def list_chains(self, limit: int = 100, run_id: Optional[str] = None, offset: int = 0) -> List[AttackChain]:
        if run_id:
            return self._query_models("attack_chains", "chain_json", AttackChain, ["run_id = ?"], [run_id], "start_time", limit, offset, descending=True)
        return self._list_models("attack_chains", "chain_json", AttackChain, limit, offset)

    def all_chains(self, run_id: Optional[str] = None, descending: bool = False) -> List[AttackChain]:
        where: List[str] = []
        params: List[Any] = []
        if run_id:
            where.append("run_id = ?")
            params.append(run_id)
        return self._query_all_models("attack_chains", "chain_json", AttackChain, where, params, "start_time", descending=descending)

    def get_chain(self, chain_id: str) -> Optional[AttackChain]:
        return self._get_model("attack_chains", "chain_id", chain_id, "chain_json", AttackChain)

    def _get_model(self, table: str, id_column: str, value: str, json_column: str, model: Type[T]) -> Optional[T]:
        allowed = {
            ("normalized_events", "event_id", "event_json"), ("sessions", "session_id", "session_json"),
            ("detections", "detection_id", "detection_json"), ("attack_chains", "chain_id", "chain_json"),
        }
        if (table, id_column, json_column) not in allowed:
            raise ValueError("model lookup is not allowed")
        with self.connect() as connection:
            row = connection.execute("SELECT %s FROM %s WHERE %s = ?" % (json_column, table, id_column), (value,)).fetchone()
        return model.model_validate_json(row[0]) if row else None

    def any_events_in_run(self, event_ids: Sequence[str], run_id: str) -> bool:
        if not event_ids:
            return False
        with self.connect() as connection:
            row = connection.execute(
                "SELECT 1 FROM normalized_events WHERE run_id = ? AND event_id IN (%s) LIMIT 1" % ",".join("?" for _ in event_ids),
                (run_id, *event_ids),
            ).fetchone()
        return row is not None

    def event_ids_for_run(self, run_id: str) -> List[str]:
        with self.connect() as connection:
            rows = connection.execute("SELECT event_id FROM normalized_events WHERE run_id = ?", (run_id,)).fetchall()
        return [str(row[0]) for row in rows]

    def put_agent_task(self, task: AgentTask, runtime: Optional[dict] = None) -> None:
        payload = {"task": task.model_dump(mode="json"), "runtime": runtime or {}}
        with self.connect() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO agent_tasks(task_id,case_id,agent_role,state,parent_task_id,task_json) VALUES (?,?,?,?,?,?)",
                (task.task_id, task.case_id, task.agent_role, task.state, task.parent_task_id, json.dumps(payload, ensure_ascii=False)),
            )

    def put_agent_result(self, result: AgentResult, artifact: Optional[dict] = None, runtime: Optional[dict] = None) -> None:
        payload = {"result": result.model_dump(mode="json"), "artifact": artifact or {}, "runtime": runtime or {}}
        with self.connect() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO agent_results(result_id,task_id,status,result_json) VALUES (?,?,?,?)",
                (result.result_id, result.task_id, result.status, json.dumps(payload, ensure_ascii=False)),
            )

    def list_agent_records(self, limit: int = 500) -> List[dict]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT t.task_json,r.result_json FROM agent_tasks t LEFT JOIN agent_results r ON r.task_id=t.task_id ORDER BY t.rowid DESC LIMIT ?", (limit,)
            ).fetchall()
        values = []
        for row in reversed(rows):
            task_payload = json.loads(row[0])
            result_payload = json.loads(row[1]) if row[1] else None
            values.append({"task": task_payload.get("task", task_payload), "runtime": task_payload.get("runtime", {}), "result": result_payload})
        return values

    def put_report(self, report_id: str, case_id: str, run_id: str, report_format: str, version: str, artifact_ref: str, evidence_ids: List[str], created_at: str) -> None:
        with self.connect() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO reports(report_id,case_id,run_id,format,version,artifact_ref,evidence_ids_json,created_at) VALUES (?,?,?,?,?,?,?,?)",
                (report_id, case_id, run_id, report_format, version, artifact_ref, json.dumps(evidence_ids), created_at),
            )

    def list_reports(self, limit: int = 100, run_id: Optional[str] = None) -> List[dict]:
        with self.connect() as connection:
            if run_id:
                rows = connection.execute("SELECT * FROM reports WHERE run_id = ? ORDER BY created_at DESC LIMIT ?", (run_id, limit)).fetchall()
            else:
                rows = connection.execute("SELECT * FROM reports ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [{**dict(row), "evidence_ids": json.loads(row["evidence_ids_json"])} for row in rows]

    def get_report(self, report_id: str) -> Optional[dict]:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM reports WHERE report_id=?", (report_id,)).fetchone()
        return ({**dict(row), "evidence_ids": json.loads(row["evidence_ids_json"])}) if row else None
