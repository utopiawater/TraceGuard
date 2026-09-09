import csv
import gzip
import json
import shutil
import subprocess
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from app.bootstrap import build_pipeline
from app.collectors import envelope_from_payload
from app.contracts import RawEventEnvelope, SourceDescriptor
from app.contracts.common import SourceKind
from app.core.ids import stable_id
from app.core.time import parse_timestamp, utc_now
from app.repositories import SQLiteRepository


ALLOWED_SUFFIXES = {".log", ".json", ".jsonl", ".csv", ".pcap", ".evtx", ".zip", ".tar.gz"}
GROUND_TRUTH_MARKERS = (
    "attack_steps.md",
    "attack_timeline.json",
    "attack_graph.json",
    "labels",
    "ground_truth",
    "groundtruth",
    "证据",
    "说明",
)
MAX_EXTRACTED_BYTES = 250 * 1024 * 1024
STAGES = [
    ("uploaded", "上传"),
    ("identified", "文件识别"),
    ("parsed", "日志解析"),
    ("normalized", "统一范式"),
    ("entities", "实体提取"),
    ("host_network", "主机与网络分析"),
    ("detections", "检测规则"),
    ("correlated", "跨源事件关联"),
    ("chains", "攻击链构建"),
    ("attack", "ATT&CK 映射"),
    ("ready_for_agent", "可启动 Agent 调查"),
    ("completed", "报告就绪"),
]


@dataclass
class RecognizedFile:
    path: Path
    kind: str
    source_kind: Optional[SourceKind]
    dataset: Optional[str]
    payload_format: str
    records: int = 0
    reason: str = ""
    evaluation_only: bool = False
    parser_status: str = "ready"


class AnalysisTaskService:
    version = "1.0.0"

    def __init__(self, settings, repository: SQLiteRepository, graph) -> None:
        self.settings = settings
        self.repository = repository
        self.graph = graph
        self.root = settings.data_dir / "analysis_tasks"
        self.root.mkdir(parents=True, exist_ok=True)

    def create_from_upload(self, filename: str, content: bytes) -> dict:
        suffix = self._suffix(filename)
        if suffix not in ALLOWED_SUFFIXES:
            raise ValueError("unsupported file type: %s" % suffix)
        task_id = "analysis_%s_%s" % (utc_now().strftime("%Y%m%d"), stable_id("task", filename, len(content), utc_now().isoformat()).split("_", 1)[1][:8])
        task_dir = self.root / task_id
        upload_dir = task_dir / "upload"
        extract_dir = task_dir / "extracted"
        upload_dir.mkdir(parents=True, exist_ok=True)
        extract_dir.mkdir(parents=True, exist_ok=True)
        target = upload_dir / Path(filename).name
        target.write_bytes(content)
        task = {
            "task_id": task_id,
            "status": "uploaded",
            "current_stage": "uploaded",
            "stages": self._stage_views("uploaded"),
            "created_at": utc_now().isoformat(),
            "updated_at": utc_now().isoformat(),
            "upload": {"filename": Path(filename).name, "size": len(content), "stored_path": str(target)},
            "identification": {"found": [], "unsupported": [], "warnings": []},
            "result": None,
            "ground_truth": {"files": [], "used_for_detection": False, "comparison": None},
        }
        self._write_task(task)
        self._expand_input(target, extract_dir, task)
        found = self.identify(task_id)
        task["identification"] = found
        task["ground_truth"]["files"] = [item["path"] for item in found["found"] if item.get("evaluation_only")]
        task["status"] = "identified"
        task["current_stage"] = "identified"
        task["stages"] = self._stage_views("identified")
        task["updated_at"] = utc_now().isoformat()
        self._write_task(task)
        return task

    def identify(self, task_id: str) -> dict:
        task_dir = self.root / task_id
        files = [path for path in (task_dir / "extracted").rglob("*") if path.is_file()]
        if not files:
            files = [path for path in (task_dir / "upload").rglob("*") if path.is_file()]
        recognized = [self._recognize(path) for path in files]
        found = [
            {
                "path": str(item.path.relative_to(task_dir)),
                "kind": item.kind,
                "source_kind": item.source_kind.value if item.source_kind else None,
                "dataset": item.dataset,
                "payload_format": item.payload_format,
                "records": item.records,
                "reason": item.reason,
                "evaluation_only": item.evaluation_only,
                "parser_status": item.parser_status,
            }
            for item in recognized
            if item.source_kind or item.evaluation_only or item.parser_status != "ready"
        ]
        unsupported = [{"path": str(path.relative_to(task_dir)), "reason": "unsupported or unrecognized content"} for path in files if all(item.path != path for item in recognized if item.source_kind or item.evaluation_only or item.parser_status != "ready")]
        warnings = []
        if any(item.kind == "PCAP" and item.parser_status == "missing_parser" for item in recognized):
            warnings.append("PCAP 已接收，但当前环境未配置 PCAP 解析器。")
        return {"found": found, "unsupported": unsupported, "warnings": warnings}

    def start(self, task_id: str) -> dict:
        task = self.get(task_id)
        if task["status"] not in {"identified", "failed"}:
            return task
        task["status"] = "running"
        task["current_stage"] = "parsed"
        task["stages"] = self._stage_views("parsed")
        task["updated_at"] = utc_now().isoformat()
        self._write_task(task)
        try:
            raws = self._raw_envelopes(task)
            task["current_stage"] = "normalized"
            task["stages"] = self._stage_views("normalized")
            task["updated_at"] = utc_now().isoformat()
            self._write_task(task)
            pipeline = build_pipeline(self.settings, self.repository, self.graph)
            result = pipeline.run(task_id, raws, mode="replay")
            task["status"] = "completed"
            task["current_stage"] = "completed"
            task["stages"] = self._stage_views("completed")
            task["result"] = self._result_summary(task_id, result)
            task["updated_at"] = utc_now().isoformat()
            self._write_task(task)
        except Exception as exc:
            task["status"] = "failed"
            task["error"] = str(exc)
            task["updated_at"] = utc_now().isoformat()
            self._write_task(task)
        return task

    def get(self, task_id: str) -> dict:
        path = self.root / task_id / "task.json"
        if not path.is_file():
            raise KeyError(task_id)
        return json.loads(path.read_text(encoding="utf-8"))

    def list(self) -> List[dict]:
        tasks = []
        for path in self.root.glob("analysis_*/task.json"):
            try:
                task = json.loads(path.read_text(encoding="utf-8"))
                tasks.append({key: task.get(key) for key in ("task_id", "status", "current_stage", "created_at", "updated_at", "upload", "result")})
            except (OSError, json.JSONDecodeError):
                continue
        return sorted(tasks, key=lambda item: item.get("created_at") or "", reverse=True)

    def result(self, task_id: str) -> dict:
        task = self.get(task_id)
        if not task.get("result"):
            return {"task": task, "summary": None}
        return {"task": task, "summary": task["result"], "ground_truth": task.get("ground_truth", {})}

    def _write_task(self, task: dict) -> None:
        path = self.root / task["task_id"] / "task.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(task, ensure_ascii=False, indent=2), encoding="utf-8")

    def _expand_input(self, path: Path, target_dir: Path, task: dict, depth: int = 0) -> None:
        if depth > 4:
            task["identification"]["warnings"].append("嵌套压缩包超过 4 层，已停止递归解压。")
            return
        suffix = self._suffix(path.name)
        if suffix == ".zip":
            with zipfile.ZipFile(path) as archive:
                for member in archive.infolist():
                    if member.is_dir():
                        continue
                    if member.file_size > MAX_EXTRACTED_BYTES:
                        task["identification"]["warnings"].append("文件超过安全展开大小限制，已跳过：%s" % member.filename)
                        continue
                    output = self._safe_join(target_dir, member.filename)
                    output.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(member) as src, output.open("wb") as dst:
                        shutil.copyfileobj(src, dst)
                    if self._suffix(output.name) in {".zip", ".tar.gz"}:
                        nested = output.with_suffix(output.suffix + ".extracted")
                        nested.mkdir(parents=True, exist_ok=True)
                        self._expand_input(output, nested, task, depth + 1)
        elif suffix == ".tar.gz":
            with tarfile.open(path, "r:gz") as archive:
                for member in archive.getmembers():
                    if not member.isfile():
                        continue
                    if member.size > MAX_EXTRACTED_BYTES:
                        task["identification"]["warnings"].append("文件超过安全展开大小限制，已跳过：%s" % member.name)
                        continue
                    output = self._safe_join(target_dir, member.name)
                    output.parent.mkdir(parents=True, exist_ok=True)
                    src = archive.extractfile(member)
                    if src:
                        with src, output.open("wb") as dst:
                            shutil.copyfileobj(src, dst)
                    if self._suffix(output.name) in {".zip", ".tar.gz"}:
                        nested = output.with_suffix(output.suffix + ".extracted")
                        nested.mkdir(parents=True, exist_ok=True)
                        self._expand_input(output, nested, task, depth + 1)
        else:
            shutil.copy2(path, target_dir / path.name)

    def _safe_join(self, root: Path, name: str) -> Path:
        destination = (root / name).resolve()
        root_resolved = root.resolve()
        if destination == root_resolved or root_resolved not in destination.parents:
            raise ValueError("unsafe archive member path: %s" % name)
        return destination

    def _recognize(self, path: Path) -> RecognizedFile:
        lowered = path.name.lower()
        if any(marker in lowered for marker in GROUND_TRUTH_MARKERS):
            return RecognizedFile(path, "Ground Truth", None, None, "json" if lowered.endswith(".json") else "text", reason="evaluation-only file", evaluation_only=True)
        if lowered.endswith(".pcap"):
            parser = shutil.which("zeek") or shutil.which("tshark")
            return RecognizedFile(path, "PCAP", SourceKind.zeek if parser else None, "pcap", "pcap_ref", 1, "pcap capture", parser_status="ready" if parser else "missing_parser")
        if lowered.endswith(".evtx"):
            parser = shutil.which("wevtutil")
            return RecognizedFile(path, "Windows EVTX", SourceKind.windows_security if parser else None, "windows.evtx", "evtx", 1, "Windows EVTX event log", parser_status="ready" if parser else "missing_parser")
        sample = self._sample(path)
        if "<Event" in sample:
            if "Microsoft-Windows-Sysmon" in sample or lowered.startswith("sysmon_") or any("<EventID>%s</EventID>" % event_id in sample for event_id in (1, 3, 5, 8, 10, 11, 12, 13, 14, 15, 22, 23, 25, 26)):
                return RecognizedFile(path, "Sysmon", SourceKind.sysmon, "sysmon.xml", "xml", 1, "Windows Event XML provider Sysmon")
            if "Microsoft-Windows-Security-Auditing" in sample or "<Channel>Security</Channel>" in sample or lowered.startswith(("windows_", "security_")) or any("<EventID>%s</EventID>" % event_id in sample for event_id in (4624, 4625, 4634, 4647, 4663, 4672)):
                return RecognizedFile(path, "Windows Security", SourceKind.windows_security, "windows.security.xml", "xml", 1, "Windows Security Event XML")
        if "type=SYSCALL msg=audit(" in sample or " msg=audit(" in sample:
            return RecognizedFile(path, "Auditd", SourceKind.auditd, "auditd.compound", "text", 1, "Linux audit log")
        if lowered in {"conn.log", "dns.log", "http.log", "files.log", "weird.log", "notice.log"} or lowered.startswith("zeek_"):
            json_suffix = lowered.endswith((".json", ".jsonl", ".ndjson"))
            return RecognizedFile(path, "Zeek", SourceKind.zeek, self._zeek_dataset(lowered), "json" if json_suffix else "csv", self._count_records(path), "Zeek log")
        if lowered in {"process_events.json", "network_events.json", "file_events.json"}:
            return RecognizedFile(path, "标准化数据集", SourceKind.dataset, "darpa_tc_e3_cadets", "json", self._count_records(path), "standard dataset event file")
        if self._looks_like_json(path):
            first = self._first_json_record(path)
            dataset = self._dataset_from_record(first, path)
            if dataset:
                return dataset
        if lowered.endswith(".csv") or self._looks_like_web_log(sample):
            dataset = "c2.http" if "c2" in lowered else "web.nginx" if self._looks_like_web_log(sample) else "generic.csv"
            return RecognizedFile(path, "Nginx/Web日志", SourceKind.application, dataset, "csv" if lowered.endswith(".csv") else "text", self._count_records(path), "web access log")
        return RecognizedFile(path, "Unknown", None, None, "text", 0, "unrecognized")

    def _raw_envelopes(self, task: dict) -> List[RawEventEnvelope]:
        raws: List[RawEventEnvelope] = []
        task_dir = self.root / task["task_id"]
        for item in task["identification"]["found"]:
            if item.get("evaluation_only") or item.get("parser_status") == "missing_parser" or not item.get("source_kind"):
                continue
            path = task_dir / item["path"]
            kind = SourceKind(item["source_kind"])
            dataset = item.get("dataset")
            for index, payload in enumerate(self._payloads(path, item["payload_format"], dataset)):
                payload = dict(payload) if isinstance(payload, dict) else payload
                record_dataset = payload.pop("_dataset", dataset) if isinstance(payload, dict) else dataset
                record_kind = self._windows_kind_from_xml(payload, kind)
                event_time_raw = self._event_time(payload)
                observed = parse_timestamp(event_time_raw) if event_time_raw is not None else utc_now()
                record_id = "%s:%s:%d" % (task["task_id"], path.name, index)
                host_hint = self._host_hint(payload)
                if host_hint and host_hint.lower() in {"localhost", "."}:
                    host_hint = self._host_hint_from_path(path) or host_hint
                source = SourceDescriptor(kind=record_kind, product=self._product(record_kind, record_dataset), dataset=record_dataset, sensor_id=self._sensor_id(path, payload, record_kind), host_hint=host_hint or self._host_hint_from_path(path), source_record_id=record_id)
                payload_format = "json" if item["payload_format"] == "pcap_ref" else "xml" if item["payload_format"] == "evtx" else item["payload_format"]
                raws.append(envelope_from_payload(source, payload, payload_format, event_time_raw, "analysis://%s/%s#%d" % (task["task_id"], item["path"], index), observed, {"analysis_task_id": task["task_id"], "uploaded_file": task["upload"]["filename"]}))
        return raws

    def _payloads(self, path: Path, payload_format: str, dataset: Optional[str]) -> Iterable[Any]:
        if payload_format == "pcap_ref":
            return list(self._pcap_payloads(path))
        if payload_format == "evtx":
            return list(self._evtx_payloads(path))
        if payload_format in {"text", "xml"}:
            return [path.read_text(encoding="utf-8", errors="replace")]
        if payload_format == "csv" and dataset and dataset.startswith("zeek."):
            return list(self._read_zeek(path))
        if payload_format == "csv":
            return list(self._read_csv(path))
        if path.suffix.lower() == ".jsonl":
            return [json.loads(line) for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]
        loaded = json.loads(path.read_text(encoding="utf-8"))
        return loaded if isinstance(loaded, list) else [loaded]

    def _read_zeek(self, path: Path) -> Iterable[dict]:
        text = path.read_text(encoding="utf-8", errors="replace").splitlines()
        fields = []
        for line in text:
            if not line or line.startswith("#separator") or line.startswith("#types") or line.startswith("#close"):
                continue
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue
            if fields:
                yield {key: (None if value == "-" else value) for key, value in zip(fields, line.split("\t"))}

    def _read_csv(self, path: Path) -> Iterable[dict]:
        with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
            for row in csv.DictReader(handle):
                yield dict(row)

    def _pcap_payloads(self, path: Path) -> Iterable[dict]:
        zeek = shutil.which("zeek")
        if zeek:
            temp_root = getattr(self, "root", path.parent) / "pcap_tmp"
            temp_root.mkdir(parents=True, exist_ok=True)
            out_dir = temp_root / stable_id("pcap", path.name)
            if out_dir.exists():
                shutil.rmtree(out_dir, ignore_errors=True)
            out_dir.mkdir(parents=True, exist_ok=True)
            try:
                command = [zeek, "-C", "-r", str(path), "LogAscii::use_json=T"]
                proc = subprocess.run(command, cwd=out_dir, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
                if proc.returncode != 0:
                    raise ValueError("PCAP Zeek parse failed: %s" % (proc.stderr.strip() or proc.stdout.strip()))
                for log_path in sorted(out_dir.glob("*.log")):
                    dataset = self._zeek_dataset(log_path.name)
                    for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
                        if not line.strip() or line.startswith("#"):
                            continue
                        try:
                            row = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        row["_dataset"] = dataset
                        yield row
            finally:
                shutil.rmtree(out_dir, ignore_errors=True)
            return
        tshark = shutil.which("tshark")
        if not tshark:
            raise ValueError("PCAP parser prerequisite missing: install Zeek or tshark")
        fields = ["frame.time_epoch", "ip.src", "ip.dst", "tcp.srcport", "udp.srcport", "tcp.dstport", "udp.dstport", "_ws.col.Protocol", "frame.len"]
        command = [tshark, "-r", str(path), "-T", "fields", "-E", "separator=\t"]
        for field in fields:
            command.extend(["-e", field])
        proc = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
        if proc.returncode != 0:
            raise ValueError("PCAP tshark parse failed: %s" % (proc.stderr.strip() or proc.stdout.strip()))
        for index, line in enumerate(proc.stdout.splitlines()):
            parts = line.split("\t")
            if len(parts) < len(fields) or not parts[1] or not parts[2]:
                continue
            src_port = parts[3] or parts[4] or None
            dst_port = parts[5] or parts[6] or None
            proto = "udp" if parts[4] or parts[6] else "tcp" if parts[3] or parts[5] else "icmp" if "ICMP" in parts[7].upper() else "other"
            yield {"_dataset": "zeek.conn", "ts": float(parts[0]), "uid": stable_id("pcap", path.name, index), "id.orig_h": parts[1], "id.resp_h": parts[2], "id.orig_p": int(src_port) if src_port else None, "id.resp_p": int(dst_port) if dst_port else None, "proto": proto, "orig_bytes": int(parts[8] or 0), "resp_bytes": 0}

    def _evtx_payloads(self, path: Path) -> Iterable[str]:
        parser = shutil.which("wevtutil")
        if not parser:
            raise ValueError("EVTX parser prerequisite missing: wevtutil is required on Windows")
        proc = subprocess.run([parser, "qe", str(path), "/lf:true", "/f:xml"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
        if proc.returncode != 0:
            raise ValueError("EVTX parse failed: %s" % (proc.stderr.strip() or proc.stdout.strip()))
        import re
        for match in re.finditer(r"<Event\b.*?</Event>", proc.stdout, flags=re.S):
            yield match.group(0)

    def _result_summary(self, task_id: str, result) -> dict:
        events = self.repository.query_events(run_id=task_id, limit=50000)
        network = [event for event in events if event.network]
        high = [item for item in result.detections if item.severity in {"high", "critical"}]
        techniques = sorted({mapping.subtechnique_id or mapping.technique_id for det in result.detections for mapping in det.attack_mappings})
        return {
            "parsed_files": len([item for item in self.get(task_id)["identification"]["found"] if not item.get("evaluation_only")]),
            "raw_records": result.accepted_raw,
            "normalized_events": len(result.events),
            "detections": len(result.detections),
            "high_risk_events": len(high),
            "entities": len(result.graph_entities),
            "attack_chains": len(result.chains),
            "attack_techniques": len(techniques),
            "network_events": len(network),
            "host_events": len([event for event in events if event.host]),
            "techniques": techniques,
            "anomalous_assets": sorted({ref for det in high for ref in det.entity_ids})[:50],
            "unparsed_files": self.get(task_id)["identification"].get("unsupported", []),
        }

    def _stage_views(self, current: str) -> List[dict]:
        current_index = next((index for index, (key, _) in enumerate(STAGES) if key == current), 0)
        return [{"key": key, "label": label, "status": "completed" if index < current_index else "running" if index == current_index else "pending"} for index, (key, label) in enumerate(STAGES)]

    @staticmethod
    def _suffix(name: str) -> str:
        lowered = name.lower()
        return ".tar.gz" if lowered.endswith(".tar.gz") else Path(lowered).suffix

    @staticmethod
    def _sample(path: Path, limit: int = 8192) -> str:
        try:
            if path.name.lower().endswith(".gz") and not path.name.lower().endswith(".tar.gz"):
                with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
                    return handle.read(limit)
            return path.read_text(encoding="utf-8", errors="replace")[:limit]
        except OSError:
            return ""

    @staticmethod
    def _looks_like_json(path: Path) -> bool:
        return path.suffix.lower() in {".json", ".jsonl"}

    def _first_json_record(self, path: Path) -> dict:
        try:
            if path.suffix.lower() == ".jsonl":
                for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                    if line.strip():
                        value = json.loads(line)
                        return value if isinstance(value, dict) else {}
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, list) and loaded:
                return loaded[0] if isinstance(loaded[0], dict) else {}
            return loaded if isinstance(loaded, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    def _dataset_from_record(self, record: dict, path: Path) -> Optional[RecognizedFile]:
        keys = set(record)
        name = path.name.lower()
        if {"id.orig_h", "id.resp_h"} & keys or {"uid", "proto"} <= keys:
            return RecognizedFile(path, "Zeek", SourceKind.zeek, self._zeek_dataset(name), "json", self._count_records(path), "Zeek JSON record")
        if {"timestamp", "action", "event_id"} <= keys and ({"subject_id", "object_id"} & keys or {"source", "destination"} & keys):
            return RecognizedFile(path, "标准化数据集", SourceKind.dataset, "darpa_tc_e3_cadets", "json", self._count_records(path), "standard dataset JSON")
        if {"timestamp", "process"} & keys or {"src_ip", "dst_ip"} <= keys:
            return RecognizedFile(path, "Process/Network/File Events", SourceKind.dataset, "sample_attack_dataset", "json", self._count_records(path), "generic normalized dataset")
        return None

    @staticmethod
    def _looks_like_web_log(sample: str) -> bool:
        return " HTTP/" in sample and any(method in sample for method in ("GET ", "POST ", "PUT ", "DELETE "))

    @staticmethod
    def _count_records(path: Path) -> int:
        try:
            if path.suffix.lower() == ".json":
                loaded = json.loads(path.read_text(encoding="utf-8"))
                return len(loaded) if isinstance(loaded, list) else 1
            return sum(1 for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip() and not line.startswith("#"))
        except Exception:
            return 0

    @staticmethod
    def _zeek_dataset(name: str) -> str:
        for token in ("conn", "dns", "http", "files", "weird", "notice", "icmp"):
            if token in name:
                return "zeek.%s" % token
        return "zeek.conn"

    @staticmethod
    def _event_time(payload: Any) -> Optional[Any]:
        if isinstance(payload, dict):
            return payload.get("timestamp") or payload.get("ts") or payload.get("UtcTime") or payload.get("time")
        if isinstance(payload, str) and "<Event" in payload:
            import re
            match = re.search(r"<TimeCreated[^>]+SystemTime=['\"]([^'\"]+)['\"]", payload)
            return match.group(1) if match else None
        return None

    @staticmethod
    def _host_hint(payload: Any) -> Optional[str]:
        if isinstance(payload, dict) and (payload.get("host") or payload.get("hostname") or payload.get("Computer")):
            return str(payload.get("host") or payload.get("hostname") or payload.get("Computer"))
        if isinstance(payload, str) and "<Event" in payload:
            import re
            match = re.search(r"<Computer>(.*?)</Computer>", payload)
            return match.group(1) if match else None
        return None

    @staticmethod
    def _host_hint_from_path(path: Path) -> Optional[str]:
        name = path.stem.lower()
        if name.startswith("n7_"):
            return "n7-office"
        if name.startswith("n8_"):
            return "n8-core"
        if name.startswith("n4_"):
            return "n4-web"
        if "c2" in name:
            return "c2"
        return None

    @staticmethod
    def _windows_kind_from_xml(payload: Any, fallback: SourceKind) -> SourceKind:
        if not isinstance(payload, str) or "<Event" not in payload:
            return fallback
        lowered = payload.lower()
        if "microsoft-windows-sysmon" in lowered or "<channel>microsoft-windows-sysmon/operational</channel>" in lowered:
            return SourceKind.sysmon
        return SourceKind.windows_security

    @staticmethod
    def _sensor_id(path: Path, payload: Any, kind: SourceKind) -> str:
        host = AnalysisTaskService._host_hint(payload)
        if host and host.lower() in {"localhost", "."}:
            host = AnalysisTaskService._host_hint_from_path(path) or host
        return "%s:%s" % (kind.value, (host or path.stem).lower())

    @staticmethod
    def _product(kind: SourceKind, dataset: Optional[str]) -> str:
        return {"sysmon": "Microsoft Sysmon", "windows_security": "Microsoft Windows Security", "auditd": "Linux Auditd", "zeek": "Zeek", "dataset": dataset or "Dataset", "application": "Application Log"}.get(kind.value, kind.value)
