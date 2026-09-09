# TraceGuard

TraceGuard 是面向 2026 网络空间安全课程设计的证据驱动攻击溯源平台。项目直接采用最终模块边界：FastAPI 模块化单体、SQLite 结构化事实库、append-only 原始归档、Neo4j 图投影、React/TypeScript 调查台和受证据约束的 Multi-Agent Harness。答辩前产品原则是：一个证据包 = 一个分析任务 = 一个 run_id = 全平台同一攻击案件的不同视图。

## 当前已接通的主路径

```text
Windows Security / Sysmon XML + Auditd / Wazuh JSON + Zeek JSON + DARPA TC E3 CADets
→ RawEventEnvelope → append-only archive
→ UnifiedSecurityEvent → Entity Resolver → Sessionizer
→ SQLite → Graph Projector → DetectionResult
→ ATT&CK Mapping → AttackChain → REST API → Web 调查台
```

当前完整场景覆盖 Windows/Linux/Network 三域、Auditd 复合事件、Wazuh 告警、Zeek conn/dns/http/files/weird/notice/ICMP、代表性主机行为和 DNS/HTTP/ICMP 隐蔽信道，并形成带 Evidence 的七阶段攻击链。fixture、实时来源和 DARPA TC E3 CADets 公开数据集均复用同一主管道。

## 本地运行

最终支持环境为 **Python 3.13（OpenSSL 3）** 与 Node.js 20+。不支持 Python 3.8；旧运行时在真实 DeepSeek HTTPS 调用中会出现 SSL EOF。Windows 从项目根目录安装：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\setup_windows.ps1
```

复制本地配置模板并填写 Neo4j 与 LLM 配置。`.env` 已被 Git ignore，API Key 不得写入其他文件：

```powershell
Copy-Item .env.example .env
```

完成配置后使用固定端口一键启动和检查：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\start.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\check.ps1
```

Web 固定入口为 `http://127.0.0.1:5173`，API 文档为 `http://127.0.0.1:8000/docs`。停止服务：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\stop.ps1
```

如果本机没有 Docker，但 `.runtime\neo4j-community-5.26.30` 已存在，可先启动本地 Neo4j runtime，再运行 `scripts/start.ps1`：

```powershell
Start-Process -FilePath ".\.runtime\neo4j-community-5.26.30\bin\neo4j.bat" -ArgumentList @("console") -WorkingDirectory ".\.runtime\neo4j-community-5.26.30" -WindowStyle Hidden -RedirectStandardOutput ".\.runtime\neo4j.stdout.log" -RedirectStandardError ".\.runtime\neo4j.stderr.log"
powershell -ExecutionPolicy Bypass -File .\scripts\start.ps1
```

答辩前可以先运行 demo readiness 检查。它会检查 Python 版本、依赖、`.env`、SQLite、历史 AttackChain/Evidence、LLM 配置、前后端服务和 Neo4j 可用性；默认不要求服务必须已经启动，也不会伪造真实 LLM 结果：

```powershell
.\.venv\Scripts\python.exe scripts/demo_readiness.py
```

如果要把正在运行的前后端和 Neo4j 也作为硬性验收：

```powershell
.\.venv\Scripts\python.exe scripts/demo_readiness.py --require-services
```

需要重新生成七阶段演示数据时，在服务停止状态执行：

```powershell
.\.venv\Scripts\python.exe scripts/replay_scenario.py --scenario backend/fixtures/scenarios/full_attack_chain --run-id run_full_multisource_001
```

需要重新生成 DARPA TC E3 CADets 公开数据集实验结果时，在服务停止状态执行：

```powershell
.\.venv\Scripts\python.exe scripts/replay_dataset.py --dataset datasets/darpa_tc_e3_cadets --data-dir data/dataset_e3 --run-id run_darpa_tc_e3_001 --reset --quick-investigation --agent-fallback
```

当前泛化验收报告写入 `data/dataset_e3_generalization/dataset_run_report.json`，前端 `/datasets` 页面和 `/api/datasets` 会读取真实报告，并展示 IOC 覆盖、未覆盖 IOC 构成、低语义系统调用占比和 Ground Truth 限制说明。Ground Truth、官方 IOC、`attack_graph.json`、`attack_timeline.json` 和 `agent_input.json` 只用于 evaluation，不用于生成 Detection、ATT&CK、AttackChain 或 Agent Finding。

Agent 调查中心保留两种调用范围：完整调查执行六个 Agent；快速调查执行 Coordinator、Host、Network、Correlation。两者共用真实 Tool、严格 Schema 和 EvidenceValidator；模型不可用时明确记录为 `deterministic_fallback`，不会伪装成 `real_llm`。

Docker Compose 同样使用 Python 3.13 镜像；容器 Web 入口为 `http://127.0.0.1:8080`。

完整安装、健康检查、Agent 演示与验收记录说明见 [Release Runbook](docs/12_release_runbook.md)。

## 验证

```powershell
.\.venv\Scripts\python.exe scripts/self_check.py
.\.venv\Scripts\python.exe -m pytest
cd frontend
npm test
npm run build
```

`self_check.py` 验证主管道、证据外键、图投影、幂等与 Agent 工具权限。普通自动化测试使用 Fake ModelClient，不消耗真实 LLM Token。正式真实模型验收记录保存在 `artifacts/release/`。

## 数据集与靶场状态

DARPA TC E3 CADets 公开数据集已接入统一主管道，当前验证规模为 20,776 条事件。最新泛化回归在保守 ATT&CK 映射后生成 225 条 Detection、1 条 AttackChain 和可回查 Evidence；早期 `data/dataset_e3` snapshot 中的 348 条 Detection 是历史基线。数据集页面同时展示未覆盖 IOC 的主要 action、event_type 和 process 分布，便于答辩时说明 coverage 限制。若没有生成过 dataset run report，数据集页面会保持真实空状态，不使用 Mock 数据。

8+ 节点真实靶场由云平台同学部署。本仓库提供拓扑、采集规范和日志 bundle 接入契约；云端导出的 Wazuh/Sysmon/Auditd/Zeek 日志到位后，可按 `docs/13_cloud_testbed_handoff.md` 接入 TraceGuard。

真实靶场日志写库前先做 dry-run，检查节点、文件、数据源、时间范围、时间偏差、可解析数量和缺失关键数据：

```powershell
.\.venv\Scripts\python.exe scripts/testbed_import_dry_run.py --bundle path\to\testbed_bundle
```
