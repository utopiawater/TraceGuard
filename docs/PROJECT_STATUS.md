# TraceGuard Project Status

本文件是 TraceGuard 当前仓库状态的交接文档。结论以 2026-09-10 本地仓库、数据集运行报告、测试结果和文档为准；如果它与早期聊天记录或旧设计文档冲突，以当前代码和本文件为准。

严禁在本文档、日志、前端接口、报告或提交中记录 `.env` 的真实内容、API Key、Neo4j 密码或其他密钥。

## 1. 当前定位

TraceGuard 是 2026 年网络空间安全小学期课程设计项目，课程题目为“基于主机日志、主机行为、网络流量的恶意攻击行为溯源分析系统设计与实现”。

当前项目已经形成证据驱动的多源攻击溯源平台：

```text
Collector / Replay / DARPA Dataset
-> RawEventEnvelope
-> append-only RawArchive + SQLite raw_events
-> NormalizerRegistry
-> UnifiedSecurityEvent
-> Entity Resolver + Sessionizer
-> SQLite + InMemoryGraph / Neo4j projection
-> DetectionResult + Evidence
-> ATT&CK Mapping
-> Deterministic AttackChain
-> Evidence-constrained Multi-Agent Investigation
-> Attribution candidate / unable_to_attribute
-> Report markdown/html
-> FastAPI + React UI
```

稳定边界：`RawEventEnvelope`、`UnifiedSecurityEvent`、`Evidence`、`DetectionResult`、`AttackChain`、`AgentTask`、`AgentResult`、`NormalizerRegistry`、Agent Tool 权限、EvidenceValidator 和主管道不应再为单一数据源重构。

## 2. 已完成能力

- Windows Security、Sysmon、Auditd、Wazuh、Zeek adapter 已接入统一主管道。
- `backend/fixtures/scenarios/full_attack_chain` 可生成带 Evidence 的七阶段课程演示链。
- SQLite repository 已支持 run-scoped 事件、session、detection、evidence、chain 查询，并支持超过 5000 条事件的 SQL 过滤。
- Detection 覆盖登录、PowerShell、端网双源连接、横向移动、权限变化、敏感文件、数据外传、注册表持久化、内存行为、DNS/HTTP/ICMP 隐蔽信道，并补充真实靶场泛化所需的 Web 探测、HTTP C2 候选、无进程上下文的 flow 扫描、归档候选和 HTTP 客户端模拟外传候选。
- ATT&CK knowledge 固定在 `knowledge/attack/mappings.json`，当前 T1046 名称为 `Network Service Scanning`。
- AttackChain 仍由 `DeterministicChainBuilder` 基于 Detection 和 ATT&CK tactic 生成，不读取 Ground Truth。
- Multi-Agent 保持六角色：Coordinator、Host、Network、Correlation、Attribution、Report。Quick scope 使用 Coordinator、Host、Network、Correlation；真实 LLM 不可用时明确记录 deterministic fallback。
- Frontend 13 个页面接真实 API，不用业务 mock 伪造结果。当前产品原则已收敛为“一个证据包 -> 一个分析任务 -> 一个 run_id -> 全平台同一攻击案件的不同视图”，详见 `docs/TraceGuard_产品设计规划.md`。
- `/api/datasets` 和 Dataset 页面已读取真实 DARPA run report；Dataset 页面会展示 IOC coverage、未覆盖 IOC 构成、低语义系统调用占比和指标限制说明。
- 前端展示层已统一中文状态、百分比置信度、AttackChain 链可信评分/完整度/阶段数说明、ATT&CK ID + 名称展示，以及 Dataset/Agent/Attribution 指标 tooltip；底层 API 字段保持不变。
- 全局搜索已接入：顶部搜索框跳转 `/search?q=...`，后端 `/api/search` 只读查询 normalized events、detections、evidence、attack chains、sessions、Agent tasks/results 和 reports，不暴露 raw envelope、Ground Truth 或密钥类配置。
- 数据源页面和 Agent source health 中的状态从“healthy”语义收窄为“ingested/已接入”，避免把历史事件存在误读为传感器实时健康。
- 页面真实性收口已完成：Events / Detections / Sessions / Evidence / Chains / Network 支持 run scope、分页、total；AttackChain 页面按 `chain_id` 精确加载图与 Evidence；Host/Sources/ATT&CK/graph 投影不再先截断 500/5000/50000 条再聚合。
- 分析任务进度条已接入后端主管道真实阶段回写：`AnalysisPipeline.run()` 在 normalized、entities、host_network、detections、attack、correlated、chains、ready_for_agent 阶段通过 progress callback 更新 `task.json`，前端只展示后端返回的真实阶段，不做假进度。
- 顶部 Current Run 下拉与“分析任务”页面共享同一任务列表来源；上传/启动任务后会立即触发刷新，并在窗口聚焦和 5 秒轮询时同步历史 run，避免任务历史已有新 run 而顶部栏仍缺项。

## 3. DARPA TC E3 CADets 接入状态

公开数据集已正式接入 TraceGuard 主管道，不再是 pending。

核心输入只使用：

- `datasets/darpa_tc_e3_cadets/processed_dataset/process_events.json`
- `datasets/darpa_tc_e3_cadets/processed_dataset/network_events.json`
- `datasets/darpa_tc_e3_cadets/processed_dataset/file_events.json`

Evaluation-only 文件，例如 `agent_input.json`、`dataset_analysis_report.*`、`attack_graph.json`、`attack_timeline.json`、`source_metadata` 中的 Ground Truth / IOC / selection manifest，只用于理解、字段审计和最终对照，不进入 Detection、ATT&CK、AttackChain 或 Agent Tool 上下文。

实际数据量：

- process: 15,441
- network: 765
- file: 4,570
- total: 20,776

完整 replay 命令：

```powershell
py -3.13 scripts/replay_dataset.py --dataset datasets/darpa_tc_e3_cadets --data-dir data/dataset_e3 --run-id run_darpa_tc_e3_001 --reset --quick-investigation --agent-fallback
```

最新泛化回归 run report:

- report: `data/dataset_e3_generalization/dataset_run_report.json`
- input_records: 20,776
- accepted_raw: 20,776
- normalized_records: 20,776
- failed_records: 0
- mapping_rate: 1.0
- unknown_action_count: 0
- entity_count: 343
- session_count: 16
- detection_count: 225
- evidence_count: 20,776
- technique_ids: `T1005`, `T1046`, `T1071.001`
- chain_count: 1
- IOC coverage: 86 / 776
- uncovered IOC analysis: 690 个未覆盖 IOC 中 651 个为 network IOC，648 个为低语义系统调用；主要由 `recvfrom`、`sendto` 和少量文件落地/权限/删除事件组成。
- Evidence backtrace rate: 1.0

当前 Dataset AttackChain 由系统 Detection 生成，关键步骤为：

1. command_and_control / `T1071.001`
2. collection / `T1005`

说明：本轮真实靶场泛化修复后，单纯 `memory.protect` 不再自动映射为 `T1055 Process Injection`，普通 `privilege.change`/Windows 4672 也不再自动映射为 `T1068 Exploitation for Privilege Escalation`。因此 CADETS 的 Technique 数从旧基线 6 种降为 3 种，这是 ATT&CK 降噪结果，不是解析回归。

二分类 Precision / Recall / F1 不报告：

> 该 DARPA TC E3 CADets 实验切片仅提供 IOC 命中及相关上下文信息，不具备完备逐事件 benign/attack 二分类真值，因此不报告二分类 Precision、Recall 和 F1。

## 4. 测试与验收基线

正式 Python 版本来自 `pyproject.toml`：`>=3.13,<3.14`。本机裸 `python` 指向 Python 3.8，不可作为正式测试环境；`xxq` conda 环境为 Python 3.11，也不符合当前项目要求。正式回归使用 `py -3.13` 或项目 `.venv`。

最近一次完整通过的回归：

- `py -3.13 -m pytest --basetemp data/test_tmp_closeout2`: passed，45 passed / 1 warning
- `py -3.13 scripts/self_check.py`: passed，8 checks
- `cd frontend; npm.cmd test`: passed，1 file / 2 tests
- `cd frontend; npm.cmd run build`: passed

2026-09-10 页面真实性与 Current Run 收口后的定点验证：

- `.\.venv\Scripts\python.exe -m pytest backend\tests\test_page_truthfulness.py backend\tests\test_analysis_api.py backend\tests\test_demo_scripts.py backend\tests\test_testbed_generalization.py --basetemp=data\pytest_truth_run5`: passed，23 passed / 2 warnings
- `.\.venv\Scripts\python.exe scripts\self_check.py`: passed，8 checks
- `cd frontend; npm.cmd test`: passed，1 file / 2 tests
- `cd frontend; npm.cmd run build`: passed

2026-09-10 分析任务进度与顶部 run picker 修复后的定点验证：

- `.\.venv\Scripts\python.exe -m pytest backend\tests\test_analysis_api.py backend\tests\test_page_truthfulness.py`: passed，8 passed / 2 warnings
- `.\.venv\Scripts\python.exe scripts\self_check.py`: passed，8 checks
- `cd frontend; npm.cmd test`: passed，1 file / 2 tests
- `cd frontend; npm.cmd run build`: passed
- `scripts/start.ps1` 可启动 FastAPI/frontend；`/api/system/health` 显示 `graph.configured=true`、`graph.connected=true`、`uri=bolt://127.0.0.1:7687`。

2026-09-09 真实靶场泛化修复后的验证：

- `py -3.13 scripts/self_check.py`: passed，8 checks
- 关键新增回归定点测试：7 passed
- `py -3.13 -m pytest -q --tb=short`: 当前机器上所有剩余失败均为 pytest `tmp_path` 在 `C:\Users\70568\AppData\Local\Temp\pytest-of-70568\...\ .lock` 创建被拒绝，未再出现业务断言失败。
- `cd frontend; npm.cmd run build`: passed
- `cd frontend; npm.cmd test -- --run`: 当前机器上 Vitest/Vite 启动 esbuild 子进程时报 `spawn EPERM`，与前端代码编译无关。

正式真实 DeepSeek 验收 artifact 保留在：

- `artifacts/release/case_1421c3d00365403d.acceptance.json`
- `artifacts/release/case_1421c3d00365403d-report.md`
- `artifacts/release/case_1421c3d00365403d-report.html`

普通自动化测试使用 Fake/Echo/Failing model，不消耗真实 LLM token。除非专门做真实模型验收，不需要重新调用 DeepSeek。

答辩前 readiness 检查：

```powershell
py -3.13 scripts/demo_readiness.py
```

该脚本检查 Python、依赖、`.env`、SQLite demo 数据、历史 AttackChain/Evidence、LLM 配置、FastAPI、frontend、Neo4j、release snapshot 和 Agent EvidenceValidator；默认不要求服务必须启动，`--require-services` 可切换为硬性服务检查。`scripts/release_verify.py` 是更严格的历史真实 DeepSeek release snapshot 验收，可能因空库、服务未启动、Neo4j 未连或 release case 不存在而失败，不应作为 clean checkout 的第一条健康检查命令。

本轮已修复 Windows 本地 `.env` 的非密钥路径配置：`TRACEGUARD_DATABASE_PATH`、`TRACEGUARD_RAW_ARCHIVE_DIR`、`TRACEGUARD_REPORT_DIR` 均指向项目内 `data/`。2026-09-10 已用本地 `.runtime\neo4j-community-5.26.30` 启动 Neo4j，并通过 `scripts/start.ps1` 重新启动 FastAPI/frontend；`/api/system/health` 显示 `graph.configured=true`、`graph.connected=true`、`uri=bolt://127.0.0.1:7687`。`.\.venv\Scripts\python.exe scripts\demo_readiness.py --require-services` passed 且无 warnings。

## 5. 云靶场分工状态

本仓库当前负责：

- TraceGuard 主系统、数据模型、主管道、前端、公开数据集接入。
- `testbed/topology.yaml` 和 `docs/07_testbed_design.md` 中的 9 节点逻辑拓扑、采集要求和 Ground Truth manifest 规范。
- 接收云平台同学导出的 Wazuh JSON、Sysmon XML、Auditd compound log、Zeek JSON log、PCAP/Zeek capture health、场景 manifest，并通过已有 adapter 进入主管道。

云平台同学负责：

- 真实 8+ 节点隔离靶场部署。
- 节点截图、网络拓扑截图、传感器安装截图、时间同步截图。
- 攻击场景执行、回滚、录像和 Ground Truth manifest。
- 导出可 replay 的日志 bundle。

对接文档：`docs/13_cloud_testbed_handoff.md`。

真实靶场日志写库前先使用：

```powershell
py -3.13 scripts/testbed_import_dry_run.py --bundle path\to\testbed_bundle
```

dry-run 不写数据库、不生成 Detection/AttackChain，只输出节点、文件、数据源、时间范围、时间偏差、可解析/不可解析数量和缺失关键数据。正式上传链路已支持安全递归展开 zip/tar.gz、Nginx/C2 HTTP 文本日志、Auditd、Windows EVTX 经 `wevtutil` 转 XML，以及 PCAP 经 Zeek/tshark 转 Zeek 事件；当前本机缺 Zeek/tshark，因此 PCAP 会被明确标记为 missing parser。

## 6. 对照小学期要求的剩余项

代码侧当前建议冻结 Dataset 和主架构。后续主要是验收材料和云靶场数据对接：

1. 等云平台靶场日志 bundle 到位后，按 `docs/13_cloud_testbed_handoff.md` 导入 TraceGuard 并生成 run report。
2. 固定一条答辩演示流程：启动系统 -> 展示七阶段 fixture -> 展示 DARPA Dataset -> 展示 Agent 调查 -> 展示报告导出。
3. 补最终课程报告/PPT：系统架构、数据模型、检测规则、ATT&CK、AttackChain、Agent、公开数据集评估、云靶场验证、局限性。
4. `.pytest-*` / `.tmp-*` / `data/test_tmp_*` / `data/pytest_truth_run*/` 已加入 `.gitignore`；之前误跟踪的 pytest 临时输出应从 Git 索引移除后随本轮收口提交。
5. 决定 Dataset 大文件策略：`processed_dataset/*.json` 建议 Git LFS 或外部下载说明；`data/dataset_e3/traceguard.db` 和 raw archive 不提交。

## 7. 当前已知限制

- DARPA Precision / Recall / F1 为 N/A，原因是缺少完整逐事件二分类真值。
- Attribution 是候选相似性分析，不是攻击者身份确认。
- Neo4j 图查询和前端图谱是 bounded 视图，不是无限全库图遍历；AttackChain 核心页面已按 `chain_id` 精确加载链相关图节点和 Evidence。
- PDF 报告导出未实现，当前支持 Markdown/HTML。
- 真实云靶场同学提供的 `攻击行为记录.zip` 已由本仓库直接验证一次。当前可解析 Nginx/C2 HTTP、Auditd 和 EVTX；PCAP 因本机缺 Zeek/tshark 未解析；N6 普通 syslog/auth.log 尚未进入统一 normalizer。
- 本次真实靶场 run report: `data/testbed_upload_analysis_final/testbed_upload_run_report.json`。该目录为本地运行产物，不建议提交 Git。

## 8. 最近一次状态更新时间

- Date: 2026-09-10
- Branch: `main`
- Latest pushed HEAD: `24634c0 fix: sync analysis task progress and run picker`
- Working tree note: 当前仅 `datasets/darpa_tc_e3_cadets/` 中少量 Evaluation-only JSON 仍为未跟踪文件；提交时需显式白名单 staging，避免把大型数据或运行产物误提交。
