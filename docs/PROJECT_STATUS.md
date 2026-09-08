# TraceGuard Project Status

本文件是 TraceGuard 当前仓库状态的交接文档。结论以 2026-09-09 本地仓库、数据集运行报告、测试结果和文档为准；如果它与早期聊天记录或旧设计文档冲突，以当前代码和本文件为准。

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
- Detection 覆盖登录、PowerShell、端网双源连接、横向移动、权限变化、敏感文件、数据外传、注册表持久化、内存行为、DNS/HTTP/ICMP 隐蔽信道，以及本次公开数据集所需的少量通用规则。
- ATT&CK knowledge 固定在 `knowledge/attack/mappings.json`，当前 T1046 名称为 `Network Service Scanning`。
- AttackChain 仍由 `DeterministicChainBuilder` 基于 Detection 和 ATT&CK tactic 生成，不读取 Ground Truth。
- Multi-Agent 保持六角色：Coordinator、Host、Network、Correlation、Attribution、Report。Quick scope 使用 Coordinator、Host、Network、Correlation；真实 LLM 不可用时明确记录 deterministic fallback。
- Frontend 13 个页面接真实 API，不用业务 mock 伪造结果。
- `/api/datasets` 和 Dataset 页面已读取真实 DARPA run report；Dataset 页面会展示 IOC coverage、未覆盖 IOC 构成、低语义系统调用占比和指标限制说明。

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

最新 run report:

- report: `data/dataset_e3/dataset_run_report.json`
- input_records: 20,776
- accepted_raw: 20,776
- normalized_records: 20,776
- failed_records: 0
- mapping_rate: 1.0
- unknown_action_count: 0
- entity_count: 461
- session_count: 16
- detection_count: 348
- evidence_count: 20,776
- technique_ids: `T1005`, `T1046`, `T1055`, `T1059`, `T1068`, `T1071.001`
- chain_count: 1
- IOC coverage: 99 / 776
- uncovered IOC analysis: 677 个未覆盖 IOC 中 651 个为 network IOC，648 个为低语义系统调用；主要由 `recvfrom`、`sendto` 和少量文件落地/权限/删除事件组成。
- Evidence backtrace rate: 1.0

当前 Dataset AttackChain 由系统 Detection 生成，关键步骤为：

1. command_and_control / `T1071.001`
2. collection / `T1005`
3. execution / `T1059`
4. privilege_escalation / `T1068`

说明：`T1055` 仍作为 memory behavior detection 出现在 Technique 集合中，但同一 privilege stage 的链代表 detection 已优先选择 `det.host.privilege_escalation` / `T1068`，避免早期 `memory.protect` 抢占权限提升阶段。

二分类 Precision / Recall / F1 不报告：

> 该 DARPA TC E3 CADets 实验切片仅提供 IOC 命中及相关上下文信息，不具备完备逐事件 benign/attack 二分类真值，因此不报告二分类 Precision、Recall 和 F1。

## 4. 测试与验收基线

正式 Python 版本来自 `pyproject.toml`：`>=3.13,<3.14`。本机裸 `python` 指向 Python 3.8，不可作为正式测试环境；`xxq` conda 环境为 Python 3.11，也不符合当前项目要求。正式回归使用 `py -3.13` 或项目 `.venv`。

最近一次通过的回归：

- `py -3.13 -m pytest -q --basetemp data/test_tmp_full_final2`: passed
- `py -3.13 scripts/self_check.py`: passed，8 checks
- `cd frontend; npm.cmd test`: passed，1 file / 2 tests
- `cd frontend; npm.cmd run build`: passed

正式真实 DeepSeek 验收 artifact 保留在：

- `artifacts/release/case_1421c3d00365403d.acceptance.json`
- `artifacts/release/case_1421c3d00365403d-report.md`
- `artifacts/release/case_1421c3d00365403d-report.html`

普通自动化测试使用 Fake/Echo/Failing model，不消耗真实 LLM token。除非专门做真实模型验收，不需要重新调用 DeepSeek。

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

## 6. 对照小学期要求的剩余项

代码侧当前建议冻结 Dataset 和主架构。后续主要是验收材料和云靶场数据对接：

1. 等云平台靶场日志 bundle 到位后，按 `docs/13_cloud_testbed_handoff.md` 导入 TraceGuard 并生成 run report。
2. 固定一条答辩演示流程：启动系统 -> 展示七阶段 fixture -> 展示 DARPA Dataset -> 展示 Agent 调查 -> 展示报告导出。
3. 补最终课程报告/PPT：系统架构、数据模型、检测规则、ATT&CK、AttackChain、Agent、公开数据集评估、云靶场验证、局限性。
4. 清理或说明当前 `git status` 中 `.pytest-*` 权限受限临时目录；提交前不要误删 release artifact 或数据集原始文件。
5. 决定 Dataset 大文件策略：`processed_dataset/*.json` 建议 Git LFS 或外部下载说明；`data/dataset_e3/traceguard.db` 和 raw archive 不提交。

## 7. 当前已知限制

- DARPA Precision / Recall / F1 为 N/A，原因是缺少完整逐事件二分类真值。
- Attribution 是候选相似性分析，不是攻击者身份确认。
- Neo4j 图查询和前端图谱是 bounded 视图，不是无限全库图遍历。
- PDF 报告导出未实现，当前支持 Markdown/HTML。
- 真实云靶场尚未由本仓库直接验证；需等待同学提供日志 bundle 和 manifest。

## 8. 最近一次状态更新时间

- Date: 2026-09-09
- Branch: `main`
- HEAD at latest committed DARPA integration: `97e66f4`
- Working tree note: 正常源码改动应只来自当前任务；仍可能显示既有 `.pytest-*` / `.tmp-*` 权限受限临时目录状态，提交时需显式白名单 staging。
