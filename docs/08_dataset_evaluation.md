# 互联网公开攻击数据集验证设计

## 1. 当前结论

系统已经把 DARPA TC E3 CADets 看作“另一种 collector”，而不是另一套产品。所有离线记录先生成 RawEventEnvelope，再进入同一 normalizer、identity/session、detection、graph、ATT&CK 和 AttackChain 管道。

```text
Live Collector ──┐
                 ├→ RawEventEnvelope → Unified Event Pipeline → Evaluation
Dataset Adapter ─┘
```

当前 P0 数据集选择为 DARPA TC E3 CADets 精简切片，已完成端到端运行。不要为了某一数据集的列名修改 UnifiedSecurityEvent。

最新运行摘要：

- dataset_id: `darpa_tc_e3_cadets`
- dataset_name: `DARPA TC E3 CADets`
- input_records: 20,776
- normalized_records: 20,776
- detection_count: 225
- chain_count: 1
- report: `data/dataset_e3_generalization/dataset_run_report.json`
- frontend: `/datasets` 页面读取 `/api/datasets` 的真实报告，展示 IOC 覆盖、未覆盖 IOC 构成和二分类指标 N/A 原因。
- Precision / Recall / F1: N/A，因为该切片不具备完备逐事件 benign/attack 二分类真值。

说明：早期 `data/dataset_e3` snapshot 曾生成 348 条 Detection。真实靶场泛化修复后，单纯内存保护和普通权限上下文不再过度映射为 `T1055` / `T1068`，因此当前验收基线为 225 条 Detection、Technique `T1005` / `T1046` / `T1071.001`。数量下降是 ATT&CK 降噪结果，不是解析回归。

## 2. 候选数据集

| 候选 | 数据类型与价值 | 局限 | 建议 |
|---|---|---|---|
| LANL Unified Host and Network | 企业环境主机与网络事件，适合认证、进程、DNS/NetFlow 等跨源关联和规模测试 | 数据匿名化、下载量大，标签与现代 Sysmon 不完全等价 | P0/P1 候选；先取单日/小时间窗 |
| LANL Comprehensive Multi-Source | 多来源连续企业安全事件，可验证多源时序和 red-team 相关分析 | 真实企业数据匿名化，细粒度文件/注册表可能不足 | P1 补充 |
| ToN_IoT | 同一研究环境并行采集网络、Windows 7/10、Ubuntu 14/18 和 IoT telemetry，含正常与多类攻击 | 各子集字段和标签粒度不同，不应假设每条记录都可一一跨源对齐 | P0 首选之一，选择 Windows/Linux/Network 小切片 |
| DARPA TC E3 CADets | 高粒度主机/网络/file provenance，当前已预处理成 process/network/file 三类 JSON | 标签为 IOC/context，不是完备逐事件二分类真值 | 已作为 P0 正式数据集 |
| DARPA OpTC | 高粒度主机/网络 provenance，适合图关系和长攻击链 | 体量、格式和预处理复杂，课程周期风险最高 | P2 或高分版 |
| 网络专用数据集 | 适合 DNS/HTTP/流量 detector 的补充比较 | 无主机证据，不能单独证明完整溯源系统 | 只作 detector 辅助 |
| 主机专用数据集 | 适合 Audit/Sysmon adapter 和进程图 | 无网络链，不能单独完成官方数据集验收 | 只作 adapter 辅助 |

LANL 官方数据页同时列出 multi-source 和 Unified Host and Network 数据集，见 [LANL Cyber Security Research Data Sets](https://csr.lanl.gov/data/)。ToN_IoT 官方页面说明其并行收集网络流量、Windows 与 Linux 审计等异构来源，见 [UNSW ToN_IoT Datasets](https://research.unsw.edu.au/projects/toniot-datasets)。

## 3. 选择策略

按以下顺序做 30 分钟可行性探测：

1. 能否合法、稳定下载并记录 license/terms；
2. 是否有明确 schema、时间戳、host/user/process/network 字段；
3. 是否有 Ground Truth 或可确定的攻击时间窗；
4. 选取的切片是否同时覆盖至少主机 + 网络；
5. 预处理是否能在开发机 30 分钟内完成；
6. 是否可以把原始记录保持不变地归档。

推荐决策：

- 若 ToN_IoT 子集可直接获得且时间字段可对齐，先做 ToN_IoT 小切片；
- 若需要更强企业认证/网络链，选择 LANL 单日/已知 red-team 时间窗；
- OpTC 只在 P0 已闭环且有足够存储后追加。

最终 P0 数据集已选定为 DARPA TC E3 CADets。LANL、ToN_IoT、OpTC 可作为后续迁移性扩展，不作为当前验收必须项。

## 4. DatasetManifest

```yaml
dataset_id: toniot-or-lanl-slice
dataset_version: source-release-id
source_url: string
license_ref: string
downloaded_at: datetime
files:
  - path: relative/path
    sha256: string
    format: csv|jsonl|evtx|pcap|other
schema_ref: docs/schema
time_range: [start, end]
timezone_assumption: UTC|specified|unknown
selected_slice:
  rule: human-readable
  rows: integer
ground_truth:
  type: row_label|time_window|scenario_steps|none
  ref: relative/path
privacy_notes: string
```

## 5. Dataset Adapter 接口

```python
class DatasetAdapter(Protocol):
    adapter_id: str
    adapter_version: str

    def inspect(self, manifest: DatasetManifest) -> DatasetProfile: ...
    def iter_raw(self, manifest: DatasetManifest) -> Iterator[RawEventEnvelope]: ...
    def map_ground_truth(self, manifest: DatasetManifest) -> Iterator[GroundTruthRecord]: ...
```

`inspect` 先输出字段、空值、时间范围、标签分布和估计事件量；只有 profile 通过质量门才允许 ingest。

Adapter 不允许：

- 直接写 Neo4j；
- 直接产生 AttackChain；
- 把数据集 label 写成 DetectionResult；
- 丢弃无法映射的原始列；
- 修改 UnifiedSecurityEvent schema。

无法统一的列进入 `extensions.dataset.<dataset_id>`。

## 6. GroundTruthRecord

```yaml
GroundTruthRecord:
  truth_id: string
  dataset_id: string
  scope: event|window|host|flow|scenario
  start_time: datetime|null
  end_time: datetime|null
  source_record_ids: [string]
  label: benign|attack|unknown
  attack_type: string|null
  technique_ids: [string]
  confidence: exact|dataset_label|inferred
  notes: string
```

数据集原始 label 不自动等于 ATT&CK Technique。若论文/官方说明没有 Technique 标注，只评估 attack/benign 或场景阶段，不人工猜 Technique 作为“真值”。

## 7. 映射需求

### Host/Windows/Linux

至少寻找 timestamp、host、user/SID/uid、process/pid/ppid、event/action、path、outcome。匿名 host/user 保持为稳定 pseudonym，不尝试反匿名化。

### Network

至少寻找 timestamp、src/dst IP/port、protocol、bytes/packets、duration、DNS/HTTP 特征、flow/session ID。缺失 session ID 时创建 provisional session，并记录 identity quality。

### 标签

保留原 label、split 和 scenario；映射到统一 label 需有独立 mapping version。

## 8. 实验设计

### Experiment A 适配正确性

- schema-valid event ratio；
- 原始行 → raw envelope → normalized event 数量核对；
- 必填字段缺失率；
- 时间解析失败率；
- 随机抽样 100 条人工核对映射。

### Experiment B 实体与会话

- host/user/process/IP 去重；
- known session/flow 拼接；
- provisional identity 占比；
- 跨源候选关联精确率。

### Experiment C 检测与链

- 在数据集标签支持范围内计算 Detection P/R/F1；
- 入口、横移、C2 或外传等场景步骤覆盖；
- chain step F1 与顺序一致率；
- 每个结论 evidence 回查成功率。

### Experiment D 性能

- rows/s、events/s；
- ingestion 到 detection p50/p95；
- 峰值内存、SQLite/Neo4j 大小；
- 固定大小图查询 p95；
- 重放结果确定性。

### Experiment E 迁移性

在第二个来源上只新增 adapter，不改 contracts/detection API/frontend；统计修改的核心文件数。若必须改统一 schema，记录为架构缺陷。

## 9. 数据切分与防泄漏

- 按时间/场景切分，不随机打散同一攻击链；
- 规则阈值只在 train/calibration 窗口调优，在 test 窗口冻结；
- ATT&CK mapping 不使用测试标签生成；
- Agent 不读取 Ground Truth；评价 runner 在结果生成后对比；
- 数据集 label 与系统 DetectionResult 分库存放。

## 10. 输出报告

`dataset_run_report.json` 至少包含：

- manifest/hash/adapter/schema/rule/ATT&CK 版本；
- 输入行数、成功/失败/跳过数；
- 数据质量；
- detector 和 chain 指标、样本量；
- 混淆矩阵；
- 典型 TP/FP/FN 的 evidence IDs；
- 性能；
- 限制与不可比较项。

前端只显示事实指标，不用单一“准确率”掩盖类别不平衡。当前 Dataset 页面额外展示未覆盖 IOC 的 action、event_type 和 process Top 分布，用于解释 coverage 缺口，不作为 Detection 反向输入。

## 11. P0 和降级

P0：一个公开数据集小切片通过完整主管道，产生可回查的事件、检测、图和评估报告。若无法获得同时含主机/网络且可对齐的数据集，可以使用一个多源数据集的官方切片或两个同场景配套子集；不能用纯网络数据集替代官方“企业内网攻击行为数据集”的完整验证。

时间不足时可以降低数据量、只评估数据集明确提供的阶段、暂停 Agent 归因；不能绕过统一事件管道，也不能把数据集标签直接显示为系统检测结果。
