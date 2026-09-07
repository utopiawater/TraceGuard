# 工程模块划分与接口

## 1. 推荐目录

```text
project/
├─ contracts/           版本化模型、JSON Schema、OpenAPI
├─ collectors/          实时源读取
├─ ingestion/           原始归档、幂等、checkpoint、dead-letter
├─ normalizer/          源 Adapter 与时间标准化
├─ identity/            canonical entity 与 alias
├─ sessions/            登录/网络会话重建
├─ storage/             SQLite、raw archive、repositories
├─ graph/               Neo4j schema、projector、bounded queries
├─ detection/           规则、窗口和隐蔽信道检测
├─ knowledge/           ATT&CK 快照与本地索引
├─ attack_chain/        跨源关联和路径恢复
├─ agents/              Harness、roles、tools、prompts
├─ attribution/         指纹、C2、APT 候选
├─ backend/             FastAPI application
├─ frontend/            React TypeScript Web
├─ datasets/            adapters、manifests、切片
├─ testbed/             拓扑、传感器配置、场景 manifest
├─ evaluation/          Ground Truth 与指标
├─ tests/               fixtures、unit、contract、integration、e2e
├─ docs/
└─ compose.yaml
```

目录按职责而非成员划分。所有模块只能依赖 `contracts` 和声明的上游接口，不能互相读取内部数据库表。

## 2. 模块契约

| 模块 | 职责 | 输入 | 输出/核心结构 | 提供的内部 API | 依赖 | 独立测试 |
|---|---|---|---|---|---|---|
| contracts | 定义共享模型与兼容策略 | 设计文档 | 7 个核心模型、JSON Schema、OpenAPI | schema validate、type generation | 无 | valid/invalid fixtures、兼容性 diff |
| collectors | 增量读取 Wazuh/Zeek/文件/API | 源配置/cursor | RawEventEnvelope | `collect() -> AsyncIterator[Raw]` | contracts | 临时日志追加、轮转、断点和重复 |
| ingestion | 原始归档、幂等、背压、死信 | RawEventEnvelope | RawRef、checkpoint、DeadLetter | `accept(raw)`、`replay(run)` | contracts、storage | 崩溃恢复、重复输入、队列满 |
| normalizer | 解析 Wazuh/Sysmon/Auditd/Zeek | RawRef/payload | UnifiedSecurityEvent | `normalize(raw)`、adapter registry | contracts | 每个源 golden fixtures、字段映射 |
| identity | 规范化/合并实体和别名 | UnifiedEvent、inventory | EntityRef、AliasDecision | `resolve(ref, at_time)` | contracts、storage | PID/IP 重用、大小写、别名冲突 |
| sessions | 登录与网络会话状态机 | UnifiedEvent | Session | `consume(event)`、`close_expired()` | contracts、identity | 并发登录、缺结束、Zeek uid 拼接 |
| storage | 事件、任务、报告、raw 索引 | typed records | repositories | append/get/search/transaction | contracts | repository contract、迁移、WAL |
| graph | 图 schema、投影和安全查询 | events/entities/sessions/detections | GraphEntity/GraphRelation | `project(batch)`、`path(query)` | contracts、Neo4j | Testcontainers/临时库、幂等、边历史 |
| detection | 单事件/窗口/相关性规则 | events/sessions/features | DetectionResult | `evaluate(event)`、`flush(window)` | contracts、knowledge 可选 | TP/FP fixtures、阈值边界 |
| knowledge | 固定 ATT&CK 知识与映射 | STIX snapshot、mapping files | Technique/Tactic/Group/Software facts | lookup/validate/map | contracts | 版本、revoked、ID 完整性 |
| attack_chain | 关联 Detection 并恢复路径 | detection + bounded graph | AttackChain | `build(case)`、`validate(chain)` | graph、knowledge、contracts | 时间逆序、无关攻击、完整链 |
| agents | 编排专职 Agent 和只读工具 | AgentTask、case refs | AgentResult | submit/cancel/status/run | contracts、application services | fake LLM、权限、schema、失败恢复 |
| attribution | 指纹、C2、APT 候选 | chain/evidence/ATT&CK/intel | AttributionResult | fingerprint/enrich/rank | knowledge、storage | 通用技术惩罚、无证据不归因 |
| backend | REST/WS、鉴权、分页、jobs | HTTP | API envelopes | OpenAPI endpoints | application modules | API contract、auth、pagination |
| frontend | 调查台与报告 UI | OpenAPI client | 页面/交互 | browser app | backend | component、mock server contract、e2e |
| datasets | 离线源适配与 manifest | dataset files | RawEventEnvelope、GroundTruth | inspect/iter_raw/map_truth | contracts | 小切片映射、hash、坏行 |
| testbed | 隔离拓扑、传感器/场景定义 | VM/container env | manifests、replay bundle | scenario runner interface | collectors、evaluation | 连通矩阵、安全出口、回滚 |
| evaluation | Ground Truth 比对和指标 | outputs + truth | EvaluationReport | `evaluate(run_id)` | contracts、storage | 手算小样例、零分母、样本量 |

## 3. 七个必须共享的模型

唯一权威定义位于 `contracts/`：

- `UnifiedSecurityEvent`
- `DetectionResult`
- `GraphEntity` / `GraphRelation`
- `AttackChain`
- `AgentTask`
- `AgentResult`
- `Evidence`

`RawEventEnvelope`、`Session`、`DatasetManifest`、`GroundTruthRecord` 作为支撑模型同样版本化。Python 由 Pydantic 生成 JSON Schema；FastAPI 复用同一类生成 OpenAPI；前端从 OpenAPI 生成 TypeScript。

## 4. 核心服务接口

### 4.1 Ingestion Port

```python
class RawEventSink(Protocol):
    async def accept(self, raw: RawEventEnvelope) -> RawAcceptResult: ...

class Normalizer(Protocol):
    def supports(self, source: SourceDescriptor) -> bool: ...
    def normalize(self, raw: RawEventEnvelope) -> list[UnifiedSecurityEvent]: ...
```

一个 raw 可能产生多个统一事件；零个事件必须返回明确 skip reason。

### 4.2 Repository Port

```python
class EventRepository(Protocol):
    def append(self, events: list[UnifiedSecurityEvent]) -> AppendResult: ...
    def search(self, query: EventQuery) -> CursorPage[UnifiedSecurityEvent]: ...

class EvidenceRepository(Protocol):
    def put(self, evidence: Evidence) -> None: ...
    def get_many(self, ids: list[str], scope: AccessScope) -> list[Evidence]: ...
```

### 4.3 Graph Port

```python
class GraphProjector(Protocol):
    def project(self, records: GraphProjectionBatch) -> ProjectionResult: ...

class GraphQuery(Protocol):
    def neighbors(self, query: BoundedNeighborQuery) -> GraphSlice: ...
    def paths(self, query: BoundedPathQuery) -> list[GraphPath]: ...
```

业务模块不得传入任意 Cypher。GraphQuery 在服务端限制 label、relation、时间、深度、节点数。

### 4.4 Detection 与 Correlation

```python
class Detector(Protocol):
    detector_id: str
    version: str
    def evaluate(self, context: DetectionContext) -> list[DetectionResult]: ...

class ChainBuilder(Protocol):
    def build(self, case: CaseScope) -> list[AttackChain]: ...
    def validate(self, chain: AttackChain) -> ChainValidation: ...
```

### 4.5 Agent Tool Port

```python
class AgentTool(Protocol):
    name: str
    input_schema: dict
    def invoke(self, args: dict, scope: AgentScope) -> ToolResult: ...
```

ToolResult 只含结果 refs、摘要、分页和错误；不返回数据库连接或自由查询能力。

## 5. 外部 REST API 分组

| Prefix | 资源 |
|---|---|
| `/api/v1/sources` | 采集健康、延迟、dead-letter |
| `/api/v1/events` | 统一事件检索和 raw 证据 |
| `/api/v1/entities` | 实体和时间线 |
| `/api/v1/sessions` | 登录/网络会话 |
| `/api/v1/detections` | 告警检索/审阅 |
| `/api/v1/cases` | 案例与关联任务 |
| `/api/v1/chains` | 攻击链、图、证据 |
| `/api/v1/attack` | ATT&CK 知识和覆盖 |
| `/api/v1/agent-runs` | Agent 任务与结果 |
| `/api/v1/attribution` | 候选归因 |
| `/api/v1/evaluations` | 靶场/数据集指标 |
| `/api/v1/reports` | 报告版本和导出 |

所有列表使用 cursor pagination；长操作返回 job；响应使用统一 data/meta/error envelope。

## 6. 模块依赖方向

```text
contracts
  ↑
storage ← ingestion ← collectors/datasets
  ↑          ↓
identity ← normalizer → sessions
  ↑          ↓           ↓
graph ← projection ← unified events
  ↑                     ↓
knowledge ← detection ← features
  ↑          ↓
attack_chain ←───────────┘
  ↑
agents / attribution
  ↑
backend ← frontend
```

禁止反向依赖，例如 normalizer 不能导入 Neo4j；frontend 不能导入数据集私有类型；Agent 不能直接导入 collector。

## 7. 测试分层

- **fixtures**：每个源 10-50 条最小样例，含坏行、缺字段和边界时间；
- **unit**：纯函数、identity、session state、rule；
- **contract**：模型生产者/消费者共享样例；
- **integration**：raw→event→graph→detection；
- **scenario**：Ground Truth manifest→AttackChain；
- **e2e**：API→前端链图→evidence drawer；
- **replay determinism**：同 bundle 两次输出除生成时间外一致。

模块完成定义：代码、接口、最小文档、golden fixture、正反测试、错误路径和 metrics 均存在。只有页面截图不算模块完成。

## 8. 配置和版本

`config/` 中只保存非秘密配置：

- source descriptors；
- identity rules；
- session timeouts；
- detection/mapping rules；
- ATT&CK snapshot version；
- tool permissions；
- testbed manifests。

秘密通过环境变量或本地未提交文件。每个输出记录配置版本/内容哈希，避免“阈值改了但报告没说”。

## 9. 并行开发边界

先冻结 contracts 和 fixtures。之后 collectors/normalizer、graph、detection、frontend、datasets/testbed 可以分别基于共享样例推进。集成以契约测试为门，不以口头约定合并。任何模块需要新字段时先提交 schema change 和迁移说明，再修改实现。
