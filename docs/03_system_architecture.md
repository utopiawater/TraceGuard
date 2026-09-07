# 恶意攻击溯源分析系统总体架构

## 1. 推荐架构

推荐采用“可回放的事件管道 + 结构化事件库 + Neo4j 关系图 + 确定性检测/关联 + 证据约束的多 Agent + Web 调查台”。课程周期内不引入 Kafka、Flink、微服务网格或向量数据库。运行时先使用一个 FastAPI 应用、一个独立 worker、Neo4j、SQLite 和文件归档，通过清晰模块边界保持未来可替换性。

```text
实时采集                          离线导入
Wazuh / Sysmon / Auditd / Zeek    Dataset Adapter / PCAP Replay
              \                    /
               RawEventEnvelope
                      |
        原始归档 + 校验 + Dead Letter
                      |
            标准化与时间质量处理
                      |
           UnifiedSecurityEvent
                      |
       实体解析 / 会话重建 / 语义去重
             |                    |
       结构化事件库          Neo4j 安全关系图
             \                    /
             Detection + Correlation
                      |
        ATT&CK 映射与 AttackChain
                      |
          证据约束的 Multi-Agent
                      |
       Web 调查、归因候选与报告导出
```

关键取舍：

- Wazuh 是采集/规则生态，不是统一数据模型；所有来源先进入本项目契约。
- Neo4j 保存“可查询关系”，不承担所有原始日志全文与任务状态。
- SQLite 用于课程规模的事件索引、检测、任务和报告元数据；若并发和规模实测超限，再无损替换为 PostgreSQL。
- 原始 JSON/NDJSON/PCAP 保存在文件归档，记录内容哈希；图边和推理结论通过 `evidence_id` 回查。
- 确定性组件判断“发生了什么”；LLM 判断“下一步查什么、跨源事实如何解释、哪些归因假设更合理”。

## 2. 分层输入输出和职责

| 层 | 输入 | 输出 | 职责 | 数据格式 | 依赖 |
|---|---|---|---|---|---|
| 采集层 | Event Channel、Wazuh JSON、Auditd、Zeek、PCAP、数据集文件 | `RawEventEnvelope` | 增量读取、来源标记、内容哈希、断点、采集健康 | JSONL；PCAP 只作原件 | 源系统 |
| 接入层 | RawEventEnvelope | accepted/raw-ref 或 dead-letter | schema 基础校验、幂等、背压、原始归档 | JSON Schema v1 | 文件归档、SQLite |
| 标准化层 | raw-ref + raw payload | `UnifiedSecurityEvent` | 源字段映射、时间标准化、动作语义和质量标注 | JSON Schema/Pydantic | adapter registry |
| 实体与会话层 | UnifiedSecurityEvent | canonical entity refs、Session、关系候选 | 别名合并、进程实例化、登录/网络会话重建 | typed records | asset inventory、identity rules |
| 存储投影层 | 标准事件和关系候选 | 事件行、图节点/边 | 结构化查询、图投影、重放 checkpoint | SQLite + Cypher | Neo4j |
| 检测层 | 事件、会话、窗口聚合 | `DetectionResult` | 规则、阈值、统计基线；说明命中理由 | versioned JSON | rule registry |
| 关联层 | DetectionResult + graph | `AttackChain` 候选 | 时间/实体/会话约束、路径评分、入口/横移/提权/外传 | versioned JSON | Neo4j、ATT&CK KB |
| 知识层 | detection tags | Technique/Tactic/Group facts | 固定版本 ATT&CK 数据与本地 mapping | STIX 2.1 snapshot + index | MITRE ATT&CK |
| Agent 层 | `AgentTask` + 只读工具结果 | `AgentResult` | 调查编排、证据解释、候选归因、报告 | strict JSON | Query tools、LLM |
| API 层 | Web/CLI 请求 | REST/WS response | 鉴权、分页、任务状态、报告下载 | OpenAPI + SSE/WS | application services |
| 产品层 | API response | 调查视图与报告 | 从态势到证据的下钻，明确实时/快照模式 | React/TypeScript | API client |

## 3. 数据流与控制流

### 3.1 实时路径

1. Collector 读取一条源记录，生成含 `source_record_id`、`sensor_id`、`observed_time` 和 `sha256` 的 RawEventEnvelope。
2. Ingestion 以 `raw_id` 幂等写入 raw archive 和索引；失败记录进入 dead-letter。
3. Adapter 生成 UnifiedSecurityEvent，保留 `raw_ref`、`parser_version` 和字段级质量。
4. Resolver 生成 canonical entity refs；Sessionizer 补齐登录/网络会话；Graph Projector 写入图。
5. Detection Engine 对单事件或窗口运行规则，产生 DetectionResult 与 Evidence。
6. Correlation Engine 将相关 Detection 按实体、会话、时间和因果约束聚为 AttackChain。
7. Coordinator 在高危链或人工请求时启动 Agent 任务。Agent 只通过受控查询工具读取事实。
8. API 将链更新通过 WebSocket/SSE 推送；前端按 evidence_id 下钻原始记录。

### 3.2 离线路径

Dataset Adapter 只负责把数据集记录转换为同一 RawEventEnvelope，并附加 `dataset_id`、`scenario_id`、`ground_truth` 引用。之后完全复用实时路径。严禁为某一数据集复制一套检测或图谱逻辑。

### 3.3 重放与可重复性

每次分析运行生成 `run_id`，记录：

- input manifest 与内容哈希；
- adapter/parser/rule/ATT&CK/prompt/model 版本；
- 时间窗口和阈值；
- 产生的事件、检测、链和报告 ID；
- 失败与降级信息。

只要原始归档和版本文件存在，即可在空数据库中重建结果。

## 4. 组件和部署边界

### 4.1 课程规模部署

```text
analysis-node
├─ api            FastAPI REST + WebSocket/SSE
├─ worker         ingest/normalize/detect/correlate/agent jobs
├─ sqlite         metadata, normalized events, jobs, reports
├─ raw-archive    append-only JSONL/PCAP manifests
├─ neo4j          entity and attack graph
└─ frontend       React static build

sensor nodes
├─ Wazuh Agent + Windows Event Channel/Sysmon
├─ Wazuh Agent + Auditd
└─ Zeek sensor on mirrored boundary/internal traffic
```

API 与 worker 可先在同一 Python 包中以不同进程启动，避免“伪微服务”。模块通过 service interfaces 和共享 contracts 解耦，不通过直接导入对方内部类耦合。

### 4.2 数据保留

- raw：实验期间全量，提交包保留关键场景和 manifest；
- normalized：按 run_id 可清理；
- graph：由 normalized 重建，不是唯一事实源；
- reports：不可变版本；
- PCAP：只保留小型场景切片，避免压垮磁盘。

## 5. 时间对齐架构

物理层先统一 W32Time/chrony/NTP；应用层不伪造精确时间，而是保存：

- `event_time`：源记录声明的事件时间；
- `observed_time`：collector 观察时间；
- `ingested_time`：中心接收时间；
- `clock_offset_ms`：已测得的源时钟偏移；
- `uncertainty_ms`：时间不确定性；
- `time_quality`：synced/estimated/unsynced/unknown。

关联时将时间点视为区间 `[corrected_time-uncertainty, corrected_time+uncertainty]`。窗口由数据源组合配置，例如 Sysmon NetworkConnect 与 Zeek conn 的默认容差可从 1 秒起，根据靶场实测分布调优；不能仅凭“落在窗口”就建立强因果关系，还需五元组、主机-IP 有效期和进程标识。

## 6. 可靠性和失败处理

- bounded queue + disk spool，队列满时停止读取或落盘，不丢弃；
- checkpoint 以源文件 inode/offset 或 API cursor 保存；
- parser 失败进入 dead-letter，携带错误码和样例；
- Neo4j 写入失败可从事件库重投影；
- 外部情报超时返回 `unavailable`，不返回伪造评分；
- LLM 输出必须通过 JSON Schema；失败可重试一次，再降级为确定性模板报告；
- 前端显示 `live`、`replay`、`snapshot` 三种模式，禁止静默替换。

## 7. 安全边界

- Collector 到中心使用 Wazuh 通道或实验网内 TLS；API 密钥只从环境变量读取。
- Agent 工具默认只读，禁止 shell、任意 Cypher、外网浏览和攻击工具调用。
- Neo4j 对 API 使用只读账号；写入账号仅给 projector/worker。
- 原始日志可能包含命令行、账号和邮件内容，报告默认脱敏。
- 靶场网络和管理网络分离；攻击/C2 节点无默认公网出口。

## 8. 技术栈评估

| 技术 | 建议 | 理由与边界 |
|---|---|---|
| Python + FastAPI | 采用 | 安全解析生态丰富、OpenAPI 自动化；单体模块化足够 |
| React + TypeScript | 采用 | 类型契约和图表生态成熟；从去年 JSX 升级到 TS |
| Neo4j | 采用 | 多跳实体关系适合；需避免全量 Event 节点和无界查询 |
| SQLite | MVP 采用 | 零运维，足够支撑课程演示；开启 WAL、分页和索引 |
| PostgreSQL | 条件升级 | 多 worker、高并发写或多人部署后替换；不是 P0 |
| Wazuh + Sysmon + Auditd | 采用 | Wazuh 可收集 Windows Event Channel；Sysmon 提供 ProcessGuid、网络、注册表、DNS 和多类进程交互事件。Sysmon 网络事件默认关闭且高噪事件需过滤，配置必须随项目交付。参考 [Microsoft Sysmon 官方事件说明](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) 与 [Wazuh Event Channel 配置](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/configuration.html) |
| Zeek | 采用 | `conn/dns/http/files` 等日志可用 uid 关联；优先 JSON 输出。参考 [Zeek 官方日志目录](https://docs.zeek.org/en/current/reference/logs/) |
| OpenAI-compatible API | 采用可替换接口 | 模型不是事实源；必须支持无模型模板降级 |
| ECharts + Cytoscape.js | 采用 | ECharts 负责指标/ATT&CK，Cytoscape 负责可控图交互；不同时引入 G6 |
| Docker Compose | 中心服务采用 | 便于交付；Windows/Sysmon、Firewall 和交换镜像仍需 VM/虚拟网络 |
| Kafka/Redis/Elasticsearch | 当前不采用 | 课程规模下运维成本高；通过接口预留替换点 |

## 9. 外部知识版本

ATT&CK 不应硬编码为过时字典。实现时下载官方 STIX 2.1 快照并写入 `knowledge/attack/<version>/`，构建本地只读索引。2026-09 设计基线可固定为 ATT&CK v19.2；每次升级需重新跑映射测试。官方提供 STIX 与 TAXII 访问方式，见 [ATT&CK Data and Tools](https://attack.mitre.org/resources/attack-data-and-tools/)。

## 10. 架构验收门

第一条端到端链必须在没有 Agent、没有外部情报、没有高级 UI 的条件下先成立：

```text
sample Sysmon/Zeek event
→ schema validation
→ canonical process/IP/session
→ Neo4j relation with evidence_id
→ deterministic detection
→ ATT&CK technique
→ attack-chain API
→ frontend evidence drawer
```

只有该闭环通过后，才接入实时传感器、Agent 和 8 节点靶场。
