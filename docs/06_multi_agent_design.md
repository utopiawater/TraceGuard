# 轻量多 Agent Harness 设计

## 1. 结论

建议实现 1 个 Coordinator + 5 个专职 Agent：Host、Network、Correlation、Attribution、Report。日志解析、规则检测、Neo4j 查询、ATT&CK 查询、IOC 查询都是确定性工具，不包装成“会聊天的 Agent”。这样既能满足多智能体协调要求，又能在短周期内实现、测试和解释。

```text
                    Coordinator
             /          |          \
          Host       Network    Correlation
             \          |          /
                 shared evidence
                       |
                 Attribution
                       |
                    Report
```

Correlation Agent 同时承担 AttackChain 调查，避免再拆一个只会转述的 Agent。Report Agent 只消费已审计结果，不重新发明事实。

## 2. Harness 核心原则

1. **事实与推理解耦**：工具返回事件、图路径、ATT&CK 和情报事实；LLM 只形成调查计划、比较假设和解释。
2. **证据强制引用**：每条 finding 至少一个 evidence_id；无证据只能列为 question/uncertainty。
3. **最小权限**：Agent 只读，不执行 shell、任意 SQL/Cypher、攻击工具或互联网搜索。
4. **结构化通信**：Agent 之间不共享自由聊天历史，只通过 AgentTask、AgentResult 和 case evidence board。
5. **上下文可控**：传递 ID 和摘要，需要时工具分页读取；不把全量日志塞入 prompt。
6. **可降级**：LLM 不可用时，确定性链和模板报告仍能演示。
7. **可重复**：固定 prompt version、模型参数和输入 refs；保存工具调用摘要。

## 3. 运行状态机

```text
case_created
 → coordinator_planning
 → specialist_tasks_queued
 → specialists_running
 → evidence_merge
 → correlation_review
 → attribution_optional
 → report_generation
 → completed | partial | failed
```

每个任务具备 `task_id`、`parent_task_id`、幂等键、最大步骤、deadline 和重试次数。Coordinator 只可创建 allowlist 中的子任务。任务失败不回滚已验证证据；最终状态可为 partial，并明确缺失来源。

## 4. 共享上下文

CaseContext 只包含：

- case_id、时间范围、资产范围和调查目标；
- event/detection/chain/entity/evidence refs；
- 已确认事实、待验证假设、已排除假设；
- 数据源健康和已知缺口；
- 当前 ATT&CK/prompt/model/rule versions；
- token/tool/step budget。

Evidence Board 采用 append-only：

```yaml
claim:
  claim_id: string
  text: string
  status: proposed|supported|contradicted|accepted
  author_agent: string
  evidence_ids: [string]
  counter_evidence_ids: [string]
  confidence: number
```

## 5. 工具目录

| Tool | 输入 | 输出 | 权限/限制 |
|---|---|---|---|
| `event_search` | filters、time range、cursor | UnifiedSecurityEvent refs | 只读、分页、最大行数 |
| `entity_timeline` | entity_id、range | ordered events | 只读 |
| `session_lookup` | session/entity | login/network sessions | 只读 |
| `graph_neighbors` | entity、relation allowlist、depth≤3 | GraphEntity/Relation | 只读 |
| `graph_path` | start/end、allowed relations、time range | bounded paths | 无任意 Cypher |
| `detection_lookup` | IDs/filters | DetectionResult | 只读 |
| `attack_lookup` | Technique/Group/Software ID | fixed ATT&CK facts | 固定版本 |
| `intel_lookup` | IOC | cached facts + provenance | provider allowlist、超时 |
| `evidence_get` | evidence IDs | evidence excerpts | 脱敏、分页 |
| `chain_validate` | proposed step refs | constraint results | 确定性 |
| `report_render` | accepted result refs | report artifact | 只接受 schema-valid 输入 |

## 6. Agent 输入输出和权限总表

| Agent | 输入 | 输出 | 数据权限 | 图查询 | ATT&CK |
|---|---|---|---|---|---|
| Coordinator | AgentTask、CaseContext、source health、Detection refs | CoordinatorPlan、子 AgentTask、编排状态 | case 摘要和任务元数据 | 无直接图查询 | 无直接查询 |
| Host | host/entity/time refs、相关 Detection | 主机时间线 findings、证据缺口、AgentResult | case 内主机事件，敏感字段脱敏 | 主机关系白名单、depth≤3 | 只读已映射 Technique |
| Network | session/IP/domain refs、相关 Detection | 会话/C2/隐蔽信道 findings、AgentResult | case 内网络事件和缓存情报 | 网络关系白名单、depth≤3 | 只读已映射 Technique |
| Correlation | 候选 AttackChain、Host/Network results | 链审阅、替代路径、缺口、AgentResult | case 内跨源证据 | bounded path，无任意 Cypher | Technique/Tactic 只读 |
| Attribution | confirmed/high-confidence chain、fingerprints、IOC refs | Top-k/无法归因、支持与反证、AgentResult | 去标识化 case facts 和带来源情报 | C2/Technique/Software 关系只读 | Group/Software/Technique 只读 |
| Report | accepted claims、Chain、Evaluation refs | ReportDraft/报告引用、AgentResult | 只读 accepted/supported claims | 不做新查询 | 只读已确认映射 |

## 7. Agent 定义

### 6.1 Coordinator Agent

**职责**：把调查目标分解为最少的专职任务；先检查数据源健康和已有 Detection；合并结果；决定是否需要归因；控制预算和终止条件。

**输入/输出**：输入 AgentTask + CaseContext；输出子任务列表或最终编排状态。

**Tools**：case summary、source health、detection lookup、task submit/status。不能直接读 raw payload，不能修改图谱。

**Neo4j/ATT&CK**：不直接查询，使用 specialist 结果。

**Prompt 模板**：

```text
你是调查协调器。只依据提供的 case refs 和工具结果工作。
目标：用最少任务回答调查问题，并保证每条结论可追溯。
先检查数据源缺口；按 Host、Network、Correlation、Attribution、Report 分派。
不要推测不存在的事件，不要把 ATT&CK 相似性写成身份事实。
输出严格符合 CoordinatorPlan schema。
```

**错误恢复**：同一失败任务最多重试一次；参数错误修正后重试；数据源缺失转 partial；模型错误改用固定调查 playbook。

### 6.2 Host Agent

**职责**：分析登录、进程父子、文件、注册表、权限和内存行为，提出有 evidence 的主机侧时间线。

**Tools**：event_search、entity_timeline、session_lookup、bounded graph neighbors、evidence_get、detection_lookup。

**数据访问**：仅 case 的 host/entity/time scope；命令行默认脱敏。

**Neo4j**：只允许 SPAWNED、EXECUTED_BY、LOGGED_IN、ACCESSED/CREATED/MODIFIED/DELETED、ON_HOST 和 SUPPORTED_BY。

**ATT&CK**：只查已由 Detection 映射的 Technique；不能凭字符串自行新增映射。

**Prompt 模板**：

```text
你是主机证据分析员。重建账号、会话、进程、文件、注册表、权限和内存行为。
区分直接观测、跨源印证和推断。对每条 finding 引用 evidence_id。
检查 PID 重用、缺失父进程、时钟不确定性和正常管理行为。
不得从可疑进程名直接断言恶意。输出 AgentResult。
```

**错误恢复**：实体 provisional 时请求 resolver 状态；事件过多时缩小到 Detection 周围窗口；来源缺失时列出无法回答的问题。

### 6.3 Network Agent

**职责**：重建 Zeek 会话，分析边界/内网方向、DNS/HTTP/ICMP 特征、C2 beacon 和传感器质量。

**Tools**：event_search、session_lookup、network feature query、intel_lookup、evidence_get。

**数据访问**：网络 session 与关联 host/process；不读取无关邮件正文或文件内容。

**Neo4j**：Session、IP、Domain、Host、C2 及 FROM/TO/INITIATED/RESOLVED_TO/COMMUNICATED_WITH。

**Prompt 模板**：

```text
你是网络证据分析员。以 session_id/Zeek uid 为主键重建流量。
先检查 capture_loss、方向和 NAT/主机-IP 有效期，再评估异常。
高熵、周期性或情报命中只能作为特征，必须给出正常替代解释。
每条 finding 引用 evidence_id，输出 AgentResult。
```

**错误恢复**：协议日志缺失时退回 conn 元数据并降低置信度；情报不可用时输出 unknown，不生成默认威胁分数。

### 6.4 Correlation Agent

**职责**：审阅确定性 Correlation Engine 的候选链，比较竞争路径，指出入口、横移、提权和数据 lineage 的证据缺口。

**Tools**：chain lookup、chain_validate、graph_path、host/network results、evidence_get。

**数据访问**：case 内跨源只读。

**Neo4j**：只能使用 bounded path 工具，深度和关系白名单由服务器控制。

**ATT&CK**：读取 Technique/Tactic 事实和 mapping rationale。

**Prompt 模板**：

```text
你是跨源攻击链分析员。系统已给出候选路径；你的任务是验证而非创造边。
逐步检查时间单调、共享实体/会话、前驱关系和独立证据。
比较至少一个替代解释。无法证明入口或外传文件时必须明确降级措辞。
只输出引用现有 step_id/evidence_id 的 AgentResult。
```

**错误恢复**：chain_validate 失败则删除无效建议边并重新评估；没有闭环时输出 partial chain，不补造步骤。

### 6.5 Attribution Agent

**职责**：基于 Technique、Software、工具指纹和 C2 基础设施产生候选组织排名，列出支持证据、反证和数据新鲜度。

**Tools**：attack_lookup、intel_lookup、fingerprint lookup、evidence_get、deterministic similarity。

**数据访问**：不访问无关个人身份数据；外部情报只使用带 provenance 的事实。

**Prompt 模板**：

```text
你是威胁归因分析员。输出候选相似性，不作现实身份定性。
优先使用直接基础设施/软件证据，其次是加权 TTP；惩罚通用技术。
对每个候选列出支持、反证、缺失的预期行为和证据新鲜度。
证据不足时选择 unable_to_attribute。输出 AgentResult。
```

**错误恢复**：ATT&CK/情报版本缺失则不运行；只有通用 Technique 时返回 unable_to_attribute。

### 6.6 Report Agent

**职责**：把已接受的事实、链、ATT&CK 映射和归因候选组织成报告；不执行新调查。

**Tools**：case summary、accepted claims、chain/evidence lookup、report_render。

**数据访问**：只读 accepted/supported claims；按报告权限脱敏。

**Prompt 模板**：

```text
你是安全事件报告员。只使用 accepted/supported claims。
报告按摘要、范围、时间线、攻击链、影响、归因候选、证据、缺口和建议组织。
每个技术结论引用 evidence_id；区分事实、推断和未知。
不得增加输入中不存在的 IOC、Technique 或影响。输出 ReportDraft schema。
```

**错误恢复**：schema 不合法重试一次；仍失败则使用确定性模板把字段直接排版。

## 8. Agent 间通信

通信只发生在 task store：

1. Coordinator 写 AgentTask；
2. specialist 读取 refs，通过工具取数据；
3. specialist 写 AgentResult 和 claims；
4. harness 验证 schema、evidence existence 和权限；
5. Coordinator 读取压缩后的结果，不读取原始 chain-of-thought；
6. Report 只读取 accepted/supported claims。

禁止 Agent 互相发送自然语言私信；这能防止上下文污染和不可追踪的“共识”。

## 9. Harness 实现

课程版用 Python 状态机即可：

- `TaskRepository`：SQLite 持久化；
- `AgentRegistry`：role → prompt/tools/schema；
- `ToolGateway`：参数校验、权限、分页、超时和审计；
- `ModelClient`：OpenAI-compatible，统一重试和 JSON schema；
- `Orchestrator`：队列、预算、状态转换；
- `EvidenceValidator`：检查 evidence_id 存在、scope 和 claim 覆盖；
- `FallbackReporter`：无 LLM 模板报告。

不需要 LangChain/LangGraph 才能叫 Harness；若引入框架会影响可调试性，优先自研 500-800 行以内的显式状态机。

## 10. 防幻觉与质量门

- AgentResult JSON schema 通过；
- 所有 finding 的 evidence_ids 存在且属于 case；
- Technique ID 存在于固定 ATT&CK 版本；
- entity/session/step refs 存在；
- 引用为 external_unverified 时不得形成高置信事实；
- finding 与 evidence 的关键词一致性仅作辅助，最终由规则或人工抽查；
- Report 中没有未出现在 accepted claims 的 IOC/数字；
- 保存 prompt/model/tool 版本，不保存或展示隐式推理过程。

## 11. 评估

| 维度 | 指标 |
|---|---|
| 正确性 | unsupported claim rate、evidence precision、Technique hallucination rate |
| 完整性 | 已知关键步骤覆盖率、待调查问题召回率 |
| 协调 | 重复工具调用率、无效子任务率、平均任务数 |
| 鲁棒性 | 缺源、超时、模型不可用三种故障下完成状态 |
| 成本 | token、tool calls、wall time |
| 一致性 | 同输入重复 5 次的核心 findings 一致率 |

P0 门槛是零不存在的 evidence/Technique 引用、模型不可用仍有确定性报告、每个结论能在 UI 下钻。自然语言文采不作为核心指标。

## 12. 演示流程

用户在攻击链页面点击“Agent 调查”，Coordinator 并行创建 Host 和 Network 任务；二者返回后，Correlation 审阅候选链；只有存在足够 Technique/IOC 时才触发 Attribution；Report 生成带证据编号的摘要。前端展示任务图、每个 Agent 的输入范围、工具调用摘要、状态、发现和证据，不展示隐藏推理文本。
