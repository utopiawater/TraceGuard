# 统一安全数据模型与 Neo4j Schema

## 1. 设计原则

统一模型不是把所有来源字段摊平成一个巨大 JSON，而是“稳定公共头 + 类型化主体/客体/网络块 + 来源扩展 + 证据引用”。公共契约使用 JSON Schema 2020-12 和 Pydantic 定义，字段命名固定为 snake_case，时间统一为带 `Z` 或显式时区的 RFC 3339，IP 使用规范字符串，枚举值小写。

模型版本与内容分离：`schema_version` 表示契约版本，`parser_version` 表示映射实现版本。新增可选字段为向后兼容；删除、改名或语义变化必须升 major。

## 2. 原始事件模型 RawEventEnvelope

```yaml
RawEventEnvelope:
  schema_version: "1.0"
  raw_id: string                 # sha256(sensor_id|source_record_id|raw_sha256)
  source:
    kind: wazuh|sysmon|windows_security|auditd|zeek|dataset|firewall|application
    product: string
    dataset: string|null         # 如 windows.security、zeek.conn
    sensor_id: string
    host_hint: string|null
  source_record_id: string|null  # Zeek uid、Audit serial、EventRecordID 等
  event_time_raw: string|number|null
  observed_time: datetime
  ingested_time: datetime
  payload_format: json|text|xml|csv|pcap_ref
  payload: object|string|null
  raw_ref: string                # 归档 URI/path + record offset
  raw_sha256: string
  labels: object                # dataset_id/scenario_id/ground_truth_ref
```

要求：payload 原样保存；解析错误不能修改原记录；同一 raw_id 重放幂等。

> 实现修订（2026-09-07）：增加 `windows_security` 来源枚举。最终架构已经定义独立 `WindowsSecurityAdapter`；若把原生 Windows Security Event XML 伪装为 `sysmon` 或 `wazuh` 会破坏来源 provenance。该变更只新增枚举值，不改变既有语义。

## 3. 统一事件 UnifiedSecurityEvent

### 3.1 稳定公共头

```yaml
UnifiedSecurityEvent:
  schema_version: "1.0"
  event_id: string               # 确定性 ID
  event_time: datetime           # 校正后的最佳事件时间
  observed_time: datetime
  ingested_time: datetime
  time:
    original: string|number|null
    clock_offset_ms: number|null
    uncertainty_ms: number
    quality: synced|estimated|unsynced|unknown
  source:
    kind: string
    product: string
    dataset: string
    sensor_id: string
    source_record_id: string|null
  host: EntityRef|null
  actor:
    user: UserRef|null
    process: ProcessRef|null
    parent_process: ProcessRef|null
  object:
    type: process|file|registry|user|host|network|memory|service|other|null
    ref: EntityRef|null
  network: NetworkContext|null
  action: string                 # process.start、file.read、network.connect 等
  event_type: string             # 源无关语义类
  outcome: success|failure|unknown
  severity: informational|low|medium|high|critical|unknown
  message: string|null
  tags: [string]
  extensions: object             # sysmon/auditd/zeek 等命名空间
  provenance:
    raw_id: string
    raw_ref: string
    raw_sha256: string
    parser_name: string
    parser_version: string
    mapping_warnings: [string]
```

### 3.2 EntityRef

```yaml
EntityRef:
  entity_type: host|user|process|file|registry|ip|domain|session|c2
  entity_id: string              # canonical ID
  source_ids: [string]           # 可选别名/源 ID
  display_name: string|null
  attributes: object             # 仅事件当时可确认的快照
  identity_quality: exact|derived|provisional
```

### 3.3 NetworkContext

```yaml
NetworkContext:
  session_id: string|null
  direction: inbound|outbound|lateral|unknown
  transport: tcp|udp|icmp|other|null
  application: dns|http|https|ssh|smb|rdp|smtp|other|null
  src: {ip: string|null, port: integer|null, host_id: string|null}
  dst: {ip: string|null, port: integer|null, host_id: string|null}
  bytes_sent: integer|null
  bytes_received: integer|null
  packets_sent: integer|null
  packets_received: integer|null
  duration_ms: number|null
  zeek_uid: string|null
  dns: object|null
  http: object|null
  icmp: object|null
```

### 3.4 event_id 和语义去重

`event_id = sha256(source.kind | sensor_id | source_record_id | raw_id | semantic_index)`。一个 Auditd 复合事件可产生多个语义事件，用 semantic_index 区分。

精确重复按 event_id 去除。跨源看到同一动作不是重复，必须保留两条事件，并建立 `CORROBORATES`/correlation record。另计算 `semantic_fingerprint` 用于候选聚类，但绝不据此删除证据。

## 4. 事件动作词表

| 类别 | action 示例 | 关键字段 |
|---|---|---|
| authentication | auth.logon、auth.logoff、auth.privilege_assigned | user、session、src_ip、logon_type |
| process | process.start、process.stop、process.access、process.inject、process.tamper | process instance、parent、target process、access mask |
| file | file.create、file.read、file.modify、file.delete、file.rename | path、hash、size、sensitivity |
| registry | registry.create、registry.set、registry.delete、registry.rename | hive、key、value_name、value_data |
| network | network.connect、network.accept、network.flow、dns.query、http.request、icmp.message | session/five tuple/protocol fields |
| memory | memory.remote_thread、memory.process_access、memory.image_load、memory.rwx_map | source/target process、address/module |

不要把 `event_type` 当 ATT&CK 技术；同一行为可映射多个技术，也可能完全正常。

## 5. 来源映射最低字段

### 5.1 Sysmon 经 Wazuh

- Event 1：`ProcessGuid/ProcessId/Image/CommandLine/User/ParentProcessGuid/ParentImage/Hashes/LogonGuid`。
- Event 3：进程 GUID、源/目的 IP/端口、协议；该事件默认关闭，配置需显式启用。
- Event 5：ProcessGuid + 终止时间，闭合进程生命周期。
- Event 7/8/10/25：映像加载、远程线程、进程访问、进程篡改，形成内存异常证据。
- Event 11/23/26：文件创建/删除。
- Event 12-14：注册表对象和值变化。
- Event 22：进程关联 DNS 查询。

Sysmon 官方说明强调 ProcessGuid 用于跨域唯一关联，事件时间为 UTC；各事件和噪声提示见 [Microsoft Sysmon 官方文档](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)。

### 5.2 Windows Security

- 4624/4625：登录成功/失败；
- 4634/4647：会话结束/用户发起注销；
- 4648：显式凭据；
- 4672：特殊权限；
- 4688/4689：进程创建/结束，作为 Sysmon 缺失时补充；
- 4768/4769/4776：Kerberos/NTLM 认证线索。

核心键为 `Computer + Boot/record context + LogonId`，同时保留 TargetUserSid、LogonType、IpAddress、WorkstationName。

### 5.3 Linux Auditd

先按相同 `audit(timestamp:serial)` 组装复合事件，再解析 SYSCALL、EXECVE、CWD、PATH、PROCTITLE、SOCKADDR。Linux Audit 复合事件可能由多条记录组成且顺序不保证，必须等待 EOE/PROCTITLE 或 timeout 闭合；官方 audit-userspace 说明了 `auid`、`ses`、`pid` 和成功结果的语义，见 [Linux Audit 项目](https://github.com/linux-audit/audit-userspace)。

至少保留：`arch/syscall/success/exit/pid/ppid/uid/euid/auid/ses/exe/comm/key/cwd/path/items/saddr/proctitle`。32/64 位 syscall 表需按 arch 解码。

### 5.4 Zeek

- conn：ts、uid、五元组、service、duration、orig/resp bytes/packets、conn_state、history；
- dns：http 等协议日志使用同一 uid 与 conn 拼接；
- dns：query、qtype、rcode、answers、TTLs、rtt；
- http：method、host、uri、user_agent、status_code、request/response body len、referrer；
- files：fuid、tx_hosts/rx_hosts、conn_uids、mime_type、filename、seen/total bytes、hash；
- tunnel/weird/notice/capture_loss：隧道、异常协议、告警和传感器质量。

Zeek 官方示例明确展示 conn 与 dns/http/files 可通过 uid 关联，见 [Zeek 日志说明](https://docs.zeek.org/en/current/reference/logs/)。

## 6. 登录和网络 Session 模型

```yaml
Session:
  session_id: string
  session_type: login|network
  start_time: datetime
  end_time: datetime|null
  state: active|closed|timed_out|orphan_start|orphan_end
  host_id: string|null
  user_id: string|null
  src_ip: string|null
  dst_ip: string|null
  protocol: string|null
  source_event_ids: [string]
  confidence: number
```

- Windows login session：`host_id + boot_id + logon_id`；4624 开始，4634/4647 结束；缺结束事件按策略标为 timed_out。
- Linux login session：优先 `host_id + boot_id + audit ses`，auid 表示最初登录身份；sshd 日志补充源 IP。
- Zeek network session：优先 `sensor_id + uid`；无 uid 时用规范化双向五元组、开始时间桶和 sensor 构造 provisional ID。

## 7. DetectionResult

```yaml
DetectionResult:
  schema_version: "1.0"
  detection_id: string
  run_id: string
  rule_id: string
  rule_version: string
  title: string
  detector_type: rule|threshold|statistical|correlation
  status: open|suppressed|confirmed|false_positive
  severity: informational|low|medium|high|critical
  confidence: 0.0..1.0
  event_ids: [string]
  entity_ids: [string]
  session_ids: [string]
  feature_values: object
  reason: string
  attack_mappings: [AttackMapping]
  evidence_ids: [string]
  created_at: datetime
```

`AttackMapping` 包含 `technique_id`、`subtechnique_id`、`tactic_ids`、`mapping_rule_id`、`attack_version` 和 `confidence`。映射是检测结论的一部分，不写回原始事件。

## 8. Evidence

```yaml
Evidence:
  schema_version: "1.0"
  evidence_id: string
  kind: raw_event|normalized_event|graph_fact|intel_fact|analytic
  source_ref: string
  event_ids: [string]
  entity_ids: [string]
  excerpt: object|string|null
  observed_at: datetime|null
  collected_at: datetime
  producer: string
  producer_version: string
  integrity_sha256: string|null
  reliability: direct|corroborated|derived|external_unverified
  supports: [string]
  contradicts: [string]
```

Evidence 是所有 Detection、AttackChain 和 AgentResult 的强制外键。LLM 自述不能成为 direct evidence。

## 9. GraphEntity 与 GraphRelation

```yaml
GraphEntity:
  schema_version: "1.0"
  entity_id: string
  entity_type: host|user|process|file|registry|ip|domain|session|alert|technique|c2|evidence
  labels: [string]
  display_name: string|null
  properties: object
  first_seen: datetime|null
  last_seen: datetime|null
  identity_quality: exact|derived|provisional
  evidence_ids: [string]

GraphRelation:
  schema_version: "1.0"
  relation_id: string
  relation_type: string
  source_entity_id: string
  target_entity_id: string
  start_time: datetime|null
  end_time: datetime|null
  properties: object
  confidence: number
  derived: boolean
  event_ids: [string]
  evidence_ids: [string]
```

GraphEntity/Relation 是 projector 与前端之间的中立契约，不暴露 Neo4j driver 对象。`relation_id` 应由 relation type、两端 canonical IDs、event/session identity 确定性生成；多个真实行为不能因为起终点相同被覆盖。

## 10. Alert API 模型

DetectionResult 是检测引擎的不可变结果；Alert 是面向处置的可变视图，两者不混用：

```yaml
Alert:
  alert_id: string
  detection_id: string
  case_id: string|null
  status: open|acknowledged|investigating|closed|suppressed
  assignee: string|null
  disposition: true_positive|false_positive|benign_positive|unknown
  analyst_notes: [Note]
  created_at: datetime
  updated_at: datetime
```

Detection 的 rule、features、events 和 mappings 不因 Alert 状态变化而被修改。Neo4j 的 `:Alert` 节点以 detection_id 投影事实，处置状态仍以结构化库为准。

## 11. AttackChain

```yaml
AttackChain:
  schema_version: "1.0"
  chain_id: string
  run_id: string
  title: string
  status: candidate|confirmed|dismissed
  start_time: datetime
  end_time: datetime
  entry_point: ChainStepRef|null
  steps: [ChainStep]
  entity_ids: [string]
  detection_ids: [string]
  technique_ids: [string]
  score: 0.0..1.0
  completeness: 0.0..1.0
  uncertainties: [string]
  evidence_ids: [string]
  algorithm_version: string
```

`ChainStep` 包含 step_id、stage、tactic_id、technique_id、event/detection/entity/session IDs、前驱关系、时间区间、score、evidence_ids 和 explanation。前驱关系枚举为 temporal、spawn、same_session、authentication、network_flow、file_lineage、identity_change、analyst_link。

## 12. AgentTask 和 AgentResult

```yaml
AgentTask:
  task_id: string
  case_id: string
  agent_role: coordinator|host|network|correlation|attribution|report
  objective: string
  input_refs: [string]
  allowed_tools: [string]
  constraints: {max_steps: int, deadline_ms: int, read_only: bool}
  parent_task_id: string|null
  state: queued|running|succeeded|failed|cancelled

AgentResult:
  result_id: string
  task_id: string
  status: succeeded|partial|failed
  findings:
    - claim: string
      confidence: number
      evidence_ids: [string]
      alternatives: [string]
  tool_calls: [ToolCallSummary]
  output_refs: [string]
  errors: [StructuredError]
  model_info: {provider: string, model: string, prompt_version: string}
```

## 13. Neo4j 节点 Schema

| Label | canonical key | 关键属性 | 说明 |
|---|---|---|---|
| Host | `host_id` | hostname、os、role、first/last_seen | Host 不以当前 IP 为主键 |
| User | `user_id` | sid/uid、name、domain、host_id | 域账号与本地账号区分 |
| Process | `process_id` | pid、guid、boot_id、start/end、image、cmdline | 表示一次进程实例 |
| File | `file_id` | host_id、normalized_path、hash、sensitivity | 路径实体；版本信息在关系/证据 |
| Registry | `registry_id` | host_id、hive、key_path、value_name | 规范化根键 |
| IP | `ip_id` | address、version、scope | 仅表示地址，不等于 Host |
| Domain | `domain_id` | punycode、display、registered_domain | 小写、去末尾点 |
| Session | `session_id` | type、start/end、state、confidence | 登录或网络会话 |
| Alert | `detection_id` | rule、severity、confidence、status | Detection 的图投影 |
| Technique | `technique_id` | name、version、revoked/deprecated | 来自固定 ATT&CK 快照 |
| C2 | `c2_id` | family、first/last_seen、confidence | 基础设施聚合，不复制 IP/Domain |
| Evidence | `evidence_id` | kind、source_ref、reliability | 仅物化链/告警所需证据 |

## 14. Neo4j 关系 Schema

| 关系 | 起点 → 终点 | 必备属性 |
|---|---|---|
| HAS_IP | Host → IP | valid_from、valid_to、event_id |
| SPAWNED | Process → Process | relation_id、event_id、timestamp、confidence |
| EXECUTED_BY | Process → User | relation_id、event_id、timestamp |
| LOGGED_IN | User → Session | event_ids、start/end |
| ON_HOST | Process/Session/File/Registry → Host | valid_from、valid_to |
| ACCESSED | Process → File | relation_id、event_id、timestamp、mode、outcome |
| CREATED/MODIFIED/DELETED | Process → File | relation_id、event_id、timestamp |
| MODIFIED | Process → Registry | relation_id、event_id、timestamp、operation |
| INITIATED | Process/Host → Session | event_ids、confidence |
| FROM/TO | Session → IP | event_ids、port |
| COMMUNICATED_WITH | Host/IP → Host/IP | derived_from_session_id、start/end、protocol |
| RESOLVED_TO | Domain → IP | event_id、timestamp、ttl |
| TRIGGERED | Entity/Session → Alert | detection_id |
| USED_TECHNIQUE | Alert → Technique | mapping_rule_id、attack_version、confidence |
| HOSTED_AT | C2 → IP | evidence_ids、valid_from/to、confidence |
| USES_DOMAIN | C2 → Domain | evidence_ids、valid_from/to、confidence |
| SUPPORTED_BY | Alert/C2 → Evidence | role |
| CORROBORATES | Evidence → Evidence | correlation_id、score |

行为边必须携带 `relation_id` 和至少一个 event/evidence 引用。对高频网络行为优先使用 Session 节点，不把同一 IP 对的所有通信压成一条累计边。

## 15. 实体统一与去重规则

### Host

建立独立 alias registry：Wazuh agent.id、hostname、FQDN、机器 GUID、MAC、IP 有效区间映射到 host_id。IP 只能作为有时间范围的别名，DHCP 环境中不可作为永久身份。

### Process

- Windows：`host_id + ProcessGuid`；无 Guid 时 `host_id + boot_id + pid + utc_time`。
- Linux：`host_id + boot_id + pid + start_time_ns`。
- 只有 pid/ppid 时创建 provisional process，后续通过时间范围合并；保留 `ALIAS_OF` 审计记录。

### File/Registry/User

- File：`host_id + normalized_path`，Windows 大小写和分隔符规范化；哈希描述内容版本而非路径身份。
- Registry：`host_id + canonical_hive + key_path + value_name`。
- Windows User：优先 domain SID；本地 SID 绑定 host。Linux User：`host_id + uid`，同时保留 auid/euid。

### IP/Domain/Session

- IP 使用标准库规范化 IPv4/IPv6；不要创建 `External_IP` 的重复 label。
- Domain 转 IDNA 小写并去尾点，registered_domain 单独存储。
- Session 用源原生 ID 优先，缺失时才由规范化字段派生。

## 16. 时间窗口关联

候选关联分数：

```text
score = 0.35 * tuple_match
      + 0.25 * time_overlap
      + 0.20 * host_ip_validity
      + 0.10 * process_identity_quality
      + 0.10 * source_reliability
```

分数只用于排序，不替代硬约束。五元组冲突、主机 IP 在该时段无效或时间区间不相交时拒绝关联。阈值由靶场标注数据校准并记录 rule version。

## 17. 建议约束与索引

```cypher
CREATE CONSTRAINT host_id IF NOT EXISTS
FOR (n:Host) REQUIRE n.host_id IS UNIQUE;
CREATE CONSTRAINT process_id IF NOT EXISTS
FOR (n:Process) REQUIRE n.process_id IS UNIQUE;
CREATE CONSTRAINT session_id IF NOT EXISTS
FOR (n:Session) REQUIRE n.session_id IS UNIQUE;
CREATE CONSTRAINT detection_id IF NOT EXISTS
FOR (n:Alert) REQUIRE n.detection_id IS UNIQUE;
CREATE CONSTRAINT evidence_id IF NOT EXISTS
FOR (n:Evidence) REQUIRE n.evidence_id IS UNIQUE;
```

其他实体同理建立唯一约束；对 `event_time/start_time/last_seen`、`Process.image`、`File.normalized_path`、`IP.address` 建索引。任何来自请求参数的 label 或 relationship type 必须使用 allowlist，不能字符串拼接任意 Cypher。

## 16. 接口契约发布方式

`contracts/` 同时输出：

- Pydantic 模型；
- `schemas/*.json`；
- FastAPI OpenAPI；
- 前端生成的 TypeScript types；
- `fixtures/valid` 和 `fixtures/invalid`；
- compatibility tests。

模块只依赖 contracts 包，不依赖另一个模块的内部 ORM、Cypher record 或 UI view model。
