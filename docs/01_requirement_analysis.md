# 2026 课程设计第 3 题需求分析

## 1. 结论与范围

本项目必须实现一条可验证的闭环：Windows/Linux 主机日志、主机行为与边界/内网流量进入同一事件管道，经时间对齐、范式解析、实体提取、检测和图关联后，形成可追溯到原始证据的 ATT&CK 攻击链；大模型多智能体只在确定性事实之上完成调查编排、跨源解释、归因假设与报告生成。系统还必须同时接受实时靶场数据和互联网公开攻击数据集，并在不少于 8 个规定角色节点的隔离靶场中验证。

官方依据为项目根目录中的 `2026网络空间安全课程设计-new(1).pdf` 第 3 题及其测试要求；考核还要求 PPT、现场演示和完整交付材料。去年项目仅作参考，不构成需求依据。

## 2. 优先级定义

- **P0 必须完成**：官方第 3 题明确提出的系统能力、两类测试，以及可证明这些能力的证据闭环。
- **P1 核心质量**：官方虽未规定实现细节，但直接决定系统是否可信、稳定、可演示，例如数据契约、证据可追溯、确定性检测、失败降级和自动化测试。
- **P2 增强能力**：不影响基本验收，可在闭环稳定后增加，例如大规模流处理、复杂机器学习、在线情报自动拉取和高级交互。

注意：官方“监控所有系统调用”在真实环境中会产生显著性能与存储压力。设计上保留全量采集能力，默认演示策略采用按架构、主机角色和攻击面选取的 syscall 规则集，并在报告中明确覆盖范围与丢失率，不能把“选择性策略”描述成“无条件全量”。

## 3. 需求追踪矩阵

| ID | 官方要求 | 系统能力 | 后端实现 | 数据来源 | 前端展示 | 测试方式 | 优先级 |
|---|---|---|---|---|---|---|---|
| R3-01 | 大模型多智能体协调 | 轻量调查 Harness，任务树、专职 Agent、共享证据引用、失败恢复 | `agents/`、只读工具网关、`AgentTask/AgentResult` | 标准事件、告警、图谱、ATT&CK 快照 | Agent 分析中心：任务状态、结论、证据、失败原因 | 固定案例重复运行，核对结论一致性、证据引用率和失败回退 | P0 |
| R3-02 | 多源数据采集与融合 | 主机日志、主机行为、网络流量统一接入 | `collectors/`、`ingestion/`、`normalizer/` | Wazuh、Sysmon、Auditd、Zeek | 数据源健康度、延迟、事件量 | 同一攻击动作产生至少两类来源事件并被关联 | P0 |
| R3-03 | Windows/Linux 主机日志 | 跨平台认证、系统和应用日志适配 | Wazuh/Sysmon/Auditd adapters | Windows Event Channel、Linux audit/journal/auth | 主机时间线、原始证据抽屉 | Windows 与 Linux 各回放一组正常/攻击事件 | P0 |
| R3-04 | 日志时间序列对齐 | UTC 规范化、时钟偏移与不确定性建模 | `TimeQuality`、offset 校正、事件时间/接收时间分离 | NTP/W32Time/chrony 状态和各源时间戳 | 时间质量、偏移、关联窗口 | 人工注入 ±2 s 偏移，验证排序和关联置信度 | P0 |
| R3-05 | 日志范式解析 | 版本化统一安全事件模型 | Pydantic/JSON Schema adapter registry | 全部在线与离线源 | 统一事件检索 | Golden fixtures 字段映射与 schema 校验 | P0 |
| R3-06 | 用户、进程、文件、注册表实体提取 | 类型化实体引用、规范化与别名合并 | entity resolver、canonical ID | Sysmon、Security、Auditd、FIM | 实体详情和上下游关系 | 每类实体正反例、重复源合并测试 | P0 |
| R3-07 | 登录会话重建 | 登录/注销配对、源 IP、账号与进程归属 | sessionizer、超时闭合和异常状态 | Windows 4624/4634/4647/4672；Audit `ses/auid`、sshd | 用户会话时间线 | 正常、缺失注销、并发登录、远程登录四类场景 | P0 |
| R3-08 | Windows/Linux 主机行为监控 | 进程、文件、网络、注册表、内存行为采集 | 主机行为适配器和策略包 | Sysmon/Wazuh/Auditd | 主机行为分析 | 两种 OS 各执行受控行为并核对事件 | P0 |
| R3-09 | 系统调用拦截 | 捕获关键文件、进程、网络 syscall，保留架构与结果 | Auditd 复合事件组装器；可选 eBPF 扩展 | `SYSCALL/EXECVE/CWD/PATH/PROCTITLE` | syscall 事件详情与覆盖声明 | execve/open/connect/accept/unlink 等代表性调用 | P0 |
| R3-10 | 进程父子链 | 进程实例唯一化和跨日志补全 | Process resolver + `SPAWNED` | Sysmon ProcessGuid；Linux boot_id/pid/start_time | 可折叠进程树 | 5 层以上进程链、PID 重用、缺父事件测试 | P0 |
| R3-11 | 文件操作和敏感访问 | 创建、修改、删除、读取及敏感度策略 | file action normalizer、sensitive asset rules | Sysmon、Auditd、Wazuh FIM | 文件操作时间线 | canary 文件读写删与哈希变化 | P0 |
| R3-12 | 内存异常行为 | 注入、远程线程、进程访问、反射/映像异常证据 | 规则检测，能力标签区分“直接观测/推断” | Sysmon 7/8/10/25、EDR/Wazuh 规则 | 内存行为告警及原始字段 | 受控注入模拟或 Atomic 测试，验证多事件证据 | P0 |
| R3-13 | 边界和内网流量捕获解析 | 双观测点或可证明的镜像覆盖 | Zeek JSON adapter、capture health | SPAN/TAP、PCAP、Zeek | 传感器覆盖和会话检索 | 边界/内网各产生已知会话，检查 capture loss | P0 |
| R3-14 | 异常协议行为建模 | 基线特征 + 规则阈值 + 可解释异常分数 | protocol feature extractor、detectors | Zeek conn/dns/http/icmp/tunnel/weird | 协议异常趋势和证据 | 正常流量基线与受控异常对比 | P0 |
| R3-15 | 网络会话重建 | 以 Zeek uid 或规范五元组+时间窗构建会话 | network sessionizer | Zeek conn 及协议日志 | 会话详情、上下行字节、关联协议 | conn 与 DNS/HTTP/files 通过 uid 正确拼接 | P0 |
| R3-16 | DNS/HTTP/ICMP 隐蔽信道 | 三类可解释检测器 | 长度/熵/频率/周期/载荷比例规则 | Zeek + PCAP 派生特征 | 隐蔽信道告警及特征贡献 | 三种教学隧道与正常对照，报告 P/R | P0 |
| R3-17 | ATT&CK 攻击链识别与阶段映射 | 规则到 Technique/Tactic 的版本化映射 | ATT&CK STIX 快照、mapping registry | DetectionResult | ATT&CK 矩阵与证据下钻 | 每条映射核对 technique_id、版本和证据 | P0 |
| R3-18 | 同一攻击者多个技术的逻辑关系 | 时间、实体、会话和因果约束的多技术关联 | correlation engine | Detection + graph | 技术序列和关联理由 | 并发无关攻击不应被错误合并 | P0 |
| R3-19 | 攻击点关系图和链路图 | 实体图、行为边和证据边 | Neo4j schema + graph projector | UnifiedSecurityEvent | 可交互攻击图 | 节点去重、边时序和 evidence_id 可回查 | P0 |
| R3-20 | 初始入侵点 | 入口候选、边界证据和置信度 | ingress detector + path root ranking | 防火墙/Zeek/Web/Email/认证 | 链首、入口类型、证据 | 已知入口场景命中，未知时明确“不确定” | P0 |
| R3-21 | 横向移动路径 | 认证与连接联合追踪 | lateral correlation rules | 登录、SMB/RDP/WinRM/SSH、进程 | 主机跳转路径 | 两跳以上受控横移，排除正常管理行为 | P0 |
| R3-22 | 权限提升路径 | 身份/令牌/权限变化与进程链关联 | privilege detectors | Windows 4672/4688/Sysmon；Audit uid/euid/sudo | 权限前后状态 | 普通到管理员/root 的受控场景 | P0 |
| R3-23 | 数据从存储到外传完整路径 | 敏感数据访问、暂存、压缩、传输关联 | collection/staging/exfil rules | 文件事件、进程、网络会话 | 数据路径和关键文件 | canary 数据读取→归档→外传闭环 | P0 |
| R3-24 | 工具、脚本、配置指纹 | 哈希、签名、命令行、UA、配置特征 | fingerprint extractor | 主机与流量证据 | 指纹卡片与来源 | 同工具变名、不同工具同名对照 | P0 |
| R3-25 | C2 基础设施关联 | IP/域名/证书/ASN/历史解析等证据聚合 | intel adapter + cache + provenance | 本地情报快照；可选外部 API | C2 图和证据新鲜度 | 无 API 时可复现实验；有 API 时验证缓存/限流 | P0 |
| R3-26 | TTP/APT 相似性匹配 | 候选排名、相似度、反证与不确定性 | ATT&CK Group/Software 关系 + 可解释加权 | ATT&CK STIX、公开情报 | 候选而非“身份定论” | 已知案例 Top-k、校准度和证据审计 | P0 |
| R3-27 | 对比开源项目验证创新性 | 能力矩阵和自研边界 | architecture benchmark notes | Wazuh/Zeek/Neo4j/开源溯源工具资料 | 报告中心 | 按采集、融合、链恢复、Agent、证据性逐项对比 | P0 |
| R3-28 | 互联网企业内网攻击数据集 | 可插拔 Dataset Adapter 共用主管道 | `datasets/` | LANL、ToN_IoT、OpTC 等候选 | 数据集实验页 | 至少一个数据集端到端导入、指标报告 | P0 |
| R3-29 | 不少于 8 节点且包含规定角色 | 8 个规定角色 + 建议独立分析节点 | testbed manifests | 隔离虚拟网络 | 拓扑与传感器覆盖 | 节点清单、连通矩阵、快照和日志证据 | P0 |
| R3-30 | 使用扫描、利用、内网渗透、后门/C2 软件构建完整入侵链 | 受控攻击计划、工具清单、回滚与安全边界 | test harness、scenario manifest | 封闭靶场 | 演示时间线 | 全链复现、检查点通过、无公网误连 | P0 |
| R3-31 | 多源溯源结果验证 | Ground truth 与系统结果自动比对 | evaluation runner | 靶场动作清单、统一事件、链结果 | 实验指标与漏检项 | 事件、实体、关系、技术、阶段和链级指标 | P0 |
| Q-01 | 稳定现场演示 | 离线可演示、数据快照、健康检查 | demo mode、seed data、read-only fallback | 最近一次真实实验快照 | 一键 Demo 流程 | 断网、情报 API 不可用、重启恢复演练 | P1 |
| Q-02 | 事实可追溯 | 所有检测、链和 Agent 结论引用 Evidence | Evidence store + provenance | 原始事件不可变存档 | 证据抽屉 | 随机抽查结论能回到 raw_ref | P1 |
| Q-03 | 模块可并行开发 | 版本化模型、契约测试、样例 fixtures | `contracts/` | 统一 JSON Schema | 前端由 OpenAPI 生成类型 | consumer-driven contract tests | P1 |
| E-01 | 更高吞吐与横向扩展 | 可替换队列和 PostgreSQL | Redis Streams/Kafka 可选适配 | 高负载流 | 运维指标 | 压测达到课程实际规模后再启用 | P2 |
| E-02 | 机器学习异常检测 | 离线训练、在线评分、漂移监控 | `ml_detectors/` 可选 | 数据集和靶场特征 | 模型解释 | 与规则基线对比且不降低可解释性 | P2 |

## 4. 非功能与验收约束

- **证据完整性**：原始记录只追加，保存来源、采集时间、解析器版本和内容哈希；任何推断不得覆盖原始事实。
- **时间语义**：必须区分 `event_time`、`observed_time`、`ingested_time`，并记录 `clock_offset_ms` 与 `uncertainty_ms`。
- **数据质量**：未知字段进入扩展区；解析失败进入死信队列，不能静默丢弃。
- **可重复性**：ATT&CK、检测规则、Agent prompt、数据集 adapter 都要有版本；实验输出记录这些版本。
- **安全性**：靶场默认无公网出口；C2 和利用工具只允许在实验 VLAN；所有凭据为一次性测试凭据。
- **演示性**：15 分钟现场应以一条完整链为主线，不同时展示十个无关 Dashboard。

## 5. P0 P1 P2 功能包

**P0 验收闭环**：四类适配器（Wazuh/Sysmon/Auditd/Zeek）、统一事件、登录/进程/文件/注册表/网络会话、三类隐蔽信道规则、确定性检测、ATT&CK 映射、图谱、攻击链、轻量多 Agent、APT 候选、一个公开数据集、8+ 节点靶场和完整证据报告。

**P1 高质量闭环**：数据质量面板、实体别名合并、关联置信度、Agent 失败恢复、OpenAPI/JSON Schema 契约测试、离线 Demo、性能与准确性指标、开源项目对比。

**P2 增强包**：Kafka/Redis、复杂 ML、在线多源情报、图嵌入、全量 PCAP 长期留存、多人 RBAC 和高级协同调查。

## 6. 需求冻结规则

后续文档与实现均使用本文件的需求 ID。任何功能若没有对应 ID，不进入 P0；任何 P0 若没有后端产物、前端证据和测试方式，不得标记完成。需求变化先更新矩阵，再更新数据契约和测试，不允许直接在某个模块中临时增加私有字段。
