# 开发路线与架构评审结论

## 1. 总体结论

项目已经越过工程骨架阶段，当前处于验收集成和材料冻结阶段。契约、主管道、检测、ATT&CK、AttackChain、Multi-Agent、前端和 DARPA 公开数据集均已接通；后续重点不应是重构，而是云靶场日志接入、最终报告/PPT、演示脚本和提交清单。

## 2. 依赖驱动的阶段

| Phase | 目标 | 主要产物 | 退出条件 | 依赖 |
|---|---|---|---|---|
| 0 契约与骨架 | 固定模型、接口、fixtures 和运行骨架 | contracts、OpenAPI、目录、Compose、CI、sample bundle | 七个模型校验通过；前后端从同一 OpenAPI；空系统健康检查通过 | 本轮设计审核 |
| 1 最小端到端 | 用小样例打通可见链 | Sample Raw→Event→SQLite/Neo4j→Detection→ATT&CK→API→UI | 一条 4-6 步链每步可回查 raw evidence；重放幂等 | Phase 0 |
| 2 真实适配器 | 接入 Wazuh/Sysmon/Auditd/Zeek | adapters、collector、time quality、sessionizers | 四源各有 golden/真实样例；Windows/Linux/Zeek 同一 schema | Phase 1 |
| 3 检测与攻击链 | 完成 P0 检测、关联和专项路径 | rules、covert channel、entry/lateral/privilege/data lineage | Ground Truth 场景链指标达标；无关并发事件不误合并 | Phase 2 |
| 4 Multi-Agent | 让 LLM 调查已有事实 | Harness、6 roles、tools、fallback report | 无不存在的 evidence/Technique；断网/模型失败可降级 | Phase 3 |
| 5 8+ 节点靶场 | 由云平台同学完成规定角色和真实链 | 9 节点、manifest、replay bundle、录像素材 | 云端 bundle 可被 TraceGuard replay，节点/采集/链/回滚清单全部通过 | 外部并行 |
| 6 数据集实验 | 验证 Dataset Adapter 可迁移 | DARPA slice、manifest、evaluation report | 已完成：20,776 条事件通过同一主管道，给出样本量和指标 | 已完成 |
| 7 交付与演示 | 稳定、文档、PPT、录像 | 报告、安装、测试、PPT、demo snapshot | 全新环境按文档启动；15 分钟脚本演练 3 次成功 | 当前重点 |

## 3. 每阶段任务

### Phase 0

1. 创建 Pydantic contracts 和 JSON Schema；
2. 建立 valid/invalid fixtures；
3. 定义 SQLite migration 与 repository port；
4. 创建 Neo4j constraints/indexes；
5. 创建 FastAPI health/version endpoints；
6. 生成 TypeScript API client；
7. 建立 `live/replay/snapshot` 运行模式；
8. 配置单元、契约和前端构建测试。

不要在 Phase 0 写复杂 detector、Agent 或完整页面。

### Phase 1

选择 6-10 条人工核对的 Sysmon/Zeek 样例：

```text
RawEventEnvelope
→ UnifiedSecurityEvent
→ Process/IP/Session + SPAWNED/INITIATED
→ one DetectionResult
→ one Technique
→ one AttackChain
→ GET /chains/{id}
→ 页面链图和 evidence drawer
```

这是第一条 Demo，也是所有后续集成的回归测试。

### Phase 2

按风险顺序：

1. Zeek conn + uid session；
2. Sysmon ProcessCreate/NetworkConnect；
3. 主机网络与 Zeek 五元组关联；
4. Windows 登录 Session；
5. Auditd 复合事件组装；
6. Linux 登录/进程/文件；
7. 注册表和内存事件；
8. capture/time/source health。

每增加一个来源先过 adapter fixture，再接 live collector。

### Phase 3

先做最能支撑完整链的检测：入口、可疑执行、持久化、凭据访问、横移、权限变化、敏感数据暂存、C2、外传。DNS/HTTP/ICMP 各保持一个可解释规则族。完成后用 Ground Truth runner 调阈值，不凭肉眼截图判断准确。

### Phase 4

先实现 Coordinator + Host + Network + Correlation + Report；Attribution 最后开启。工具先用 fake LLM 做权限和 schema 测试，再接真实 API。Prompt 只引用数据 ID；Agent 页面展示结果和证据，不展示隐式推理。

### Phase 5

并行准备 VM/容器镜像、快照、NTP、传感器和网络镜像。先逐节点验证采集，再运行完整场景。至少保存一份已验证 replay bundle 作为现场保险。

### Phase 6

先 `inspect` 数据集，再选择小切片；输出 mapping coverage 和质量报告后才运行检测。若公开标签不足以评估 Technique，就如实评估 event/attack/window，不制造 ATT&CK 真值。

### Phase 7

冻结版本，清理所有静默 Mock/默认密码/危险重置接口，重新部署，连续演练。报告中的每个“实现了”都要指向测试、截图或代码；未完成项进入限制和展望。

## 4. 以 2026-09-12 验收为约束的压缩安排

当前日期为 2026-09-09，主体系统和 DARPA 数据集已接通。若验收日期不变，建议逆排：

| 日期 | 必须完成 |
|---|---|
| 09-09 | 冻结主架构和 Dataset 模块；同步文档；等待云靶场日志 bundle |
| 09-10 | 接入云靶场导出日志；核对 run_id 隔离、Evidence、AttackChain 和 Agent quick/full |
| 09-11 | 最终 PPT/报告/录像；演示脚本连续演练；清理提交清单和大文件策略 |
| 09-12 | 只做现场环境验证和演示，不再改 schema/核心算法 |

如果团队实际有更长开发窗口，仍按 Phase 顺序，不按日期强行并行核心依赖。

## 5. MVP 定义

最小可运行版本不是“有一个 Dashboard”，而是：

- Wazuh/Sysmon 与 Zeek 样例或实时小流进入统一模型；
- Process、Host、IP、Session 和 Evidence 正确入库/入图；
- 至少一条确定性 Detection 映射到 ATT&CK；
- 一条包含入口/执行/C2 或横移的 AttackChain；
- FastAPI 返回同一契约；
- React 显示链、步骤和原始证据；
- replay 两次结果幂等；
- UI 明确运行模式。

若只剩一天，先完成这个 MVP，再补官方 P0 的广度。

## 6. 最终高分版本

高分版本应做到：

1. Windows/Linux/网络三域都有 direct evidence；
2. 登录、进程、文件、注册表、内存、网络会话链能相互下钻；
3. 入口→横移→提权→敏感数据→外传路径与 Ground Truth 对齐；
4. DNS/HTTP/ICMP 检测有正常对照和量化指标；
5. ATT&CK mapping 有固定版本和规则依据；
6. 9 节点靶场可重复、可回滚，现场使用真实 replay；
7. 公开数据集复用同一主管道；
8. Agent 每条 finding 有 evidence，失败时模板降级；
9. 归因输出候选、反证和“不足以归因”；
10. 文档、PPT、代码和测试对同一能力口径一致。

## 7. 第一条端到端 Demo

建议使用“PowerShell/脚本进程发起到实验 C2 的连接”作为第一条：

1. 一条 Sysmon ProcessCreate；
2. 一条 Sysmon NetworkConnect；
3. 一条同五元组 Zeek conn；
4. normalizer 生成三条 UnifiedSecurityEvent；
5. resolver 用 ProcessGuid 建 Process，sessionizer 用 Zeek uid 建 Session；
6. graph 形成 Parent→Process→Session→IP；
7. rule 生成可疑解释器/C2 Detection；
8. ATT&CK mapping 生成 Technique；
9. chain API 返回 2-3 个步骤；
10. UI 点每一步查看 raw evidence。

这个 Demo 同时检验模型、实体、时间、端网融合、图、Detection、ATT&CK、API 和前端，是投入产出最高的路径。

## 8. 技术风险 TOP 10

| 排名 | 风险 | 影响 | 最早缓解 |
|---|---|---|---|
| 1 | 统一模型迟迟不冻结 | 所有模块返工 | Phase 0 契约测试，任何新字段先评审 |
| 2 | 8 节点先搭但采集不通 | 时间消耗大、无系统闭环 | 先 2 源 sample，后逐节点采集检查 |
| 3 | Windows 事件噪声/缺事件 | 内存、网络、登录证据断裂 | 固定 Sysmon config，按场景过滤并保存健康指标 |
| 4 | Auditd 复合记录错误拼接 | 文件/进程/用户关系错误 | 以 timestamp+serial 组装，EOE/timeout fixture |
| 5 | 主机网络与 Zeek 误关联 | 攻击链看似完整但不真实 | 五元组+时间区间+Host-IP 有效期+置信度 |
| 6 | Neo4j 实体/关系错误 MERGE | PID/IP 重用导致串链 | ProcessGuid/boot_id；Session 节点化；幂等测试 |
| 7 | UI 静默 Mock 掩盖后端失败 | 现场展示虚假结果 | 显式 mode，Mock 仅测试环境 |
| 8 | Agent 幻觉或无限调用 | 错误归因、成本/延迟失控 | evidence validator、只读工具、step budget、fallback |
| 9 | 公开数据集过大/字段不匹配 | Phase 6 拖垮进度 | 先 inspect 和小切片，30 分钟可行性门 |
| 10 | 现场 VM/网络/外部 API 不稳定 | 演示失败 | snapshot/replay、固定情报、三次离线演练 |

## 9. 最容易拖垮进度的功能

- 全量 syscall 长期采集和全量 PCAP；
- 试图自己实现 EDR 级内存取证；
- 实时 WHOIS/多情报平台聚合；
- 通用自然语言 Cypher Agent；
- Kafka/Flink/Elasticsearch 全家桶；
- 3D 全网图和无限节点力导向；
- 在公开大数据集上训练复杂模型；
- 同时开发十几个页面；
- 现场实时跑完整攻击链；
- 把“归因到某 APT”当必须结果。

这些能力只有在 P0 闭环稳定后才考虑。

## 10. 时间不足时的降级顺序

允许降级但要诚实标注：

1. PostgreSQL 降为 SQLite；
2. 多进程队列降为单 worker + disk spool；
3. 在线情报降为带来源的本地快照；
4. ML 异常检测降为规则/统计特征；
5. 实时完整攻击降为真实采集的 replay bundle；
6. 复杂交互图降为≤100 节点的链图；
7. 6 Agent 降为 Coordinator、Host、Network、Correlation、Report，Attribution 用确定性排名；
8. OpTC 降为 ToN_IoT/LANL 小切片；
9. 高级内存取证降为 Sysmon 8/10/25 的行为证据；
10. 多种入口场景降为一条完整链 + 三类隐蔽信道独立小场景。

不能降级：

- 8 个规定角色节点的证明；
- 在线/离线共用统一管道；
- Windows/Linux/网络三域；
- Evidence 可回查；
- 多智能体协调的最小真实实现；
- ATT&CK 与完整链的实际输出。

## 11. 架构评审结论

### 推荐总体架构

FastAPI 模块化单体 + worker、React/TypeScript、Neo4j、SQLite、append-only raw archive、Wazuh/Sysmon/Auditd/Zeek、固定 ATT&CK STIX、证据约束 Agent Harness、Docker Compose 中心部署和 9 节点隔离靶场。

### P0 P1 P2

- P0：官方所有明确能力和两类验证，按 `docs/01_requirement_analysis.md` 矩阵验收。
- P1：契约测试、证据性、数据质量、显式降级、离线演示、量化指标。
- P2：消息中间件、复杂 ML、在线多情报、大规模图和高级协同。

### 去年项目可借鉴

端网采集的分层思路、Neo4j 表达进程/网络关系、FastAPI/React 的快速交付、攻击图视觉编码和基本 ATT&CK 展示。

### 去年项目不能直接沿用

松散 dict、空事件模型、会话缺失、IP 边累计、硬编码网段/归因、静默 Mock、5 节点测试、无数据集和无多 Agent。尤其不能把去年报告中未被源码/测试证明的能力当作已实现资产。

### 最终决策

架构可进入 Phase 0，但前提是先审核并冻结 `UnifiedSecurityEvent`、`Evidence`、进程/会话身份规则和 P0 降级边界。审核通过前不应开始大规模业务代码或靶场攻击脚本开发。
