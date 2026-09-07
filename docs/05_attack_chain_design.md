# ATT&CK 映射与攻击链分析设计

## 1. 目标

系统要输出的不是按时间排序的一串告警，而是一组有证据、有前驱关系、有不确定性说明的攻击步骤。ATT&CK 用于统一技术语义，不直接证明因果；攻击链由确定性关联规则和图路径约束构建，Agent 只负责补充调查与解释。

```text
Raw Event
  → Normalized Event
  → Detection
  → ATT&CK Technique
  → Tactic
  → Course Attack Stage
  → Attack Chain Candidate
  → Analyst/Agent Review
  → Confirmed Attack Chain
```

## 2. ATT&CK 知识基线

- 使用 MITRE 官方 Enterprise ATT&CK STIX 2.1 快照，提交包固定版本；2026-09 基线为 v19.2。
- Technique、Sub-technique、Tactic、Group、Software、Campaign 及关系进入只读本地索引。
- 过滤 revoked/deprecated 对象，但保留旧 ID 的别名和迁移信息。
- 每条映射记录 `attack_version`、`mapping_rule_id`、platform、命中字段和置信度。
- 不从名称猜 ID；UI 和报告始终以 Technique ID 为稳定键。

MITRE 官方同时提供 STIX 和 TAXII；课程演示使用本地快照，避免现场断网，来源见 [ATT&CK Data and Tools](https://attack.mitre.org/resources/attack-data-and-tools/)。

## 3. 课程攻击阶段

课程阶段是产品层概念，ATT&CK tactic 是知识层概念，两者不能混为一个枚举。

| Course stage | 主要 ATT&CK tactic | 说明 |
|---|---|---|
| initial_access | Initial Access | 边界、邮件、Web 或外部远程服务入口 |
| execution | Execution | 脚本、解释器、用户执行 |
| persistence | Persistence | 计划任务、服务、注册表、账号 |
| privilege_escalation | Privilege Escalation | 身份/令牌/权限提升 |
| credential_access | Credential Access | 凭据文件、LSASS、浏览器凭据等 |
| discovery | Discovery | 主机、账号、网络、服务发现 |
| lateral_movement | Lateral Movement | 从一台资产到另一台资产的认证与执行 |
| collection | Collection | 敏感数据访问、归档和暂存 |
| command_and_control | Command and Control | beacon、远控和隧道 |
| exfiltration | Exfiltration | 数据从受控区到攻击基础设施 |

Defense Evasion 等 tactic 作为跨阶段标签附着于步骤，不能强行插入唯一线性顺序。一个 Detection 可映射多个 Technique，一个 Technique 可出现在不同 tactic 上。

## 4. Detection 到 Technique 映射

### 4.1 映射规则

```yaml
mapping_rule:
  id: map.sysmon.remote_thread
  version: 1.0.0
  applies_to: det.sysmon.remote_thread
  technique_id: T1055
  subtechnique_id: null
  tactic_ids: [TA0004, TA0005]
  platforms: [Windows]
  confidence: 0.85
  evidence_fields:
    - source_process_guid
    - target_process_guid
    - start_address
```

映射只接受 DetectionResult，不直接接受任意原始字符串。规则检测先证明行为模式，映射规则再提供标准语义。

### 4.2 P0 检测族

| 检测族 | 主要证据 | 示例 Technique 方向 |
|---|---|---|
| suspicious interpreter | Process start + parent + cmdline | T1059 及子技术 |
| scheduled persistence | task/cron/registry/service event | T1053、T1547、T1543 |
| process injection | Sysmon 8/10/25、映像或内存事件 | T1055 |
| credential access | LSASS access、凭据文件读取、工具行为 | T1003 等 |
| remote services | 登录会话 + SMB/RDP/WinRM/SSH + 远程进程 | T1021 子技术 |
| discovery | system/network/account discovery process | Discovery 相关技术 |
| archive staging | 敏感文件集合 + 压缩/暂存 | T1560、T1074 |
| C2 channel | 周期 beacon、已知 C2、应用层通道 | T1071 等 |
| covert channel | DNS/HTTP/ICMP 特征 | T1071/T1095 等，按证据谨慎映射 |
| exfiltration | 敏感数据 lineage + outbound session | Exfiltration 相关技术 |

Technique ID 以实现时固定 ATT&CK 快照校验为准；本表是设计方向，不替代映射注册表。

## 5. 多技术关联规则

关联由硬约束和软评分共同完成。

### 5.1 硬约束

- 时间区间必须相交或满足有向先后窗口；
- 至少共享一个 canonical host/process/user/session/file，或存在明确网络/认证边；
- 步骤方向不能违反进程派生、登录、网络或数据 lineage；
- 被不同 case 隔离的事件默认不合并；
- 同一时间段的两个无共享实体攻击不能仅因 Technique 相同而合并。

### 5.2 软特征

- 进程祖先/后代距离；
- 相同登录 session；
- Zeek uid 与主机 network connect 五元组匹配；
- 同一脚本/文件哈希/工具指纹；
- 目标资产角色和网络区；
- 时间接近度和源证据可靠性；
- 与已有链入口、横移方向和数据路径的一致性。

### 5.3 关联结果

每条连接记录：

```yaml
step_link:
  from_step_id: string
  to_step_id: string
  relation: spawn|same_session|network_flow|authentication|file_lineage|identity_change|temporal
  score: 0.0..1.0
  hard_constraints_passed: [string]
  feature_contributions: object
  evidence_ids: [string]
```

## 6. 攻击链构建算法

1. **种子选择**：以 high/critical Detection、明确边界入口、C2 或敏感数据外传为种子。
2. **候选扩展**：在限定时间和跳数内沿允许关系向前/向后扩展。
3. **时间过滤**：边按有效时间验证，保留时间不确定性区间。
4. **路径评分**：累加检测置信度、关系质量、证据独立性、阶段连贯性；对缺失关键证据、过宽时间窗口和背景服务施加惩罚。
5. **去重与分群**：按入口、核心实体和步骤集合 Jaccard 相似度合并近似链。
6. **阶段标注**：Technique/Tactic 映射为课程阶段；跨阶段标签单独保存。
7. **入口/横移/提权/外传专项求证**：运行下述验证器。
8. **输出候选**：保留 Top-N 路径、反证、缺口和 evidence IDs；不自动标记 confirmed。

建议链分数：

```text
chain_score =
  0.30 * mean_detection_confidence
  + 0.25 * mean_link_score
  + 0.20 * independent_source_coverage
  + 0.15 * stage_coherence
  + 0.10 * entry_to_impact_completeness
  - penalties
```

评分仅用于排序。confirmed 必须由 Ground Truth 匹配或人工确认。

## 7. 四类关键路径恢复

### 7.1 初始入侵点

候选根节点满足至少一项：

- 边界入站会话后紧邻 Web/Email/远程服务异常；
- 外部来源登录会话后产生异常进程；
- 新文件/脚本经邮件或 Web 下载后被执行；
- 受控漏洞服务产生父进程异常派生。

输出 `entry_point.type`、外部源、受害资产、入口服务、第一条执行证据和置信度。如果边界日志缺失，只输出“最早可观测活动”，不能称为真实入口。

### 7.2 横向移动

要求同时存在：

1. 源主机上的远程客户端进程或凭据使用；
2. 源到目标的 SMB/RDP/WinRM/SSH 等会话；
3. 目标主机的新登录 session；
4. 可选但高价值：目标上的远程服务子进程。

四类证据越完整，置信度越高。正常运维账号、跳板机和变更窗口进入 allowlist，并在报告中显示抑制原因。

### 7.3 权限提升

将同一 host/session/process lineage 中的身份状态变化建成有向路径：

```text
low_priv_user
→ process/action
→ privileged token/session
→ privileged child process
```

Windows 结合 4672、完整性级别、Token/User、进程父子；Linux 结合 auid/uid/euid、sudo/su/PAM 和 execve。只有“运行了 sudo”不足以证明成功提权，必须检查 outcome 和后续身份。

### 7.4 数据访问到外传

```text
Sensitive File
← READ — Process
→ CREATE/MODIFY — Staging Archive
← READ — Transfer Process
→ INITIATED — Network Session
→ TO — External IP/C2
```

文件 lineage 需要 path/hash/size/time，网络需要 bytes 和方向；若只能观察到大流量而没有数据 lineage，标记为 `possible_exfiltration`，不能声称具体文件已外传。

## 8. 隐蔽信道检测

### DNS

特征：查询名长度、标签长度、字符熵、唯一子域比例、NXDOMAIN 比例、请求频率、周期性、上下行尺寸。规则以滑动窗口产生 feature_values，正常软件更新和 CDN 域名作为对照。

### HTTP

特征：固定周期 beacon、异常小请求/固定响应、URI/参数熵、User-Agent 稳定异常、Host/SNI 不一致、非标准方法或内容类型、出站字节模式。TLS 加密场景仅使用元数据并降低结论强度。

### ICMP

特征：echo payload 长度/熵、序列与间隔、异常双向字节、持续会话。若 Zeek 日志不足，使用小型 PCAP 派生特征 adapter。

三个 detector 独立输出 DetectionResult；“熵高”只是特征，不是恶意结论。

## 9. C2 与 APT/TTP 相似性

### C2 基础设施

C2 对象聚合 IP、Domain、证书、ASN/组织、注册与历史解析等事实。每个外部事实必须保存 provider、query_time、valid_time、source_url/reference 和可靠性。现场断网时使用预先冻结的情报快照。

### APT 候选匹配

输入为已确认/高置信 Technique 集合、Software/工具指纹和基础设施事实；候选来自 ATT&CK Group—Technique/Software 关系。输出 Top-k：

- matched techniques 与权重；
- matched software/infrastructure；
- missing expected techniques；
- common-technique penalty；
- evidence_ids；
- 数据版本与“非身份定论”提示。

禁止用国别、单个通用工具或单一 IP 直接定性攻击者身份。

## 10. API

- `POST /api/v1/cases/{case_id}/correlate`：触发确定性关联；
- `GET /api/v1/cases/{case_id}/chains`：分页列出候选链；
- `GET /api/v1/chains/{chain_id}`：AttackChain；
- `GET /api/v1/chains/{chain_id}/graph`：裁剪后的节点/边；
- `GET /api/v1/chains/{chain_id}/evidence`：证据分页；
- `POST /api/v1/chains/{chain_id}/review`：确认/驳回/备注；
- `GET /api/v1/attack/techniques/{id}`：固定版本知识事实；
- `GET /api/v1/chains/{chain_id}/attribution`：候选归因。

## 11. 测试指标

- Detection：precision、recall、false positives/hour；
- ATT&CK mapping：Technique precision/recall、版本有效率；
- link：关联边 precision/recall；
- chain：步骤集合 F1、顺序一致率、入口命中率、横移跳点准确率；
- data lineage：敏感文件到会话的完整边覆盖率；
- attribution：Top-1/Top-3、Brier score/置信度校准，数据不足时允许“不归因”；
- performance：端到端 p50/p95 延迟、Neo4j 路径查询 p95。

每个指标必须给出样本量、Ground Truth 来源和阈值版本。
