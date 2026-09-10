# TraceGuard 产品设计规划

> 版本：答辩前产品收口版  
> 定位：基于主机日志、主机行为、网络流量的多源恶意攻击行为溯源分析平台  
> 核心原则：**一个证据包 = 一个分析任务 = 一个 run_id = 全平台同一攻击案件的不同视图**

---

## 1. 产品定位

TraceGuard 面向典型企业内网入侵场景，统一接入 Windows/Linux 主机日志、主机行为数据和网络流量，对多源安全数据进行解析、时间对齐、资产归一、事件标准化、检测、ATT&CK 映射和跨源关联，最终形成可回溯到原始证据的攻击链。

在结构化分析结果之上，平台再调用多 Agent 对攻击链进行证据核验、关联分析、威胁归因和报告生成。

TraceGuard 不是“多个独立安全页面的集合”，而应当是一个**围绕一次分析任务展开的完整攻击案件工作区**。

---

## 2. 最终产品目标

平台最终需要回答五个核心问题：

1. **发生了什么？**  
   哪些主机、用户、进程、文件、网络连接出现了异常。

2. **攻击者用了什么技术？**  
   将 Detection 映射到 MITRE ATT&CK Technique。

3. **这些行为之间有什么关系？**  
   将跨主机、跨日志、跨网络流量的行为关联为 AttackChain。

4. **攻击路径是什么？**  
   从入口、横向移动、权限行为、数据收集到外传，展示完整时间线与证据链。

5. **可能是谁、依据是什么？**  
   基于本地 ATT&CK/TTP 知识、攻击工具/脚本特征和离线 C2 情报进行候选归因；证据不足时允许 `unable_to_attribute`。

---

## 3. 总体产品流程

```text
                    TraceGuard
                        │
                        ▼
                 【分析任务中心】
                        │
             ┌──────────┴──────────┐
             │                     │
          离线分析              在线监测
        上传证据包             Collector / Probe
             │                     │
             └──────────┬──────────┘
                        ▼
               当前分析任务 run_id
                        │
                        ▼
          多源解析 / 时间统一 / 资产归一
                        │
                        ▼
              UnifiedSecurityEvent
                        │
              ┌─────────┴─────────┐
              ▼                   ▼
         Detection             Evidence
              │
              ▼
         ATT&CK Mapping
              │
              ▼
       Correlation / AttackChain
              │
         ┌────┴─────┐
         ▼          ▼
      人工复核      Agent 调查
                     │
                     ▼
                  Attribution
                     │
                     ▼
                   Report
```

### 3.1 答辩前重点

答辩前优先做稳：

```text
离线证据包
→ 分析任务
→ 多源解析
→ Detection
→ ATT&CK
→ AttackChain
→ Agent
→ Attribution
→ Report
```

### 3.2 在线监测定位

真正实时监测作为独立入口，不与当前“上传证据包分析”混淆。

未来形态：

```text
在线监测
├─ Auditd / Sysmon Collector
├─ Zeek / Network Probe
├─ SSH / HTTP Log Collector
└─ 其他 Sensor
        ↓
UnifiedSecurityEvent
        ↓
复用同一 Detection / ATT&CK / Chain / Agent 管道
```

即：**离线与在线只在数据入口不同，后续分析链路共用。**

---

## 4. 核心产品对象：Analysis Run

平台最核心的业务对象不是“日志”“Detection”或“某个页面”，而是：

> **一次分析任务 / 一个攻击案件 / 一个 run_id**

例如：

```text
任务名：八节点靶场攻击实验
run_id：analysis_20260910_xxxxx
```

该 run 下统一关联：

- Raw Event
- UnifiedSecurityEvent
- Entity
- Session
- Evidence
- Detection
- ATT&CK Technique
- AttackChain
- Agent Task / Result
- Attribution
- Report

---

## 5. Current Run 全局工作区

### 5.1 顶部任务选择器

平台顶部固定显示：

```text
当前分析任务：[八节点靶场攻击实验 ▼]
```

用户可切换：

```text
八节点靶场攻击实验
历史测试任务 A
历史测试任务 B
全部数据
```

### 5.2 切换原则

一旦切换 Current Run：

- Dashboard
- 攻击事件
- 攻击链
- 日志与事件
- 主机
- 网络
- ATT&CK
- Agent
- Attribution
- Report

必须全部切到同一个 `run_id`。

同时清理上一个 run 的：

- selected chain
- selected evidence
- selected detection
- selected Agent case
- selected report
- selected entity

禁止出现跨 run 串数据。

### 5.3 Run Registry

正常平台产生的 Analysis Run 应统一进入可选择的 Run Registry。

推荐：

```text
正常产品运行：
data/traceguard.db

所有正常分析任务：
同一数据库，通过 run_id 隔离

data/analysis_tasks/：
保存上传文件及任务元数据

Dataset Benchmark：
可独立使用 data/dataset_e3/traceguard.db

pytest / self-check：
临时数据库
```

---

## 6. 分析任务中心

“在线分析”统一改为：

> **分析任务**

### 6.1 页面功能

#### 新建任务

用户配置：

- 任务名称
- 证据包
- 可选 manifest
- 默认时区
- 其他合法环境元数据

点击：

```text
开始分析
```

### 6.2 实际分析阶段

只展示后端真实存在的阶段，例如：

```text
上传
→ 文件识别
→ 日志解析
→ 标准化
→ 实体/资产处理
→ 主机与网络分析
→ Detection
→ ATT&CK
→ 跨源关联
→ AttackChain
→ 可启动 Agent 调查
→ 基础溯源分析完成
```

不得把不存在的后端阶段做成“假进度条”。

当前实现中，阶段进度由 `AnalysisPipeline.run()` 的 progress callback 回写 `task.json`，前端分析任务页只渲染后端返回的 `stages/current_stage`。因此页面不会自行假设“已经跑到哪一步”；如果后端停在某阶段，页面也会真实停在该阶段。

### 6.3 完成状态

基础分析完成后：

```text
✓ 溯源分析完成
可启动 Agent 调查

[进入分析工作区]
[启动完整 Agent 调查]
```

不能在此时显示：

- 报告已生成
- Attribution 已完成
- 报告就绪

除非对应 Agent 流程确实已执行。

---

## 7. 多源数据接入

平台需要统一处理以下数据类型。

### 7.1 Windows 主机日志

目标能力：

- Windows Security Event
- EVTX 基础解析
- 登录/注销事件
- 特权上下文
- 账户创建/删除
- 进程创建（若日志中存在）
- 文件访问等关键行为

重点不是支持所有 Windows Event，而是保证已支持事件的解析语义准确。

### 7.2 Linux 主机日志与行为

目标能力：

- Auditd
- auth.log / SSH / sudo
- 进程执行
- 文件访问
- 权限变化
- 网络连接
- 系统调用相关行为

### 7.3 Web / 应用日志

例如：

- Nginx access/error
- HTTP 应用日志
- C2 HTTP 行为日志

注意：

> 文件名、目录名不能直接成为“攻击答案”。

例如文件叫 `c2_http.log`，不能因为名称中含 `c2` 就直接判为 C2。

### 7.4 PCAP / 网络流量

优先级：

```text
Zeek（可选增强）
→ tshark（可选增强）
→ Python 内置基础 PCAP Parser（必须可用）
```

输出统一：

```text
network.flow
```

字段至少包括：

- first_seen
- last_seen
- src_ip
- src_port
- dst_ip
- dst_port
- protocol
- packets
- bytes

答辩前优先保证真实 `.pcap` 能生成基础 flow。

---

## 8. 时间统一

不同日志可能存在：

- UTC
- `+0800`
- `+08:00`
- 无时区时间

平台统一将时间转换为 UTC 存储。

对于无时区日志，通过 Analysis Task / manifest 提供：

```json
{
  "default_timezone": "+08:00"
}
```

原则：

- 日志显式带时区 → 尊重原时区
- 日志不带时区 → 使用任务默认时区
- 最终统一 UTC
- 不在代码里全局硬编码 UTC+8

---

## 9. Asset Resolver / 资产归一

真实攻击链需要解决：

> 同一台主机在不同数据源中可能有不同名字。

例如：

```text
office
WIN-M2NV2G374QA
n7-office
10.x.x.x
```

最终必须统一：

```text
N7-Office
```

Asset Resolver 应综合：

- hostname
- IP
- alias
- manifest
- sensor
- source path hint
- 角色信息

最终形成 canonical asset。

禁止只靠：

```text
n7_*
n8_*
```

这种文件名前缀判断。

---

## 10. manifest.json

证据包根目录可放：

```text
manifest.json
```

用于描述环境元数据，而不是攻击答案。

### 10.1 允许字段

```json
{
  "default_timezone": "+08:00",
  "asset_aliases": {
    "office": "n7-office",
    "win-m2nv2g374qa": "n7-office",
    "web": "n4-web"
  },
  "sensitive_path_patterns": [
    "/data/secret/**"
  ]
}
```

### 10.2 禁止进入 Detection 的信息

以下内容可以作为人工 Ground Truth 验证材料，但不得进入检测和攻击链生成：

- attack_steps
- expected_techniques
- expected_chain
- GT attack labels
- 已知攻击节点顺序

原则：

> manifest 描述“环境是什么”，TraceGuard 自己判断“发生了什么”。

---

## 11. UnifiedSecurityEvent

不同数据源最终统一为同一事件模型。

核心字段可包括：

```text
event_id
run_id
timestamp
source_kind
sensor
host
canonical_asset
user
process
parent_process
file
network
action
severity
time_quality
raw_reference
```

UnifiedSecurityEvent 是后续所有结构化分析的基础。

---

## 12. Detection + Evidence

### 12.1 Detection 定位

Detection 由：

- 通用检测规则
- 行为关联
- 已归一的安全事件

产生。

不得：

- 使用 Ground Truth 提升 Detection
- 为提高 ATT&CK 数量强行映射
- 为提高指标针对数据集硬编码

### 12.2 Evidence

每个 Detection 必须能够追溯：

```text
Detection
→ UnifiedSecurityEvent
→ Evidence
→ Raw Event / Source
```

这是整个系统可信性的基础。

---

## 13. 攻击事件中心

页面回答：

> 当前案件检测到了哪些安全行为？

应展示：

- Detection 类型
- 时间
- 主机
- 用户/进程
- 严重等级
- ATT&CK
- Evidence
- 来源

必须支持：

- 当前 run scope
- total
- pagination
- 默认最近记录优先
- 排序
- 条件过滤

禁止只返回最早 100 条。

---

## 14. 日志与安全事件

页面回答：

> 当前 run 实际接入和标准化了哪些数据？

展示：

- 时间
- source
- host
- action
- process
- file
- network
- raw/evidence reference

要求：

- 分页
- total
- 最近记录
- source filter
- host filter
- action filter
- 当前 run scope

该页面是 Evidence 回溯的重要入口，而不是简单日志列表。

---

## 15. 主机行为分析

页面回答：

> 当前案件中每台主机发生了什么？

### 15.1 答辩前真实能力

至少准确展示：

- 主机事件数
- 登录/认证行为
- 进程行为
- 文件行为
- 权限相关行为
- 网络行为
- 关联 Detection

### 15.2 后续增强

如果后端真正实现，再展示：

- Process Tree
- Session Timeline
- 异常父子进程
- 内存行为
- 完整权限提升链

页面不能把尚未实现的能力写成“已经支持”。

---

## 16. 网络流量分析

页面回答：

> 谁和谁通信？什么时候？通过什么协议？流量规模如何？是否与 Detection/AttackChain 关联？

展示：

- Source Asset / IP
- Destination Asset / IP
- Protocol
- Port
- packets / bytes
- first_seen / last_seen
- 关联 Detection
- 关联 AttackChain

可增加：

- 主机通信关系图
- Top Talkers
- 外联目的地
- 可疑连接

只有后端真正存在对应检测时，才展示：

- DNS Tunnel
- HTTP Covert Channel
- ICMP Tunnel

---

## 17. ATT&CK 分析

页面回答：

> 当前 run 使用了哪些 ATT&CK Technique？

展示：

- Technique ID
- Technique Name
- Tactic
- Detection 数
- unique Evidence 数
- 涉及资产
- 首次/最后出现时间

支持下钻：

```text
Technique
→ Detection
→ Event
→ Evidence
```

禁止通过简单求和造成 Evidence 重复计数。

---

## 18. AttackChain：平台核心页面

AttackChain 是 TraceGuard 最重要的展示页面。

### 18.1 页面布局

```text
┌────────────┬──────────────────────┬────────────────┐
│ 攻击链列表 │     攻击关系图       │ 时间线/证据检查 │
│            │                      │                │
│ Chain #1   │ N1 → N4 → N2        │ Detection      │
│ Chain #2   │        ↓             │ ATT&CK         │
│ Chain #3   │       N7 → N8        │ Evidence       │
│            │                      │ Confidence     │
└────────────┴──────────────────────┴────────────────┘
```

### 18.2 精确查询

当前 chain 必须按 `chain_id` 精确获取：

- nodes
- edges
- steps
- detections
- evidence

禁止：

```text
先拿前 100 个 graph nodes
→ 再碰运气找当前 chain
```

Evidence 也必须：

```text
GET /evidence/{evidence_id}
```

精确回查，而不是先取前 500 条。

### 18.3 Chain Relation

关系应尽量区分：

- temporal
- shared entity
- process parent
- network
- authentication
- file lineage
- inferred

不能因为“时间上相邻”就直接宣称强因果。

---

## 19. Agent 调查

Agent 是**AttackChain 之后的增强调查层**。

不是主检测器。

结构：

```text
Detection / Evidence
        ↓
AttackChain
        ↓
Coordinator
   ┌────┴────┐
   ↓         ↓
 Host      Network
   └────┬────┘
        ↓
 Correlation
        ↓
 Attribution
        ↓
 Report
```

完整调查可包含：

1. Coordinator Agent
2. Host Agent
3. Network Agent
4. Correlation Agent
5. Attribution Agent
6. Report Agent

原则：

- Agent 只基于已有 Evidence / Detection / Chain
- EvidenceValidator 开启
- 不允许虚构 Evidence ID
- 不允许凭空制造 ATT&CK Technique
- 不允许为满足预期链补步骤
- 证据不足允许 `unable_to_attribute`

---

## 20. Attribution / 威胁归因

平台当前应定位为：

> **基于本地知识与离线情报的候选归因 / 相似性分析**

而不是：

> “确认攻击组织”或“实时全球威胁情报系统”。

### 20.1 可使用数据

- 本地 ATT&CK Group/TTP 数据
- 工具/脚本指纹
- 行为模式
- 离线 C2 intelligence snapshot
- 域名/IP/配置特征

### 20.2 页面必须明确

例如：

```text
候选组织：APTxx
TTP 相似度：0.xx
证据等级：低/中/高
情报来源：本地 ATT&CK / 离线快照
结论：仅供候选归因，不构成身份确认
```

如果没有足够证据：

```text
unable_to_attribute
```

是正确结果。

---

## 21. 报告中心

Report Agent 在完整调查后生成：

- Markdown
- HTML
- 可选导出

内容可包括：

- 分析任务概要
- 数据源
- 关键 Detection
- ATT&CK
- AttackChain
- 关键 Evidence
- Agent Findings
- Attribution
- 风险总结
- 局限性

Report 必须绑定当前 `run_id`。

切换 run 时不能显示上一任务报告。

---

## 22. 安全实体视图

如果当前页面只有实体列表而没有完整的“节点 + 边 + 图关系”，页面不应夸大成完整“安全知识图谱”。

推荐名称：

> **安全实体视图**

展示：

- Asset
- User
- Process
- File
- IP
- Domain
- Session
- C2 candidate

如果未来真正构建 entity relation graph，再升级为“安全知识图谱”。

---

## 23. 数据源与资产

准确定位：

> 当前平台已接入的数据源和解析结果概览。

展示：

- source type
- sensor
- record count
- asset count
- time quality
- parse status
- run coverage

如果没有真实在线 heartbeat，不能写：

```text
Sensor Online / Healthy
```

应使用：

```text
已导入
已解析
解析成功
```

---

## 24. Dataset Benchmark

数据集实验与正常案件分析属于两个不同产品用途。

### 正常分析任务

```text
真实案件 / 靶场证据包
→ Analysis Run
→ 全平台工作区
```

### Dataset

```text
CADETS
→ Benchmark / Evaluation
→ 泛化能力验证
```

Dataset 页面可展示：

- normalized count
- Detection
- Technique
- Chain
- Evidence backtrace
- IOC coverage
- stage coverage
- limitations

Ground Truth 只能用于：

> Evaluation

不能用于：

> Detection / ATT&CK / AttackChain 生成。

---

## 25. Dashboard

Dashboard 回答：

> 当前案件整体发生了什么？

展示建议：

### 核心 KPI

- 标准化事件数
- Detection 数
- ATT&CK Technique 数
- AttackChain 数

### 数据覆盖

- Windows Security
- Auditd
- PCAP
- HTTP/Nginx
- 其他源

### 资产

- 涉及资产数
- 高风险资产
- 外联资产

### 攻击链摘要

只展示真正“最近”的 Chain，而不是最早的记录。

### 状态语义

如果只是离线上传数据，不把“已 ingest”展示成“Sensor Healthy”。

---

## 26. 全局搜索

搜索至少支持：

- Event
- Detection
- Chain
- Entity
- Session

如后端真正支持，再加入：

- Agent Finding
- Report

搜索结果点击后应尽可能定位：

```text
Event → 对应 Event
Detection → 对应 Detection
Chain → 对应 Chain
```

如果暂时只能跳列表，则文案应准确，不宣称“精确定位”。

---

## 27. 页面真实性原则

这是答辩前最重要的产品原则之一。

每个页面都必须满足：

```text
页面展示
↓
API
↓
Repository / SQL
↓
真实数据库
↓
真实算法
↓
Evidence
```

任何数据都不应来自：

- 静态 mock
- 为页面效果硬编码的数字
- Ground Truth
- 当前 run 之外的历史状态
- 被截断后误导的数据
- 名称和实际能力不一致的功能

页面状态应区分：

- REAL
- PARTIAL
- NOT_IMPLEMENTED
- OFFLINE / SNAPSHOT

而不是把 PARTIAL 包装为“完整支持”。

---

## 28. 数据库设计原则

### 正常平台

```text
data/traceguard.db
```

所有 Analysis Run 共用。

通过：

```text
run_id
```

隔离案件。

### 上传任务

```text
data/analysis_tasks/
```

保存：

- upload bundle
- task metadata
- manifest
- processing metadata

### Dataset

```text
data/dataset_e3/traceguard.db
```

可独立。

### 测试

pytest / self-check 使用临时数据库。

### 历史数据

例如：

- testbed_upload_analysis_final
- testbed_analysis
- pytest_tmp*

可以保留为历史产物，但不能成为正常产品隐式依赖。

---

## 29. 最终导航结构建议

```text
TraceGuard
│
├─ 分析工作区
│  ├─ 安全态势总览
│  ├─ 分析任务
│  ├─ 攻击事件中心
│  └─ 攻击链溯源
│
├─ 证据分析
│  ├─ 日志与安全事件
│  ├─ 主机行为分析
│  ├─ 网络流量分析
│  └─ 安全实体视图
│
├─ 威胁分析
│  ├─ ATT&CK 分析
│  ├─ Agent 调查
│  └─ 威胁归因
│
├─ 管理与输出
│  ├─ 数据源与资产
│  ├─ 报告中心
│  └─ 设置
│
└─ 实验验证
   └─ 数据集实验
```

---

## 30. 最终用户操作路径

答辩演示建议严格按真实产品流程：

```text
进入 TraceGuard
        ↓
分析任务
        ↓
新建“八节点靶场攻击实验”
        ↓
上传 攻击行为记录.zip
        ↓
开始分析
        ↓
多源日志/PCAP 处理进度
        ↓
溯源分析完成
        ↓
进入分析工作区
        ↓
安全态势总览
        ↓
攻击事件中心
        ↓
日志 / 主机 / 网络 Evidence
        ↓
ATT&CK
        ↓
攻击链溯源
        ↓
点击 Chain Step 回查 Evidence
        ↓
启动完整 Agent 调查
        ↓
Agent Findings
        ↓
候选威胁归因
        ↓
报告中心
```

---

## 31. 产品验收标准

### 31.1 分析任务

- [x] 一个证据包创建一个 run_id
- [x] 可切换历史 Analysis Run
- [x] Current Run 全平台一致
- [x] 顶部 Current Run 下拉与任务历史同步刷新
- [x] 分析进度条来自后端真实阶段回写

### 31.2 多源数据

- [x] Windows 日志进入统一事件
- [x] Linux/Auditd 进入统一事件
- [x] Web/HTTP 进入统一事件
- [x] PCAP 进入 network.flow
- [x] 时间统一
- [x] 资产统一

### 31.3 Detection / ATT&CK

- [x] Detection 可回溯 Event/Evidence
- [x] ATT&CK 不依赖 Ground Truth
- [x] Technique 统计属于当前 run

### 31.4 AttackChain

- [x] Chain 不依赖固定前 N 个 graph nodes
- [x] chain_id 精确加载图
- [x] Evidence 精确下钻
- [x] 同 tactic 多 Technique 在 Detection/ATT&CK 视图保留；主链展示按阶段选择代表步骤，避免答辩链路爆炸
- [x] 不把时间相邻误写成绝对因果

### 31.5 Agent

- [x] 可在平台手动启动完整调查
- [x] 六 Agent 真实执行
- [x] real LLM / fallback 状态可见
- [x] EvidenceValidator 生效
- [x] Agent 不制造不存在的 Evidence/ATT&CK

### 31.6 Attribution / Report

- [x] Attribution 说明本地/离线情报性质
- [x] 允许 unable_to_attribute
- [x] Report 属于当前 run
- [x] 切换 run 不串报告

### 31.7 页面真实性

- [x] Events 分页 + total
- [x] Detections 分页 + total
- [x] 默认展示最近数据
- [x] Dashboard 最近记录语义正确
- [x] 没有 mock 冒充实时能力
- [x] 页面名称与真实功能一致

---

## 32. 答辩前优先级

### P0：必须完成

1. Current Run 全平台统一
2. Events / Detections 正确分页、排序、total
3. AttackChain 精确图数据与 Evidence 下钻
4. manifest / timezone / AssetResolver
5. PCAP 真实进入 Network Flow
6. Analysis 状态语义准确
7. Attribution mock/离线数据语义收口
8. 真实靶场证据包完整手工验收
9. 真实完整 Agent 流程手工验收

### P1：建议完成

1. Host 页面增强
2. Network 关系展示
3. ATT&CK 下钻
4. Search 精确定位
5. 数据源状态语义优化
6. 历史 Run Registry 统一

### P2：答辩后可增强

1. 真正在线 Collector
2. Zeek 实时 Probe
3. DNS/HTTP/ICMP 隐蔽信道专项检测
4. 更完整进程树
5. 更完整登录会话重建
6. 实时外部威胁情报
7. 完整安全知识图谱
8. Neo4j 在线持久化增强

---

## 33. 一句话产品定义

> **TraceGuard 是一个以分析任务为核心，将 Windows/Linux 主机日志、主机行为和网络流量统一融合，通过 Detection、ATT&CK 与跨源关联构建可回溯 Evidence 的攻击链，并利用多 Agent 完成增强调查、候选归因和报告生成的企业内网恶意攻击行为溯源分析平台。**

---

## 34. 当前开发总原则

后续开发遵循：

```text
先确保已有能力是真的
→ 再确保数据显示准确
→ 再确保跨页面属于同一个 run
→ 再确保 Evidence 可回溯
→ 最后才增加新能力
```

禁止为了答辩“看起来功能很多”继续加入未真正实现的页面和静态展示。

当前阶段的目标不是功能数量最大化，而是：

> **老师现场点击任意页面，都能解释这是什么数据、从哪里来的、属于哪个 run、经过什么算法、能否回到 Evidence，以及当前能力的真实边界。**
