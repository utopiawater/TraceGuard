# Web 调查平台产品设计

本文件保留早期 Web 调查台设计。答辩前的产品收口版以 `docs/TraceGuard_产品设计规划.md` 为准；其核心原则是“一个证据包 = 一个分析任务 = 一个 run_id = 全平台同一攻击案件的不同视图”。

## 1. 产品定位

Web 端是“证据驱动的攻击调查台”，不是大屏拼图。主流程只有一条：

```text
发现异常 → 选择事件/案例 → 查看攻击链 → 下钻主机/网络证据
→ 核对 ATT&CK → 启动 Agent 调查 → 审阅归因候选 → 导出报告
```

全局始终显示运行模式 `LIVE / REPLAY / SNAPSHOT`、数据时间范围、数据源缺口和 ATT&CK 版本。任何接口失败都显示失败状态，不静默换成 Mock。

## 2. 信息架构

### 2.1 一级页面

| 页面 | 展示内容 | 数据来源 | 主要 API | 对应需求 |
|---|---|---|---|---|
| 安全态势总览 | 活跃案例、严重度、数据源健康、时间质量、最近攻击链、资产受影响范围 | event/detection/case/source health | `GET /overview`、`GET /sources/health` | R3-02、R3-04、Q-01 |
| 企业网络拓扑 | 9 节点角色、网段、传感器覆盖、资产状态、受控路径叠加 | asset inventory、Host/HAS_IP、testbed manifest | 未来接口 | R3-13、R3-29 |
| 攻击事件中心 | Detection/Case 列表、筛选、状态、证据计数、数据模式 | DetectionResult、Case | `GET /detections`、`GET/POST /cases` | R3-17、R3-18、Q-02 |
| 攻击链溯源 | 课程阶段时间线、步骤图、入口、横移、提权、数据路径、缺口 | AttackChain、Graph、Evidence | `GET /chains/{id}`、`/graph`、`/evidence` | R3-19~R3-23 |
| 主机行为分析 | 登录会话、进程树、文件/注册表、权限与内存行为 | UnifiedEvent、Session、Host graph | `GET /hosts/{id}/timeline`、`/process-tree`、`/sessions` | R3-03、R3-06~R3-12 |
| 网络流量分析 | 会话、DNS/HTTP/ICMP 特征、C2、capture health | Zeek/session/detection/intel | `GET /network/sessions`、`/covert-channels` | R3-13~R3-16、R3-25 |
| ATT&CK 分析 | Technique/Tactic 覆盖、证据计数、版本、映射理由 | Detection mappings、ATT&CK KB | `GET /attack/coverage`、`/techniques/{id}` | R3-17、R3-18 |
| Agent 与归因中心 | 任务图、各 Agent 状态、finding、证据、候选组织和反证 | AgentTask/Result、Attribution | `POST /cases/{id}/agent-runs`、`GET /agent-runs/{id}`、`/attribution` | R3-01、R3-24~R3-26 |
| 报告与实验 | 报告版本、数据集指标、靶场 Ground Truth 对比、导出 | reports、evaluation runs | `GET /reports`、`GET /evaluations/{id}` | R3-27~R3-31 |

当前实现没有单独企业拓扑页面；资产/来源覆盖在 Dashboard、数据源与资产、安全实体视图、AttackChain 页面中展示。不要为了“页面数量”牺牲闭环。

## 3. 关键页面

### 3.1 总览

首屏只回答四个问题：

1. 数据是否在正常进入系统；
2. 当前最重要的攻击案例是什么；
3. 哪些资产受影响；
4. 最近一次完整分析是否可用。

组件：

- Source Status：Wazuh/Sysmon/Auditd/Zeek 等来源的已接入事件量和最后事件时间；没有实时 heartbeat 时不写 Sensor Healthy；
- Time Quality：offset/uncertainty 分布，不能把“最新入库延迟”误称时钟偏差；
- Active Cases：严重度、开始/结束、入口候选、最高阶段；
- Affected Assets：按角色和网段，而非无意义总数；
- Recent Runs：LIVE/REPLAY、版本和状态。

### 3.2 攻击事件中心

表格列：case/detection、标题、严重度、置信度、首末时间、主机、Technique、证据数、状态。支持按来源、资产、stage、Technique、run_id 过滤。

选择 Detection 后可：

- 查看 rule reason 和 feature_values；
- 查看映射依据，而不是只有 ATT&CK 标签；
- 创建/加入 Case；
- 标记 confirmed/false positive/suppressed 并记录 reviewer。

### 3.3 攻击链溯源

布局：

```text
[链标题/分数/状态/数据缺口/版本]
[阶段时间线：入口→执行→持久化→提权→凭据→横移→收集→C2→外传]
[可交互的裁剪关系图] | [当前步骤详情]
[证据表：时间/来源/直接性/原始记录]
[替代路径与未证实结论]
```

默认只展示当前链涉及节点。当前实现通过 `chain_id` 精确加载链相关图节点和 Evidence；全局实体视图仍是 bounded 视图，不应宣称完整知识图谱。

链状态只能由 Ground Truth runner 或人工审阅改为 confirmed。Agent 建议边以虚线候选显示，不直接写入事实图。

### 3.4 主机行为

- 登录 session：开始/结束/源 IP/logon type/state；
- 进程树：实例 ID、PID、ProcessGuid/boot_id、父子、用户、完整性级别；
- 文件：action、path、hash、sensitivity、process；
- 注册表：hive/key/value/operation；
- 内存：source/target process、事件类型、直接或推断、原始字段。

必须能切换“按事件时间”和“按进程树”两种视图。provisional 实体和缺失父进程需要明确标识。

### 3.5 网络流量

会话表以 session_id/Zeek uid 为主，展示方向、五元组、服务、bytes、duration、关联 process。协议面板展示 DNS、HTTP、ICMP 的特征贡献和正常对照。

C2 信息分三层：

- observed：本地直接看到的 IP/Domain/session；
- enriched：外部/本地情报事实及时间；
- inferred：被系统分类为 C2 的理由和置信度。

### 3.6 ATT&CK

矩阵单元格显示 Detection 数、confirmed chain 数和 evidence 数。点击后列出：

- Technique name/ID 和 ATT&CK version；
- 哪条 mapping rule 命中；
- 对应 detection/step；
- 数据源和平台；
- 已撤销/弃用状态。

矩阵覆盖率不能被解释为“安全能力越高越好”；它只表示当前场景观察到的技术。

### 3.7 Agent 与归因

任务图只展示 objective、state、耗时、工具调用摘要、finding 数和错误。finding 卡片必须显示 confidence、evidence、alternative explanation。

归因候选展示：

- Top-k 候选和相似度；
- matched/missing/common techniques；
- tool/software 与 infrastructure 证据；
- 反证；
- `unable_to_attribute` 合法状态；
- “相似性不等于现实身份确认”提示。

### 3.8 报告与实验

- 一键导出 JSON + HTML/Markdown 报告；
- Dataset run：行数、mapping 成功率、P/R/F1、FP/FN；
- Testbed run：Ground Truth step 与系统 step 对照；
- 版本：schema/parser/rule/ATT&CK/prompt/model；
- 可复现 bundle 下载。

## 4. 全局交互

- 任何时间、资产、Technique、evidence 点击都可在页面间保持同一 case context；
- URL 保存 case_id、time range 和 selected entity，刷新不丢状态；
- 长任务返回 `202 + job_id`，通过 WebSocket/SSE 更新；
- 查询必须分页；图查询有深度和节点上限；
- 证据抽屉显示 raw/normalized 切换和字段来源；
- 时间显示默认本地时区，同时可切 UTC，后端始终 UTC。

## 5. 状态与错误设计

| 状态 | UI 行为 |
|---|---|
| loading | 骨架和任务阶段，不显示虚构数值 |
| empty | 说明筛选范围内无数据，提供清除筛选 |
| source unavailable | 标出缺失数据源及对结论影响 |
| stale | 显示最后更新时间和数据模式 |
| partial | 展示已有结果和缺口 |
| failed | 错误码、可重试动作和 run_id |
| snapshot | 顶部固定标签和快照生成时间 |

## 6. API 响应约定

```json
{
  "data": {},
  "meta": {
    "request_id": "req_...",
    "schema_version": "1.0",
    "mode": "live",
    "generated_at": "2026-09-07T12:00:00Z",
    "next_cursor": null,
    "warnings": []
  }
}
```

错误：

```json
{
  "error": {
    "code": "SOURCE_UNAVAILABLE",
    "message": "Zeek session store is unavailable",
    "request_id": "req_...",
    "retryable": true,
    "details": {}
  }
}
```

前端 TypeScript 类型从 OpenAPI 生成；禁止手写一份不同的 AttackChain interface。

## 7. 可视化技术

- ECharts：趋势、分布、ATT&CK 热力；
- Cytoscape.js：攻击链和实体图；
- 普通 HTML table：事件、证据和指标，保证可复制、可筛选；
- 不使用 3D 地球、随机粒子、无语义动态数字；
- 颜色不是唯一编码，严重度同时用文本/图标；
- 红色只表示已确认高危，候选使用琥珀色，未知使用灰色。

## 8. 15 分钟答辩脚本对应

1. 1 分钟：总览看数据源和 9 节点；
2. 2 分钟：触发/回放一个真实事件；
3. 4 分钟：攻击链，从入口下钻到原始证据；
4. 2 分钟：横移、提权、canary 数据外传；
5. 2 分钟：ATT&CK 与 Agent 任务；
6. 2 分钟：数据集指标与开源项目差异；
7. 2 分钟：架构、自研边界和限制。

产品页面必须服务这条脚本，无法进入脚本的 Dashboard 属于 P2。

## 9. 当前实现边界

- 当前“分析任务”是证据包/replay 分析，不是真正实时在线监测。
- 分析任务进度条已接入后端真实阶段回写，不由前端假设阶段；顶部 Current Run 下拉会与任务历史同步刷新。
- “威胁归因”是候选相似性分析；证据不足时 `unable_to_attribute` 是正确结果。
- 报告中心只展示已实际生成并持久化的 Markdown/HTML 报告；基础分析完成不等于报告已生成。
- 搜索已覆盖事件、Detection、Evidence、AttackChain、Session、Agent、Report；结果跳转会保留当前 run，但部分列表页仍以分页表格承载定位。
