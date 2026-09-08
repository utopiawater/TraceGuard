# 云平台靶场与 TraceGuard 对接清单

本清单用于和负责云平台靶场的同学对接。TraceGuard 代码侧已经具备 Wazuh、Sysmon、Windows Security、Auditd、Zeek、Replay 和公开数据集接入能力；云靶场侧重点是提供可复现日志、Ground Truth manifest 和截图/录像证据。

## 1. 分工边界

TraceGuard 仓库负责：

- 统一数据模型、Normalizer、Detection、ATT&CK、AttackChain、Evidence、Agent、Report 和前端展示。
- 接收并 replay 云靶场导出的日志 bundle。
- 输出系统检测结果、攻击链、证据回查和报告。

云平台靶场同学负责：

- 8+ 节点真实部署、隔离网络、安全边界和回滚。
- 各节点传感器安装和时间同步。
- 攻击场景执行和 Ground Truth manifest。
- 日志、截图、录像、哈希清单和 bundle 打包。

## 2. 最低节点要求

至少保留 8 个规定角色，建议 9 个逻辑节点：

| 角色 | 建议节点 | 必须提供的证据 |
|---|---|---|
| 攻击节点 | Kali/Ubuntu | IP、工具执行清单、时间窗口 |
| C2/后门服务 | Ubuntu/容器 | HTTP/DNS/ICMP 或 beacon 服务日志 |
| 防火墙/网关 | OPNsense/VyOS/云安全组 | 分区规则、允许/拒绝日志 |
| Web Server | Linux | Wazuh/Auditd/Web access/error |
| Email 或辅助服务 | Linux/容器 | 服务日志、Wazuh 或应用日志 |
| 内网交换/镜像点 | 云镜像/虚拟交换 | 镜像配置或 PCAP/Zeek 输入说明 |
| Windows Client | Windows 10/11 | Sysmon、Security、Wazuh |
| Windows Server | Windows Server | Sysmon、Security、Wazuh |
| Analysis Center | TraceGuard/Zeek/Wazuh/Neo4j | 采集健康、TraceGuard 截图 |

资源不足时，C2、Email、交换节点可以用容器或云服务替代，但报告里必须保留独立逻辑角色和 IP/host_id。

## 3. 必交日志格式

按一次实验 run 打包：

```text
testbed_bundle/
  manifest.yaml
  checksums.sha256
  windows/
    win_client_sysmon.xml
    win_client_security.xml
    win_server_sysmon.xml
    win_server_security.xml
  linux/
    web_audit.log
    web_wazuh.jsonl
    email_audit.log
    email_wazuh.jsonl
  network/
    zeek_conn.jsonl
    zeek_dns.jsonl
    zeek_http.jsonl
    zeek_weird.jsonl
    capture_health.json
  app/
    web_access.log
    c2_access.log
  screenshots/
  videos/
```

TraceGuard 已支持的优先输入：

- Sysmon XML
- Windows Security XML
- Auditd compound text log
- Wazuh JSON / JSONL alert
- Zeek JSON log: conn、dns、http、files、weird、notice、icmp

如果云端只能导出 CSV 或其他格式，先保留原文件，不要手工改字段；另附 schema 说明。

## 4. manifest.yaml 必填字段

```yaml
scenario_id: cloud-testbed-chain-001
run_id: run_cloud_testbed_001
timezone: UTC+08:00
time_sync:
  expected_max_offset_ms: 1000
  evidence: screenshots/time_sync.png
nodes:
  - node_id: N4
    role: web_server
    hostname: web01
    os: ubuntu
    ips: ["172.16.20.10"]
    sensors: ["auditd", "wazuh", "web_access"]
steps:
  - step_id: s01
    stage: initial_access
    planned_window: ["2026-09-09T10:00:00+08:00", "2026-09-09T10:05:00+08:00"]
    actor: N1
    target: N4
    expected_sources: ["zeek.http", "auditd"]
    notes: "教学 PoC，仅在隔离环境执行"
artifacts:
  screenshots: ["screenshots/topology.png", "screenshots/wazuh_agents.png"]
  videos: ["videos/demo.mp4"]
```

Ground Truth manifest 只用于最终 evaluation，不进入 Detection、ATT&CK、AttackChain 或 Agent Tool。

## 5. 推荐攻击链检查点

至少覆盖：

- 外部扫描或探测。
- Web 初始访问或受控入口。
- 执行或脚本启动。
- C2 / beacon / 反连通信。
- 权限变化。
- 横向移动。
- canary 敏感文件访问或暂存。
- 外传或模拟外传。

如果现场时间不足，可以使用云端真实日志 replay；PPT 和系统页面需标明 replay mode。

## 6. TraceGuard 导入验收

云端 bundle 到位后，TraceGuard 侧验收至少检查：

- raw envelope 数量与 bundle manifest 对齐。
- normalized event 没有静默丢失。
- run_id 隔离，不混入 fixture / DARPA / 历史实验。
- Detection 均有 Evidence。
- AttackChain step 均可回查 raw evidence。
- Agent findings 通过 EvidenceValidator。
- 报告中明确 Ground Truth 只用于对照。

## 7. 不要交付的内容

- 真实公网攻击目标。
- 真实个人、学校或企业数据。
- API Key、云平台 AK/SK、Neo4j 密码、Wazuh 密钥。
- 未脱敏的账号口令。
- 没有 manifest 的散乱日志截图。
