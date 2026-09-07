# 8 节点以上隔离教学靶场设计

## 1. 结论

建议搭建 9 个逻辑节点：官方规定的 8 类节点全部独立登记，再增加 1 个分析中心。通过 5 台 VM + 容器服务 + 虚拟交换实现，不要求 9 台高配置 VM。所有攻击、扫描、后门和 C2 软件仅在 Host-only/Internal 虚拟网络运行，默认无公网路由；情报数据提前冻结。

## 2. 拓扑

```text
                    MGMT 10.10.99.0/24
                         [N9 SOC]
                    Wazuh/Neo4j/API/Zeek
                              |
                mirror -------+--------- management
                              |
[N1 Attacker]     [N2 C2]   [N3 Firewall]
 172.16.10.10   172.16.10.20   WAN/DMZ/LAN
        \             /          |
         Attack segment      DMZ 172.16.20.0/24
                           /                 \
                    [N4 Web]              [N5 Email]
                           \                 /
                         [N6 Internal Switch]
                                  |
                           LAN 172.16.30.0/24
                           /                \
                    [N7 Office PC]       [N8 Core Server]
```

N3 防火墙负责分区和边界日志；N6 使用 Open vSwitch/虚拟交换机实现 LAN 交换和镜像；边界接口及内网镜像流量送入 N9 Zeek。若虚拟化平台不能把全部流量镜像到同一 NIC，可在 N9 使用两个 Zeek interface 或分别录制 PCAP 后合并，但报告必须说明覆盖边界。

## 3. 节点清单

| 节点 | 官方角色 | 实现形式 | 最低建议 | 安全遥测 | 用途 |
|---|---|---|---|---|---|
| N1 | Attack Node | Kali/Ubuntu VM | 2 vCPU/2 GB | 工具执行清单、可选审计 | 受控扫描、利用和横移起点 |
| N2 | C2 Server | Ubuntu VM 或独立 Docker host | 1 vCPU/1 GB | 服务访问日志、网络流量 | 实验 C2/HTTP/DNS/ICMP 接收端 |
| N3 | Firewall | OPNsense/VyOS VM | 1-2 vCPU/1-2 GB，3 NIC | 防火墙连接/阻断日志 | Attack、DMZ、LAN 分区 |
| N4 | Web Server | Ubuntu VM + 易受控容器 | 2 vCPU/2 GB | Wazuh + Auditd + Web access/error | 边界 Web 入口与 Linux 行为 |
| N5 | Email Server | Linux 容器/轻量 VM | 1 vCPU/1 GB | SMTP/应用日志 + Wazuh | 封闭邮件投递/取证 |
| N6 | Internal Switch | Open vSwitch/虚拟交换节点 | 宿主功能或 1 vCPU/512 MB | 流镜像统计 | 内网交换与 Zeek mirror |
| N7 | Office PC | Windows 10/11 VM | 2 vCPU/4 GB | Sysmon + Security + Wazuh | 用户登录、脚本、注册表、内存行为 |
| N8 | Core Server | Windows Server VM | 2 vCPU/4 GB | Sysmon + Security + Wazuh | 远程登录、权限、敏感 canary 数据 |
| N9 | Analysis Center | Ubuntu VM/物理宿主容器组 | 4 vCPU/8 GB | 自监控、Zeek capture health | Wazuh Manager、Neo4j、SQLite、API、UI |

资源不足时，N2/N5 可为独立容器，N6 使用虚拟交换；N7/N8 必须是真正 Windows VM，N4/N9 为 Linux。每个逻辑节点都在资产表拥有独立 host_id、角色、IP 有效期和截图证据。

## 4. 网络和安全边界

- 三个业务网段均为 Internal/Host-only；N3 默认拒绝任何到真实公网的转发。
- 管理网只允许 N9 到各传感器/Agent；Attack 网不能访问宿主机管理接口。
- C2 域名使用保留的实验域或 hosts/本地 DNS，不使用真实第三方域名/IP。
- 数据全部为 canary/虚构账号；不得放入真实个人、学校或企业数据。
- 攻击工具镜像、规则和场景 manifest 固定哈希；运行前快照，运行后回滚。
- 紧急停止：关闭 N3 Attack/DMZ/LAN 转发或暂停 N1/N2。
- 任何需要联网下载的步骤在实验前完成；现场不依赖公网。

## 5. 采集设计

### 5.1 Windows

N7/N8：

- Security：登录/注销、显式凭据、特殊权限、进程事件；
- Sysmon：1/3/5/7/8/10/11/12-14/22/25/26，按实验路径过滤；
- Wazuh Agent 将 Event Channel 统一汇聚；
- W32Time 状态和 offset 作为时间质量事件。

### 5.2 Linux

N4/N5/N9：

- Auditd 采集 execve、关键文件读写、身份变化、关键 socket；
- Wazuh 采集 auth、sudo、服务、FIM 和应用日志；
- Web/SMTP 服务保留请求/会话 ID；
- chrony/NTP 状态进入时间质量。

### 5.3 Network

- N3 边界和 N6 内网镜像到 N9；
- Zeek JSON：conn、dns、http、ssl/x509、ssh、smtp、files、tunnel、weird、notice、capture_loss；
- 每次场景保存小型 PCAP 切片、Zeek logs 和 capture loss；
- 防火墙日志与 Zeek flow 交叉验证入口和被阻断行为。

## 6. 完整攻击验证场景

这是封闭教学场景的行为设计，不包含面向真实系统的利用命令。所有步骤由 `scenario_manifest.yaml` 给出预计时间、节点、预期证据和回滚动作。

| 阶段 | 受控行为 | 节点 | 预期主机证据 | 预期网络证据 | 预期链结果 |
|---|---|---|---|---|---|
| 0 基线 | 正常 Web、邮件、DNS、登录 10 分钟 | N4/N5/N7/N8 | 正常会话/进程 | 正常分布 | 建立误报对照 |
| 1 扫描探测 | N1 对 N3 暴露服务做限速扫描 | N1→N3/N4 | Web/防火墙日志 | Zeek conn/weird | 外部侦察，不等于成功入侵 |
| 2 初始访问 | 对 N4 故意脆弱容器执行已批准的教学 PoC | N1→N4 | Web 子进程、Auditd execve | 入站 HTTP 会话 | entry_point=N4 Web |
| 3 执行/C2 | N4 启动实验 beacon 与 N2 通信 | N4→N2 | 进程+connect | 周期 HTTP | C2 step + process/session |
| 4 持久化 | N4 创建实验 cron/service 标记 | N4 | 文件/服务/execve | 可无 | Persistence Technique |
| 5 凭据访问 | 读取专用 canary credential 文件 | N4 | file.read、process/user | 无 | Credential Access，明确为 canary |
| 6 横向移动 1 | 使用实验凭据访问 N5 并执行标记命令 | N4→N5 | 两端登录与进程 | SSH/SMB 会话 | 源进程→网络→目标登录 |
| 7 用户入口 | N5 向 N7 投递仅在实验域可访问的测试邮件，用户模拟器启动签名测试程序 | N5→N7 | 邮件/登录/进程/下载文件 | SMTP/HTTP/DNS | Email/Web 证据与 N7 进程关联 |
| 8 Windows 持久化/内存 | 在 N7 创建可回滚计划任务/注册表项并运行安全的注入遥测测试 | N7 | Sysmon registry、8/10/25 等 | C2 beacon | Persistence + Injection evidence |
| 9 权限提升 | 利用预置错误配置切换到实验管理员上下文 | N7 | 4672、进程 token/父子 | 无 | 身份前后路径 |
| 10 横向移动 2 | 通过实验 WinRM/SMB/RDP 凭据访问 N8 | N7→N8 | 源工具、N8 登录和远程进程 | 内网会话 | Lateral Movement |
| 11 数据访问/暂存 | N8 读取 canary 文档并创建带唯一标记的归档 | N8 | file.read/create、hash/size | 无 | Sensitive File→Archive |
| 12 外传 | 归档经 HTTP 发往 N2；独立短实验生成 DNS 和 ICMP 通道特征 | N8→N2 | transfer process | HTTP/DNS/ICMP | 数据 lineage→session→C2 |
| 13 清理/回滚 | 停止 beacon，删除实验任务/文件，回滚快照 | 全部 | 清理事件 | 会话结束 | 记录但不把回滚当攻击影响 |

若某个真实注入测试不稳定，可使用 Atomic Red Team/自编译无害测试器触发明确的 Sysmon 事件；必须将结果描述为“行为遥测验证”，不能声称检测了所有反射加载变体。

## 7. Ground Truth Manifest

```yaml
scenario_id: lab-chain-001
version: 1.0
clock_baseline:
  expected_max_offset_ms: 500
steps:
  - step_id: s02
    stage: initial_access
    actor_host: N1
    target_host: N4
    planned_window: [start, end]
    expected_events:
      - {source: zeek.http, action: http.request}
      - {source: auditd, action: process.start}
    expected_techniques: [validated-at-build-time]
    expected_relations: [network_flow, spawn]
    rollback: restore_n4_snapshot
```

Runner 记录实际 start/end、退出状态和 artifact hash。Ground Truth 与检测使用不同文件和代码路径，避免“用答案生成答案”。

## 8. 验收清单

- 9 个资产和规定角色均在 UI 可见；
- N7/N8 Windows、N4/N5 Linux 实时事件进入同一 schema；
- 边界和内网 Zeek 均有 capture health；
- 登录、进程、文件、注册表、内存、网络均至少一条 direct evidence；
- 至少两次横移、一次权限变化、一次 canary 数据访问与外传；
- DNS/HTTP/ICMP 三个 detector 都有正例和正常对照；
- 链入口、路径和终点与 manifest 对比；
- 所有 AttackChain step 可下钻 raw evidence；
- 场景可回滚，二次运行结果 ID 不冲突；
- 截图/录像记录节点清单、传感器健康、链图和证据。

## 9. 演示压缩方案

现场不实时执行完整攻击。预先生成一份经过 Ground Truth 验证的 replay bundle；现场只执行一个安全、短小的动作展示“实时入站”，其余链通过 replay 在 2-3 分钟内重建。UI 必须标明 replay 模式。这样既保留真实数据，又避免 15 分钟内因 VM、网络或工具波动失败。
