# TraceGuard

TraceGuard 是面向 2026 网络空间安全课程设计的证据驱动攻击溯源平台。项目直接采用最终模块边界：FastAPI 模块化单体、SQLite 结构化事实库、append-only 原始归档、Neo4j 图投影、React/TypeScript 调查台和受证据约束的 Multi-Agent Harness。

## 当前已接通的主路径

```text
Windows Security / Sysmon XML + Auditd / Wazuh JSON + Zeek JSON
→ RawEventEnvelope → append-only archive
→ UnifiedSecurityEvent → Entity Resolver → Sessionizer
→ SQLite → Graph Projector → DetectionResult
→ ATT&CK Mapping → AttackChain → REST API → Web 调查台
```

当前完整场景覆盖 Windows/Linux/Network 三域、Auditd 复合事件、Wazuh 告警、Zeek conn/dns/http/files/weird/notice/ICMP、代表性主机行为和 DNS/HTTP/ICMP 隐蔽信道，并形成带 Evidence 的七阶段攻击链。fixture 与实时来源共用同一 Adapter。

## 本地运行

最终支持环境为 **Python 3.13（OpenSSL 3）** 与 Node.js 20+。不支持 Python 3.8；旧运行时在真实 DeepSeek HTTPS 调用中会出现 SSL EOF。Windows 从项目根目录安装：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\setup_windows.ps1
```

复制本地配置模板并填写 Neo4j 与 LLM 配置。`.env` 已被 Git ignore，API Key 不得写入其他文件：

```powershell
Copy-Item .env.example .env
```

完成配置后使用固定端口一键启动和检查：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\start.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\check.ps1
```

Web 固定入口为 `http://127.0.0.1:5173`，API 文档为 `http://127.0.0.1:8000/docs`。停止服务：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\stop.ps1
```

需要重新生成七阶段演示数据时，在服务停止状态执行：

```powershell
.\.venv\Scripts\python.exe scripts/replay_scenario.py --scenario backend/fixtures/scenarios/full_attack_chain --run-id run_full_multisource_001
```

Agent 调查中心保留两种调用范围：完整调查执行六个 Agent；快速调查执行 Coordinator、Host、Network、Correlation。两者共用真实 Tool、严格 Schema 和 EvidenceValidator；模型不可用时明确记录为 `deterministic_fallback`，不会伪装成 `real_llm`。

Docker Compose 同样使用 Python 3.13 镜像；容器 Web 入口为 `http://127.0.0.1:8080`。

完整安装、健康检查、Agent 演示与验收记录说明见 [Release Runbook](docs/12_release_runbook.md)。

## 验证

```powershell
.\.venv\Scripts\python.exe scripts/self_check.py
.\.venv\Scripts\python.exe -m pytest
cd frontend
npm run build
```

`self_check.py` 验证主管道、证据外键、图投影、幂等与 Agent 工具权限。普通自动化测试使用 Fake ModelClient，不消耗真实 LLM Token。正式真实模型验收记录保存在 `artifacts/release/`。

## 真实空状态

公开数据集尚未接入时，API 返回空 `data` 与明确 `meta.warnings`；前端不会以 Mock 数据替代。Wazuh、Sysmon、Auditd、Zeek 已进入统一主管道，Dataset Adapter 保留明确的未接入状态。
