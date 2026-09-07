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

要求 Python 3.8+、Node.js 20+。Windows 推荐从项目根目录执行安装脚本；它只在当前进程内取消 `PIP_NO_INDEX` 并绕过失效的本地代理，不会持久修改系统设置：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\setup_windows.ps1
```

然后执行：

```powershell
python scripts/replay_scenario.py
python scripts/replay_scenario.py --scenario backend/fixtures/scenarios/full_attack_chain --run-id run_full_multisource_001
python scripts/export_schemas.py
python scripts/export_openapi.py
python -m uvicorn app.main:app --app-dir backend --reload
```

若当前网络可以正常访问官方 PyPI，也可不用安装脚本，直接执行 `python -m pip install -e ".[dev]"`。

另开终端：

```powershell
cd frontend
npm install
npm run generate:api
npm run dev
```

浏览器访问 `http://127.0.0.1:5173`，API 文档位于 `http://127.0.0.1:8000/docs`。

也可复制 `.env.example` 为 `.env`，修改本地 Neo4j 密码后执行 `docker compose up --build`，Web 入口为 `http://127.0.0.1:8080`。

## 验证

```powershell
python scripts/self_check.py
python -m pytest
cd frontend
npm run build
```

`self_check.py` 不依赖 FastAPI/pytest，可在受限离线环境验证完整主管道、证据外键、图投影、幂等与 Agent 工具权限。完整 API 测试需要安装开发依赖。

## 真实空状态

Agent 执行、归因、公开数据集和报告生成器尚未填充时，API 返回空 `data` 与明确 `meta.warnings`；前端不会以 Mock 数据替代。Wazuh 与 Auditd 已进入统一主管道，Dataset Adapter 仍保留明确的未接入状态，留待下一阶段。
