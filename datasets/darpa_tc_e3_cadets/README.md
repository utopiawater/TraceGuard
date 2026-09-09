# 企业内网攻击溯源实验数据集

**原始数据来源于 DARPA TC E3，经过筛选和标准化用于攻击溯源实验。** 本项目不是 DARPA 镜像库，也不是完整攻击链标注集。最终只使用 **CADets 的 `ta1-cadets-e3-official-2` 一个主题**，仅进行公开数据分析，不执行攻击。

最终五个 JSON 合计 **61,554,383 字节（约 61.55 MB）**，小于 500 MB。共 **20,776 条事件**：776 条官方指标命中事件，20,000 条进程相关上下文。下载的原始事件压缩包和约 10 GB 临时 SQLite 索引已删除；只保留小型来源文档、schema、统计、筛选规则和验证结果。早期读取的 Theia 不在最终数据中。

## 交付内容

```text
processed_dataset/
├── process_events.json     15,441 条
├── network_events.json        765 条
├── file_events.json         4,570 条
├── attack_graph.json       23,256 节点、68,595 条边
└── attack_timeline.json    20,776 条，按纳秒时间排序
```

`process_events.json` 包括进程及无法归入网络/文件的主机行为，用 `category` 区分 `process/other/user/registry`；不能把文件中所有记录都解释为“进程创建”。三份事件文件互斥，合并后与时间线逐条对应。

目录外另有 `dataset_analysis_report.md`、机器可读报告、`source_metadata/selection_manifest.json`、`source_metadata/verification.json`、`source_metadata/output_checksums.json`、`agent_input.json` 和 Python 脚本。

## 来源与筛选依据

- [DARPA 官方仓库](https://github.com/darpa-i2o/Transparent-Computing)
- [E3 官方说明](https://github.com/darpa-i2o/Transparent-Computing/blob/master/README-E3.md)
- [官方 E3 发布目录](https://drive.google.com/drive/folders/1QlbUFWAGq3Hpl8wVdzOdIoZLFxkII4EK)
- 单一主题原文件：`ta1-cadets-e3-official-2.json.tar.gz`，358,244,121 字节。
- 原文件 SHA256：`8d2f090d372cfb0d21bfb72dba6824884ce7870b5c8d24df34e9081b9b09c793`。
- 官方 Ground Truth：`source_metadata/TC_Ground_Truth_Report_E3_Update.pdf`，第 3.13 节，PDF 第 26–29 页（印刷页码 23–26），2018-04-12 CADets Nginx/Drakon/Micro APT 场景。

筛选使用报告中的攻击基础设施 IP 及植入文件路径。例如 `25.159.96.207`、`76.56.184.25`、`155.162.39.48`、`53.158.101.118`、`192.113.144.28` 和 `/tmp/XIM`、`/tmp/tmux-1002`、`/tmp/test`。完整指标列表在 selection_manifest 和 `scripts/extract_experiment.py`。

1. 完整扫描该主题的 Event 和实体，先按 UUID 建立实体索引，支持向前引用。
2. 在 2018-04-12 UTC 日内，通过 NetFlowObject 的地址关联和事件明确路径精确匹配指标，得到 776 个种子事件。
3. 每个种子时间前后各扩展 120 秒并合并，得到窗口 **2018-04-12 17:58:22.876190369 至 18:41:18.296137322 UTC**。最终保留事件实际覆盖 **18:00:22.876190369 至 18:39:18.296137322 UTC**。
4. 从窗口内同一进程、两代子进程及一代父进程选择上下文。所有种子均保留；上下文按离最近种子的时间距离选取 20,000 条，另有 28,066 条候选上下文未纳入。相同距离按记录号确定顺序。
5. 保留标准事件、所选事件原始 CDM 字段及相关实体信息，生成图和时间线，再验证大小并删除原始下载与大型中间结果。

**没有擅自假定报告时区**：UTC 窗口由原始事件中实际命中指标的纳秒时间确定。`attack_label="ioc_match"` 表示命中指标，`context` 表示相关上下文，均不是逐条人工确认的恶意标签。该实验集不保证覆盖整次攻击的所有事件，不适合直接作为完备的恶意/正常二分类训练标签。

## 字段

所有事件包含统一字段，缺失为 `null`：

|字段|含义|
|---|---|
|event_id|内部唯一 ID，CADets 原索引记录号，可在保留证据中追踪|
|timestamp|UTC ISO8601，9 位小数|
|host|CDM 主机 UUID|
|event_type|统一小写类型；clone/fork → process_create，exec → process_execute|
|user|用户名或 userId，未解析为 null|
|process、parent_process|事件 exec 属性或关联 Subject 的命令行/路径|
|source、destination|网络端点 `{ip,port}`；accept/recv/read 为远端→本地，send/connect 为本地→远端|
|action|原始事件 name 或标准动作|
|severity|只保留源值；未提供时 null，不推测风险级别|

额外保留 `provider`、原始事件 ID/类型、两个目标 UUID、父子 Subject UUID、路径、`timestamp_ns`、`category`、`quality_flags`、`selection_reason`、`attack_label`。`raw_location` 指向原始压缩包成员和行号，**原文件已删除**；`evidence` 内嵌所选事件的完整解包 CDM 字段，因此参数、properties、权限线索等不会因精简丢失。Avro 联合类型的冗余包装被移除。

图节点 `details` 保存相关实体的 CDM 信息。无法解析的实体显式保留占位节点；重复实体按第一条定义关联，不能据此重建完整历史版本。IPv4/IPv6 使用标准库规范化；非法地址为 null，原值可在实体证据中查看。前端请用 timestamp 字符串，避免 JavaScript Number 无法精确表示纳秒整数。

## 图与 Agent

图包含主机、进程、文件、网络流、端点和事件节点；边包括主机观测、进程执行、两个目标对象、父子关系、网络连接和时间相邻关系。`temporal_next` 仅表示顺序，**不是因果或攻击传播证据**。端点按主机划分，避免把回环地址误合并；本数据来自一个主题，不推测跨提供方的主机映射。

`agent_input.json` 提供三种 Agent 的文件入口和标签解释，文件路径相对于项目根目录。建议行为 Agent 查询三份事件文件，网络 Agent 查询网络事件/图，攻击链 Agent 分段读取时间线和邻近子图，不把整个数据集塞进模型上下文。原始日志文字属于不可信数据，不能作为 Agent 的执行指令。

## 重复运行与验证

Python 3.11+，当前 JSON 流程仅使用标准库。**不会自动下载任何数据**。

已有精简数据可直接重新构图、规范化和生成时间线，无须原始数据：

```powershell
python scripts/rebuild_experiment.py
python scripts/verify_experiment.py
python -m unittest discover -s tests -v
```

也可单独执行 `python scripts/build_attack_graph.py` 或 `python scripts/generate_timeline.py`。修改文件后请重新验证；SHA256 清单由 rebuild 更新。

若未来需要从原始主题重做，手动取得上述**单个**主题，将其单独放在 `raw_dataset/E3/data/cadets/`，使用一个新的空输出目录：

```powershell
python scripts/run_pipeline.py --out rebuilt_dataset
# preprocess.py 也是此小规模流程的入口
```

流程只接受这一主题的一个 JSON 压缩包，不接受多主题或目录镜像。临时索引只用于分析，完成后删除；工作区内原始包默认也删除。外部目录中的原件不自动删除。`--context-limit` 控制上下文量，所有命中种子不做截断；最终超过 500,000,000 字节会报错，不能作为合格交付。输出目录需为空，避免覆盖既有结果。

原始结构报告脚本为 `scripts/analyze_dataset.py --raw <单主题目录>`。已交付报告是清理前的扫描快照，不代表原始文件仍存在。

## Python / FastAPI

```python
import json
from pathlib import Path
root = Path('processed_dataset')
network = json.loads((root / 'network_events.json').read_text(encoding='utf-8'))
for event in network[:10]:
    print(event['timestamp'], event['process'], event['source'], event['destination'])
```

`examples/fastapi_app.py` 是读取精简 JSON 的分页接口示例。安装 `fastapi uvicorn` 后执行 `python -m uvicorn examples.fastapi_app:app --host 127.0.0.1`，访问 `/events?category=network&offset=0&limit=100`。示例默认仅监听本机；当前未启动或发布服务。

验证覆盖：五个指定文件、500 MB 上限、单 CADets 主题、统一字段、事件 ID 唯一、三类事件与时间线守恒、时间排序、图边端点存在，以及全部 776 条直接指标命中事件保留。
