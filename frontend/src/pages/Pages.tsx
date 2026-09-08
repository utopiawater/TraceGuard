import { ResourcePage } from '../components/ResourcePage'
import { EmptyState } from '../components/EmptyState'
import { PageHeader } from '../components/PageHeader'
import { useApi } from '../hooks/useApi'

export const IncidentsPage=()=> <ResourcePage title="攻击事件中心" description="审阅确定性检测、置信度、ATT&CK 映射与证据数量。" endpoint="/api/detections" columns={[["title","事件"],["severity","严重度"],["confidence","置信度"],["attack_mappings.0.subtechnique_id|attack_mappings.0.technique_id","ATT&CK"],["rule_id","规则"],["created_at","发生时间"]]}/>
export const GraphPage=()=> <ResourcePage title="安全知识图谱" description="查看规范化实体与有证据引用的行为关系。" endpoint="/api/entities" columns={[["display_name","实体"],["entity_type","类型"],["first_seen","首次出现"],["last_seen","最后出现"]]}/>
export const HostsPage=()=> <ResourcePage title="主机行为分析" description="围绕登录会话、进程树、文件、注册表、权限和内存行为调查。" endpoint="/api/hosts" columns={[["hostname","主机"],["logins","登录"],["process","进程"],["file","文件"],["registry","注册表"],["privilege","权限"],["memory","内存"],["last_seen","最后活动"]]}/>
export const NetworkPage=()=> <ResourcePage title="网络流量分析" description="按 Zeek UID 与五元组检查 DNS、HTTP、ICMP、C2 和跨源会话。" endpoint="/api/network" columns={[["event_time","时间"],["source","来源"],["action","动作"],["transport","协议"],["application","应用"],["src","源端"],["dst","目标端"],["bytes_sent","发送字节"]]}/>
export const EventsPage=()=> <ResourcePage title="日志与安全事件" description="检索统一事件并沿 provenance 回查原始记录。" endpoint="/api/events" columns={[["event_time","事件时间"],["source.kind","来源"],["host.display_name","主机"],["action","动作"],["event_type","类型"],["message","摘要"],["provenance.parser_name","解析器"]]}/>
export const AttackPage=()=> <ResourcePage title="ATT&CK 分析" description="查看固定版本的 Technique 覆盖、映射规则与证据数量。" endpoint="/api/attack" columns={[["technique_id","Technique"],["technique_name","名称"],["detection_count","检测"],["evidence_count","证据"],["attack_version","版本"]]}/>
export const SourcesPage=()=> <ResourcePage title="数据源与资产" description="检查传感器、最后事件、时间质量、dead-letter 与资产覆盖。" endpoint="/api/sources" columns={[["sensor_id","传感器"],["kind","来源"],["dataset","数据集"],["status","状态"],["last_event_time","最后事件"]]}/>
interface DatasetRun {
  dataset_id: string
  dataset_name: string
  source: string
  scenario: string
  run_id: string
  status: string
  records: number
  normalized_records: number
  failed_records: number
  mapping_rate: number
  detection_count: number
  technique_ids: string[]
  technique_count: number
  chain_count: number
  ioc_coverage?: { covered: number; total: number; rate: number | null }
  stage_coverage?: { covered: number; total: number; rate: number | null; stages: string[] }
  evidence_backtrace_rate: number
  runtime_seconds: number
  precision: number | null
  recall: number | null
  f1: number | null
  f1_reason: string
  limitations: string[]
}

export const DatasetsPage=()=> {
  const { data, meta, loading, error } = useApi<DatasetRun[]>('/api/datasets')
  const run = data?.[0]
  return <><PageHeader title="数据集实验" description="公开攻击数据集通过同一主管道导入，并只在独立 Evaluation 中对照 Ground Truth。" />
    {loading && <div className="skeleton-list" aria-label="正在加载"><span/><span/><span/></div>}
    {error && <EmptyState kind="error" title="无法读取数据集实验" detail={`${error}。系统不会用模拟数据替代失败结果。`} />}
    {!loading && !error && !run && <EmptyState title="当前没有数据集运行报告" detail={meta?.warnings[0] ?? '执行数据集 replay 后，实验结果会出现在这里。'} />}
    {run && <section className="dataset-run">
      <header className="dataset-run-head">
        <div>
          <strong>{run.dataset_name}</strong>
          <span>{run.source}</span>
          <code>{run.scenario}</code>
        </div>
        <span className={`status-pill ${run.status}`}>{run.status}</span>
      </header>
      <div className="dataset-metrics">
        <Metric label="输入事件" value={run.records} />
        <Metric label="成功标准化" value={run.normalized_records} />
        <Metric label="失败事件" value={run.failed_records} />
        <Metric label="映射率" value={pct(run.mapping_rate)} />
        <Metric label="Detection" value={run.detection_count} />
        <Metric label="ATT&CK Technique" value={run.technique_count} />
        <Metric label="AttackChain" value={run.chain_count} />
        <Metric label="Evidence 回查率" value={pct(run.evidence_backtrace_rate)} />
      </div>
      <div className="dataset-detail-grid">
        <article>
          <h2>实验结果</h2>
          <dl>
            <div><dt>Run ID</dt><dd><code>{run.run_id}</code></dd></div>
            <div><dt>IOC 覆盖</dt><dd>{coverage(run.ioc_coverage)}</dd></div>
            <div><dt>攻击阶段覆盖</dt><dd>{coverage(run.stage_coverage)}</dd></div>
            <div><dt>运行耗时</dt><dd>{run.runtime_seconds}s</dd></div>
          </dl>
        </article>
        <article>
          <h2>ATT&CK</h2>
          <div className="technique-list">{run.technique_ids?.length ? run.technique_ids.map(id => <code key={id}>{id}</code>) : <span>暂无 Technique</span>}</div>
        </article>
        <article>
          <h2>二分类指标</h2>
          <dl>
            <div><dt>Precision</dt><dd>{score(run.precision)}</dd></div>
            <div><dt>Recall</dt><dd>{score(run.recall)}</dd></div>
            <div><dt>F1</dt><dd>{score(run.f1)}</dd></div>
          </dl>
          <p>{run.f1_reason}</p>
        </article>
      </div>
      {!!run.limitations?.length && <p className="dataset-note">{run.limitations.join(' ')}</p>}
    </section>}
  </>
}

function Metric({label,value}:{label:string;value:string|number}) {
  return <div><span>{label}</span><strong>{value}</strong></div>
}

function pct(value: number | null | undefined) {
  return value == null ? 'N/A' : `${(value * 100).toFixed(1)}%`
}

function score(value: number | null | undefined) {
  return value == null ? 'N/A' : value.toFixed(3)
}

function coverage(value?: {covered:number;total:number;rate:number|null}) {
  if (!value) return 'N/A'
  return `${value.covered}/${value.total}${value.rate == null ? '' : ` · ${pct(value.rate)}`}`
}
