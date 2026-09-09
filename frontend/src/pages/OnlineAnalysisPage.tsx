import { AlertCircle, Bot, CheckCircle2, FileSearch, FileUp, GitBranch, Network, Play, ShieldCheck } from 'lucide-react'
import { DragEvent, useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { apiPost, apiUpload } from '../api/client'
import { EmptyState } from '../components/EmptyState'
import { PageHeader } from '../components/PageHeader'
import { useApi } from '../hooks/useApi'

type Stage = { key:string; label:string; status:'pending'|'running'|'completed' }
type FoundFile = { path:string; kind:string; source_kind?:string|null; dataset?:string|null; records:number; reason:string; evaluation_only:boolean; parser_status:string }
type AnalysisTask = {
  task_id:string
  status:string
  current_stage:string
  stages:Stage[]
  created_at:string
  updated_at:string
  upload:{filename:string;size:number}
  identification:{found:FoundFile[];unsupported:{path:string;reason:string}[];warnings:string[]}
  result?:null|Record<string, unknown>
  error?:string
  ground_truth?:{files:string[];used_for_detection:boolean;comparison?:unknown}
}

export function OnlineAnalysisPage() {
  const { data: tasks } = useApi<AnalysisTask[]>('/api/v1/analysis/tasks')
  const [task, setTask] = useState<AnalysisTask | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [dragging, setDragging] = useState(false)
  const active = task ?? tasks?.[0] ?? null
  const runParam = active ? `run_id=${encodeURIComponent(active.task_id)}` : ''

  useEffect(() => {
    if (!active || !['running', 'uploaded', 'identified'].includes(active.status)) return
    const id = window.setInterval(async () => {
      try {
        const next = await fetch(`/api/v1/analysis/tasks/${active.task_id}`).then(r => r.json())
        setTask(next.data)
      } catch {
        return
      }
    }, 1800)
    return () => window.clearInterval(id)
  }, [active?.task_id, active?.status])

  const foundKinds = useMemo(() => [...new Set(active?.identification?.found.filter(item => !item.evaluation_only).map(item => item.kind) ?? [])], [active])

  const upload = async (file: File) => {
    setBusy(true); setError(null)
    try {
      const response = await apiUpload<AnalysisTask>('/api/v1/analysis/upload', file)
      setTask(response.data)
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : '上传失败')
    } finally {
      setBusy(false); setDragging(false)
    }
  }

  const start = async () => {
    if (!active) return
    setBusy(true); setError(null)
    try {
      const response = await apiPost<AnalysisTask>(`/api/v1/analysis/tasks/${active.task_id}/start`)
      setTask(response.data)
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : '启动分析失败')
    } finally {
      setBusy(false)
    }
  }

  const onDrop = (event: DragEvent<HTMLLabelElement>) => {
    event.preventDefault()
    const file = event.dataTransfer.files.item(0)
    if (file) void upload(file)
  }

  return <><PageHeader title="在线分析" description="上传日志、PCAP、多源攻击记录包或标准数据集，TraceGuard 会识别文件并复用现有主管道完成分析。" aside={active ? <span className="freshness"><FileSearch size={15}/> {active.task_id}</span> : undefined} />
    <section className="analysis-workspace">
      <label className={`upload-zone ${dragging ? 'dragging' : ''}`} onDragOver={event=>{event.preventDefault();setDragging(true)}} onDragLeave={()=>setDragging(false)} onDrop={onDrop}>
        <FileUp size={34} />
        <strong>拖拽文件到这里，或点击选择</strong>
        <span>.log .json .jsonl .csv .pcap .zip .tar.gz</span>
        <input type="file" accept=".log,.json,.jsonl,.csv,.pcap,.zip,.gz" onChange={event=>{const file=event.target.files?.[0]; if(file) void upload(file)}} disabled={busy} />
      </label>
      {error && <EmptyState kind="error" title="在线分析失败" detail={error} />}
      {active && <section className="analysis-panel">
        <header>
          <div><span className="eyebrow">当前任务</span><h2>{active.upload.filename}</h2><code>{active.task_id}</code></div>
          <span className={`status-pill ${active.status}`}>{active.status}</span>
        </header>
        <div className="analysis-discovery">
          <strong>已发现</strong>
          <div>{foundKinds.length ? foundKinds.map(kind => <span key={kind}><CheckCircle2 size={14}/>{kind}</span>) : <span>等待识别结果</span>}</div>
        </div>
        {!!active.identification.warnings.length && <p className="analysis-warning"><AlertCircle size={15}/>{active.identification.warnings.join(' ')}</p>}
        <div className="stage-list">{active.stages.map(stage => <div key={stage.key} className={stage.status}><span /><strong>{stage.label}</strong><small>{stage.status}</small></div>)}</div>
        <div className="table-wrap compact-table"><table><thead><tr><th>文件</th><th>类型</th><th>记录</th><th>Parser/Normalizer</th><th>状态</th></tr></thead><tbody>{active.identification.found.map(item => <tr key={item.path}><td>{item.path}</td><td>{item.kind}</td><td>{item.records}</td><td>{item.evaluation_only ? 'Evaluation only' : `${item.source_kind ?? '-'} / ${item.dataset ?? '-'}`}</td><td>{item.parser_status}</td></tr>)}</tbody></table></div>
        {active.status === 'identified' && <button className="primary-action analysis-start" onClick={start} disabled={busy}><Play size={15}/>开始分析</button>}
        {active.error && <p className="analysis-warning"><AlertCircle size={15}/>{active.error}</p>}
        {active.result && <AnalysisResult task={active} runParam={runParam} />}
      </section>}
    </section>
  </>
}

function AnalysisResult({task, runParam}:{task:AnalysisTask;runParam:string}) {
  const result = task.result ?? {}
  const metrics: [string, unknown][] = [
    ['解析文件', result.parsed_files], ['原始记录', result.raw_records], ['标准化事件', result.normalized_events],
    ['检测事件', result.detections], ['高危事件', result.high_risk_events], ['实体', result.entities],
    ['攻击链', result.attack_chains], ['ATT&CK Techniques', result.attack_techniques], ['网络事件', result.network_events],
  ]
  return <section className="analysis-result">
    <div className="dataset-metrics">{metrics.map(([label,value]) => <div key={label}><span>{label}</span><strong>{String(value ?? 0)}</strong></div>)}</div>
    <div className="analysis-actions">
      <Link className="secondary-action" to={`/incidents?${runParam}`}><ShieldCheck size={15}/>查看攻击事件</Link>
      <Link className="secondary-action" to={`/chains?${runParam}`}><GitBranch size={15}/>查看攻击链</Link>
      <Link className="secondary-action" to={`/hosts?${runParam}`}><FileSearch size={15}/>主机行为</Link>
      <Link className="secondary-action" to={`/network?${runParam}`}><Network size={15}/>网络流量</Link>
      <Link className="secondary-action" to={`/attack?${runParam}`}><ShieldCheck size={15}/>ATT&CK分析</Link>
      <Link className="secondary-action" to={`/agents?${runParam}`}><Bot size={15}/>启动Agent调查</Link>
      <Link className="secondary-action" to={`/reports?${runParam}`}><FileSearch size={15}/>生成报告</Link>
    </div>
    <section className="ground-truth-note">
      <h2>Ground Truth 对比</h2>
      <p>Ground Truth、labels、attack_timeline.json、attack_graph.json 与 attack_steps.md 仅用于 Evaluation，对本次 Detection、Correlation、AttackChain 不作为输入。</p>
    </section>
  </section>
}
