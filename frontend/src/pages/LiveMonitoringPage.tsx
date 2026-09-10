import { CheckCircle2, DatabaseZap, PauseCircle, Play, RadioTower, ServerCog, ShieldAlert } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { apiPost } from '../api/client'
import { EmptyState } from '../components/EmptyState'
import { PageHeader } from '../components/PageHeader'
import { useAnalysis } from '../context/AnalysisContext'
import { useApi } from '../hooks/useApi'

type LiveSource = {
  source_id: string
  source_type: string
  status: 'online' | 'offline'
  last_seen?: string | null
  events_received: number
  last_error?: string | null
}

type LiveStatus = {
  run_id: string | null
  mode: string
  status: 'idle' | 'running' | 'completed' | string
  started_at?: string | null
  completed_at?: string | null
  sources: LiveSource[]
  counts: Record<string, number>
  attack_chain_stages: number
  processed?: number
}

const sourceTypeName: Record<string, string> = {
  replay: 'Replay',
  wazuh: 'Wazuh Manager',
  zeek: 'Zeek Sensor',
}

export function LiveMonitoringPage() {
  const { currentRunId, setCurrentRunId, runScopedPath } = useAnalysis()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [tick, setTick] = useState(0)
  const query = new URLSearchParams()
  if (currentRunId) query.set('run_id', currentRunId)
  query.set('t', String(tick))
  const endpoint = `/api/v1/live/status?${query.toString()}`
  const { data } = useApi<LiveStatus>(endpoint)
  const live = data ?? null
  const running = live?.status === 'running'
  const online = useMemo(() => live?.sources.filter(source => source.status === 'online').length ?? 0, [live])

  useEffect(() => {
    if (!running) return
    const id = window.setInterval(() => setTick(value => value + 1), 2000)
    return () => window.clearInterval(id)
  }, [running])

  const start = async () => {
    setBusy(true); setError(null)
    try {
      const response = await apiPost<LiveStatus>('/api/v1/live/start', {})
      setCurrentRunId(response.data.run_id)
      window.dispatchEvent(new Event('traceguard:runs-updated'))
      setTick(value => value + 1)
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : '启动实时监测失败')
    } finally {
      setBusy(false)
    }
  }

  const stop = async () => {
    if (!live?.run_id) return
    setBusy(true); setError(null)
    try {
      await apiPost<LiveStatus>('/api/v1/live/stop', { run_id: live.run_id })
      window.dispatchEvent(new Event('traceguard:runs-updated'))
      setTick(value => value + 1)
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : '停止实时监测失败')
    } finally {
      setBusy(false)
    }
  }

  return <><PageHeader title="实时监测" description="启动一个 mode=live 的统一 run，Wazuh、Zeek 或 HTTP 降级入口的新增事件都会进入同一条分析流水线。" aside={live?.run_id ? <span className="freshness"><RadioTower size={15}/>{live.run_id}</span> : undefined} />
    <section className="live-command-bar panel">
      <div>
        <span className={`status-pill ${running ? 'running' : live?.status === 'completed' ? 'succeeded' : 'partial'}`}>{running ? 'RUNNING' : live?.status === 'completed' ? 'COMPLETED' : 'IDLE'}</span>
        <code>{live?.run_id ?? '尚未启动 live run'}</code>
      </div>
      <div className="agent-actions">
        <button className="primary-action" onClick={start} disabled={busy || running}><Play size={15}/>开始实时监测</button>
        <button className="secondary-action" onClick={stop} disabled={busy || !live?.run_id || !running}><PauseCircle size={15}/>停止实时监测</button>
      </div>
    </section>
    {error && <EmptyState kind="error" title="实时监测操作失败" detail={error} />}
    <section className="metric-strip">
      <div><ServerCog/><span>ONLINE Sources</span><strong>{online}/{live?.sources.length ?? 0}</strong></div>
      <div><DatabaseZap/><span>Raw/Event</span><strong>{live?.counts?.raw_events ?? 0}/{live?.counts?.normalized_events ?? 0}</strong></div>
      <div><ShieldAlert/><span>Detection</span><strong>{live?.counts?.detections ?? 0}</strong></div>
      <div><CheckCircle2/><span>AttackChain 阶段</span><strong>{live?.attack_chain_stages ?? 0}</strong></div>
    </section>
    {!live?.run_id && <EmptyState title="尚未启动实时监测" detail="启动后，Worker 会按 micro-batch 读取配置的数据源；单个 source 离线不会让整个 live run 失败。" />}
    {live?.run_id && <section className="live-grid">
      <section className="panel source-health">
        <div className="panel-title"><h2>实时 Source 状态</h2><span>{running ? '2 秒轮询刷新' : '当前未运行'}</span></div>
        {live.sources.length ? live.sources.map(source => <div className="source-row live-source-row" key={source.source_id}>
          <span className={`status-dot ${source.status === 'offline' ? 'offline' : ''}`} />
          <div>
            <div className="source-row-primary"><strong>{source.source_id}</strong><span className={`source-status-pill ${source.status === 'online' ? 'healthy' : 'error'}`}>{source.status.toUpperCase()}</span></div>
            <div className="source-row-meta"><span>{sourceTypeName[source.source_type] ?? source.source_type} · {source.events_received} 条 Raw</span><time>{source.last_seen ? new Date(source.last_seen).toLocaleString('zh-CN') : '尚未收到'}</time></div>
            {source.last_error && <small className="live-source-error">{source.last_error}</small>}
          </div>
        </div>) : <p className="inline-empty">未配置实时数据源；仍可通过 HTTP live ingest 写入这个 run。</p>}
      </section>
      <section className="panel live-next-steps">
        <div className="panel-title"><h2>当前 Live Run</h2><span>{live.status}</span></div>
        <dl>
          <div><dt>Run ID</dt><dd><code>{live.run_id}</code></dd></div>
          <div><dt>Started</dt><dd>{live.started_at ? new Date(live.started_at).toLocaleString('zh-CN') : '-'}</dd></div>
          <div><dt>Completed</dt><dd>{live.completed_at ? new Date(live.completed_at).toLocaleString('zh-CN') : '-'}</dd></div>
        </dl>
        <div className="analysis-actions">
          <Link className="secondary-action" to={runScopedPath('/events')}><DatabaseZap size={15}/>查看 Events</Link>
          <Link className="secondary-action" to={runScopedPath('/incidents')}><ShieldAlert size={15}/>查看 Detection</Link>
          <Link className="secondary-action" to={runScopedPath('/chains')}><CheckCircle2 size={15}/>查看 AttackChain</Link>
        </div>
      </section>
    </section>}
  </>
}
