import * as echarts from 'echarts/core'
import { LineChart as EchartsLineChart } from 'echarts/charts'
import { GridComponent, LegendComponent, TooltipComponent } from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'
import { CheckCircle2, Clock3, DatabaseZap, PauseCircle, Play, RadioTower, ServerCog, ShieldAlert } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { apiPost } from '../api/client'
import { EmptyState } from '../components/EmptyState'
import { PageHeader } from '../components/PageHeader'
import { useAnalysis } from '../context/AnalysisContext'
import { useApi } from '../hooks/useApi'

echarts.use([EchartsLineChart, GridComponent, LegendComponent, TooltipComponent, CanvasRenderer])

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

type LiveTraffic = {
  run_id: string
  categories: string[]
  series: {
    network: number[]
    endpoint: number[]
    total: number[]
  }
  eps: number
  recent_events: Array<{
    event_id: string
    time: string
    source: string
    src?: string | null
    dst?: string | null
    action: string
    severity: string
    message?: string | null
  }>
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
  const chartRef = useRef<HTMLDivElement>(null)
  const chartInstance = useRef<echarts.ECharts | null>(null)
  const query = new URLSearchParams()
  if (currentRunId) query.set('run_id', currentRunId)
  query.set('t', String(tick))
  const endpoint = `/api/v1/live/status?${query.toString()}`
  const { data } = useApi<LiveStatus>(endpoint)
  const live = data ?? null
  const running = live?.status === 'running'
  const trafficRunId = live?.run_id ?? currentRunId
  const trafficQuery = new URLSearchParams()
  if (trafficRunId) trafficQuery.set('run_id', trafficRunId)
  trafficQuery.set('t', String(tick))
  const { data: traffic } = useApi<LiveTraffic>(trafficRunId ? `/api/v1/live/traffic?${trafficQuery.toString()}` : '/api/v1/live/traffic?run_id=__none__')
  const online = useMemo(() => live?.sources.filter(source => source.status === 'online').length ?? 0, [live])

  useEffect(() => {
    if (!running || !live?.run_id) return
    const runId = live.run_id
    let cancelled = false
    const poll = async () => {
      try {
        await apiPost<LiveStatus>(`/api/v1/live/poll?run_id=${encodeURIComponent(runId)}`)
      } catch {
        // Source errors are displayed in the status panel; keep the refresh loop alive.
      } finally {
        if (!cancelled) setTick(value => value + 1)
      }
    }
    poll()
    const id = window.setInterval(poll, 2000)
    return () => {
      cancelled = true
      window.clearInterval(id)
    }
  }, [running, live?.run_id])

  useEffect(() => {
    if (!chartRef.current) return
    chartInstance.current = echarts.init(chartRef.current)
    const resize = () => chartInstance.current?.resize()
    window.addEventListener('resize', resize)
    return () => {
      window.removeEventListener('resize', resize)
      chartInstance.current?.dispose()
      chartInstance.current = null
    }
  }, [])

  useEffect(() => {
    if (!chartInstance.current || !traffic) return
    chartInstance.current.setOption({
      animationDuration: 260,
      animationEasing: 'quarticOut',
      color: ['#249F95', '#EA580C', '#334155'],
      grid: { left: 38, right: 18, top: 30, bottom: 38 },
      legend: { top: 0, right: 10, itemWidth: 13, itemHeight: 8, textStyle: { color: '#536173', fontSize: 11 } },
      tooltip: { trigger: 'axis' },
      xAxis: { type: 'category', boundaryGap: false, data: traffic.categories, axisLine: { lineStyle: { color: '#E7ECF3' } }, axisLabel: { color: '#536173', fontSize: 11 } },
      yAxis: { type: 'value', minInterval: 1, splitLine: { lineStyle: { color: '#EEF1F5' } }, axisLabel: { color: '#536173', fontSize: 11 } },
      series: [
        { name: 'Network', type: 'line', smooth: true, showSymbol: false, data: traffic.series.network, lineStyle: { width: 2 }, areaStyle: { opacity: 0.14 } },
        { name: 'Endpoint', type: 'line', smooth: true, showSymbol: false, data: traffic.series.endpoint, lineStyle: { width: 2 }, areaStyle: { opacity: 0.1 } },
        { name: 'Total', type: 'line', smooth: true, showSymbol: false, data: traffic.series.total, lineStyle: { width: 2, type: 'dashed' } },
      ],
    })
  }, [traffic])

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
      <section className="panel live-traffic-panel">
        <div className="panel-title"><h2>实时事件速率 / 流量趋势</h2><span>{traffic?.eps ?? 0} EPS · 最近 90 秒</span></div>
        <div className="live-traffic-chart" ref={chartRef} role="img" aria-label="当前 live run 的 Network、Endpoint 与 Total 事件速率趋势图" />
        <div className="live-traffic-summary">
          <div><span>Network</span><strong>{traffic?.series.network.reduce((sum, value) => sum + value, 0) ?? 0}</strong></div>
          <div><span>Endpoint</span><strong>{traffic?.series.endpoint.reduce((sum, value) => sum + value, 0) ?? 0}</strong></div>
          <div><span>Total</span><strong>{traffic?.series.total.reduce((sum, value) => sum + value, 0) ?? 0}</strong></div>
        </div>
      </section>
      <section className="panel live-events-panel">
        <div className="panel-title"><h2>最近事件滚动</h2><span>{running ? '随 micro-batch 更新' : '最终快照'}</span></div>
        {traffic?.recent_events.length ? <div className="live-event-list">
          {traffic.recent_events.map(event => <article key={event.event_id} className="live-event-row">
            <time><Clock3 size={13}/>{new Date(event.time).toLocaleTimeString('zh-CN')}</time>
            <strong>{event.src ?? event.source}<span>→</span>{event.dst ?? 'observed'}</strong>
            <small>{event.source} · {event.action}</small>
            <span className={`status-pill ${event.severity === 'high' || event.severity === 'critical' ? 'failed' : event.severity === 'medium' ? 'partial' : 'running'}`}>{event.severity}</span>
          </article>)}
        </div> : <p className="inline-empty">当前 run 还没有进入主管道的事件。</p>}
      </section>
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
