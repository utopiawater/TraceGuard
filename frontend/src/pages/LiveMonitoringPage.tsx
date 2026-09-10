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

type LiveDisplaySource = {
  key: string
  label: string
  status: 'waiting' | 'ingesting' | 'normal' | string
  events_received: number
  last_seen?: string | null
}

type LivePhase = {
  key: string
  label: string
  state: 'pending' | 'active' | 'done' | string
}

type LiveStatus = {
  run_id: string | null
  mode: string
  status: 'idle' | 'running' | 'completed' | string
  started_at?: string | null
  completed_at?: string | null
  elapsed_seconds: number
  sources: LiveSource[]
  display_sources: LiveDisplaySource[]
  counts: Record<string, number>
  attack_chain_stages: number
  attack_techniques: number
  network_events: number
  active_entities: number
  data_access_method: string
  phase_progress: LivePhase[]
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

const sourceStatusName: Record<string, string> = { waiting: '等待接入', ingesting: '接入中', normal: '正常' }
const sourceStatusClass: Record<string, string> = { waiting: 'pending', ingesting: 'active', normal: 'healthy' }
const metricValue = (started: boolean, value?: number) => started ? String(value ?? 0) : '—'
const metricSub = (started: boolean, text: string) => started ? text : '待启动'

function formatDuration(seconds = 0) {
  const safe = Math.max(Math.floor(seconds), 0)
  const minutes = Math.floor(safe / 60)
  const secs = safe % 60
  return `${String(minutes).padStart(2, '0')}:${String(secs).padStart(2, '0')}`
}

function TrafficSvg({ traffic }: { traffic?: LiveTraffic | null }) {
  const width = 820
  const height = 250
  const pad = { left: 36, right: 16, top: 22, bottom: 32 }
  const series = traffic?.series ?? { network: [], endpoint: [], total: [] }
  const values = [...series.network, ...series.endpoint, ...series.total]
  const max = Math.max(1, ...values)
  const count = Math.max(series.total.length, 1)
  const points = (items: number[]) => items.map((value, index) => {
    const x = pad.left + (index / Math.max(count - 1, 1)) * (width - pad.left - pad.right)
    const y = pad.top + (1 - value / max) * (height - pad.top - pad.bottom)
    return `${x.toFixed(1)},${y.toFixed(1)}`
  }).join(' ')
  const hasData = values.some(value => value > 0)
  const grid = Array.from({ length: 5 }, (_, index) => pad.top + index * ((height - pad.top - pad.bottom) / 4))
  return <svg className="live-traffic-svg" viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" aria-hidden="true">
    {grid.map(y => <line key={y} x1={pad.left} x2={width - pad.right} y1={y} y2={y} />)}
    {traffic?.categories.filter((_, index) => index % 4 === 0).map((label, index) => {
      const x = pad.left + ((index * 4) / Math.max(count - 1, 1)) * (width - pad.left - pad.right)
      return <text key={label} x={x} y={height - 9}>{label}</text>
    })}
    {hasData ? <>
      <polyline className="network" points={points(series.network)} />
      <polyline className="endpoint" points={points(series.endpoint)} />
      <polyline className="total" points={points(series.total)} />
    </> : <text className="empty" x={width / 2} y={height / 2}>等待实时事件进入趋势窗口</text>}
  </svg>
}

export function LiveMonitoringPage() {
  const { currentRunId, currentRun, setCurrentRunId, runScopedPath } = useAnalysis()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [tick, setTick] = useState(0)
  const chartRef = useRef<HTMLDivElement>(null)
  const chartInstance = useRef<echarts.ECharts | null>(null)
  const selectedLiveRunId = currentRun?.mode === 'live' ? currentRunId : null
  const query = new URLSearchParams()
  if (selectedLiveRunId) query.set('run_id', selectedLiveRunId)
  query.set('t', String(tick))
  const endpoint = `/api/v1/live/status?${query.toString()}`
  const { data } = useApi<LiveStatus>(endpoint)
  const live = data ?? null
  const running = live?.status === 'running'
  const trafficRunId = live?.run_id ?? selectedLiveRunId
  const trafficQuery = new URLSearchParams()
  if (trafficRunId) trafficQuery.set('run_id', trafficRunId)
  trafficQuery.set('t', String(tick))
  const { data: traffic } = useApi<LiveTraffic>(trafficRunId ? `/api/v1/live/traffic?${trafficQuery.toString()}` : '/api/v1/live/traffic?run_id=__none__')
  const counts = live?.counts ?? {}
  const hasLiveTask = Boolean(live?.run_id)
  const activeDisplaySources = live?.display_sources.filter(source => source.status !== 'waiting').length ?? 0
  const totalDisplaySources = live?.display_sources.length ?? 5

  useEffect(() => {
    const id = window.setInterval(() => setTick(value => value + 1), running ? 1000 : 3000)
    return () => window.clearInterval(id)
  }, [running])

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

  return <><PageHeader title="实时监测" description="启动统一实时任务，证据持续进入同一条分析流水线并形成安全事件、告警与攻击关联。" aside={live?.run_id ? <span className="freshness"><RadioTower size={15}/>{live.run_id}</span> : undefined} />
    <section className="live-command-bar panel">
      <div>
        <span className={`status-pill ${running ? 'running' : live?.status === 'completed' ? 'succeeded' : 'partial'}`}>{running ? 'RUNNING' : live?.status === 'completed' ? 'COMPLETED' : 'IDLE'}</span>
        <code>{live?.run_id ?? '尚未启动实时监测'}</code>
        <span className="live-duration">监测时长 {hasLiveTask ? formatDuration(live?.elapsed_seconds) : '--:--'}</span>
      </div>
      <div className="agent-actions">
        <button className="primary-action" onClick={start} disabled={busy || running}><Play size={15}/>开始实时监测</button>
        <button className="secondary-action" onClick={stop} disabled={busy || !live?.run_id || !running}><PauseCircle size={15}/>停止实时监测</button>
      </div>
    </section>
    {error && <EmptyState kind="error" title="实时监测操作失败" detail={error} />}
    <section className="metric-strip">
      <div><DatabaseZap/><span>安全事件</span><strong>{metricValue(hasLiveTask, live?.counts?.normalized_events)}</strong><small>{metricSub(hasLiveTask, `${live?.counts?.raw_events ?? 0} 条原始记录`)}</small></div>
      <div><RadioTower/><span>当前 EPS</span><strong>{metricValue(hasLiveTask, traffic?.eps)}</strong><small>{metricSub(hasLiveTask, '最近 90 秒')}</small></div>
      <div><ShieldAlert/><span>安全告警</span><strong>{metricValue(hasLiveTask, live?.counts?.detections)}</strong><small>{metricSub(hasLiveTask, '检测结果')}</small></div>
      <div><ServerCog/><span>活跃实体</span><strong>{metricValue(hasLiveTask, live?.active_entities)}</strong><small>{metricSub(hasLiveTask, `${activeDisplaySources}/${totalDisplaySources} 类数据源`)}</small></div>
      <div><CheckCircle2/><span>ATT&CK 技术</span><strong>{metricValue(hasLiveTask, live?.attack_techniques)}</strong><small>{metricSub(hasLiveTask, '已映射')}</small></div>
      <div><RadioTower/><span>网络事件</span><strong>{metricValue(hasLiveTask, live?.network_events)}</strong><small>{metricSub(hasLiveTask, 'flow / web / c2')}</small></div>
    </section>
    {!live?.run_id && <EmptyState title="尚未启动实时监测" detail="启动后，证据会按当前时间轴逐批进入分析流水线；切换到其他页面后处理仍会继续。" />}
    {live?.run_id && <section className="live-grid">
      <section className="panel live-traffic-panel">
        <div className="panel-title"><h2>实时事件速率 / 流量趋势</h2><span>{traffic?.eps ?? 0} EPS · 最近 90 秒</span></div>
        <div className="live-traffic-chart" role="img" aria-label="当前实时监测任务的 Network、Endpoint 与 Total 事件速率趋势图">
          <div className="live-traffic-echarts" ref={chartRef} />
          <TrafficSvg traffic={traffic} />
        </div>
        <div className="live-traffic-summary">
          <div><span>Network</span><strong>{traffic?.series.network.reduce((sum, value) => sum + value, 0) ?? 0}</strong></div>
          <div><span>Endpoint</span><strong>{traffic?.series.endpoint.reduce((sum, value) => sum + value, 0) ?? 0}</strong></div>
          <div><span>Total</span><strong>{traffic?.series.total.reduce((sum, value) => sum + value, 0) ?? 0}</strong></div>
        </div>
      </section>
      <section className="panel live-events-panel">
        <div className="panel-title"><h2>最近事件滚动</h2><span>{running ? '随新增事件更新' : '最终快照'}</span></div>
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
        <div className="panel-title"><h2>数据源接入状态</h2><span>{running ? '1 秒刷新' : live.status === 'completed' ? '最终状态' : '当前未运行'}</span></div>
        {live.display_sources.length ? live.display_sources.map(source => <div className="source-row live-source-row" key={source.key}>
          <span className={`status-dot ${source.status === 'waiting' ? 'offline' : ''}`} />
          <div>
            <div className="source-row-primary"><strong>{source.label}</strong><span className={`source-status-pill ${sourceStatusClass[source.status] ?? 'neutral'}`}>{sourceStatusName[source.status] ?? source.status}</span></div>
            <div className="source-row-meta"><span>{source.events_received ? `${source.events_received} 条原始记录` : '等待证据进入'}</span><time>{source.last_seen ? new Date(source.last_seen).toLocaleString('zh-CN') : '尚未接入'}</time></div>
          </div>
        </div>) : <p className="inline-empty">启动后将显示业务数据源接入状态。</p>}
      </section>
      <section className="panel live-next-steps">
        <div className="panel-title"><h2>当前监测任务</h2><span>{live.status}</span></div>
        <div className="live-progress-list">
          {live.phase_progress.map(stage => <span key={stage.key} className={`live-progress-step ${stage.state}`}>{stage.label}</span>)}
        </div>
        <dl>
          <div><dt>Run ID</dt><dd><code>{live.run_id}</code></dd></div>
          <div><dt>接入方式</dt><dd>{live.data_access_method}</dd></div>
          <div><dt>攻击链阶段</dt><dd>{live.attack_chain_stages}</dd></div>
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
