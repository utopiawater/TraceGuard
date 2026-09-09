import * as echarts from 'echarts/core'
import { BarChart } from 'echarts/charts'
import { GridComponent, TooltipComponent } from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'
import { AlertTriangle, CheckCircle2, GitBranch, RadioTower } from 'lucide-react'
import { useEffect, useRef } from 'react'
import { useSearchParams } from 'react-router-dom'
import { EmptyState } from '../components/EmptyState'
import { PageHeader } from '../components/PageHeader'
import { useApi } from '../hooks/useApi'
import { chainStatusName, pct, sourceDisplayName, sourceStatusName, stageName } from '../lib/display'

interface RecentChain { chain_id:string;title:string;score:number;status:string;technique_ids:string[];entity_ids?:string[];evidence_ids?:string[];sources?:string[];steps?:{stage:string}[] }
interface Dashboard { counts: Record<string,number>; sources: {source:string;event_count:number;last_event_time:string;status:string}[]; recent_chains: RecentChain[]; time_quality:{synced:number;other:number} }
interface SystemHealth { status:string; mode:'live'|'replay'|'snapshot' }

echarts.use([BarChart, GridComponent, TooltipComponent, CanvasRenderer])

const sourceStatusClass = (status: string) => {
  if (['ingested', 'healthy', 'normal'].includes(status)) return 'healthy'
  if (['delayed', 'stale'].includes(status)) return 'delayed'
  if (['unhealthy', 'error', 'failed'].includes(status)) return 'error'
  return 'neutral'
}

export function DashboardPage() {
  const [params] = useSearchParams()
  const runId = params.get('run_id')
  const { data, error, loading } = useApi<Dashboard>(`/api/dashboard${runId ? `?run_id=${encodeURIComponent(runId)}` : ''}`)
  const { data: health } = useApi<SystemHealth>('/api/system/health')
  const chartRef = useRef<HTMLDivElement>(null)
  const pipelineStatusText = health?.mode === 'replay'
    ? 'Replay 数据已接入分析管道'
    : health?.mode === 'live'
      ? '实时数据已接入分析管道'
      : '数据已接入标准分析管道'
  useEffect(() => {
    if (!chartRef.current || !data?.sources.length) return
    const chart = echarts.init(chartRef.current)
    chart.setOption({ animationDuration: 180, grid:{left:38,right:12,top:18,bottom:36}, xAxis:{type:'category',data:data.sources.map(s=>sourceDisplayName[s.source] ?? s.source),axisLine:{lineStyle:{color:'#E7ECF3'}},axisLabel:{fontSize:12,color:'oklch(0.38 0.018 250)',fontWeight:400,interval:0,rotate:0}}, yAxis:{type:'value',splitLine:{lineStyle:{color:'#E7ECF3'}}}, tooltip:{trigger:'axis'}, series:[{type:'bar',data:data.sources.map(s=>s.event_count),barWidth:24,itemStyle:{color:'#43BFB3',borderRadius:[5,5,0,0]},emphasis:{itemStyle:{color:'#249F95'}}}] })
    const resize = () => chart.resize(); addEventListener('resize',resize)
    return () => { removeEventListener('resize',resize); chart.dispose() }
  }, [data])
  return <><PageHeader title="安全态势总览" description="先确认数据是否可信，再进入当前最重要的攻击链。" aside={data ? <span className="freshness"><CheckCircle2 size={15}/> {runId ? `任务 ${runId}` : pipelineStatusText}</span> : undefined} />
    {loading && <div className="skeleton-hero" />}{error && <EmptyState kind="error" title="总览读取失败" detail={error} />}
    {data && <>
      <section className="metric-strip"><div><RadioTower/><span title="当前数据库中已经进入主管道的来源类型数。">已接入来源</span><strong>{data.sources.length}</strong></div><div><AlertTriangle/><span title="由确定性规则或统计检测产生，均应能回查 Evidence。">确定性检测</span><strong>{data.counts.detections}</strong></div><div><GitBranch/><span title="AttackChain 是候选关联链，不会自动等同于已确认事故。">候选攻击链</span><strong>{data.counts.attack_chains}</strong></div><div><CheckCircle2/><span title="事件自身 time_quality 为 synced 的数量；不等同于现场 NTP 已验收。">时间质量 synced</span><strong>{data.time_quality.synced}</strong></div></section>
      {data.sources.length === 0 ? <EmptyState title="尚未收到安全事件" detail="运行场景回放或接入 Sysmon / Zeek 后，总览才会显示真实结果。" /> : <div className="dashboard-layout"><section className="panel chart-panel"><div className="panel-title"><h2>来源事件量</h2><span>当前分析窗口</span></div><div ref={chartRef} className="chart" role="img" aria-label="各数据来源事件数量柱状图" /></section><section className="panel source-health"><div className="panel-title"><h2>数据源接入状态</h2><span>{data.sources.length} 个来源</span></div>{data.sources.map(source=><div className="source-row" key={source.source}><span className="status-dot"/><div><div className="source-row-primary"><strong>{sourceDisplayName[source.source] ?? source.source}</strong><span className={`source-status-pill ${sourceStatusClass(source.status)}`}>{sourceStatusName[source.status] ?? source.status}</span></div><div className="source-row-meta"><span>{source.event_count} 条事件</span><time>{new Date(source.last_event_time).toLocaleTimeString('zh-CN')}</time></div></div></div>)}</section></div>}
      <section className="chain-list"><div className="section-heading"><h2>最近攻击链</h2><span>候选链不会自动标记为已确认</span></div>{data.recent_chains.length ? data.recent_chains.map(chain=>{const stages=[...(new Set(chain.steps?.map(step=>stageName[step.stage]??step.stage).filter(Boolean)??[]))];const facts=[typeof chain.evidence_ids?.length==='number'?`${chain.evidence_ids.length} 条证据`:null,typeof chain.entity_ids?.length==='number'?`${chain.entity_ids.length} 个实体`:null].filter(Boolean);const sources=chain.sources?.map(source=>sourceDisplayName[source]??source).join(' / ');return <a className="chain-card" href={`/chains?chain=${chain.chain_id}`} key={chain.chain_id}><span className="chain-score" title="链可信评分：由步骤检测置信度和 ATT&CK 映射置信度综合得到。"><strong>{pct(chain.score)}</strong><small>链可信评分</small></span><div className="chain-card-main"><div className="chain-card-head"><strong>{chain.title}</strong><span className={`badge ${chain.status==='candidate'?'candidate':'neutral'}`}>{chainStatusName[chain.status]??chain.status}</span></div>{stages.length>0&&<small className="chain-stage-path">{stages.join(' → ')}</small>}<small className="chain-technique-path">{chain.technique_ids.join(' → ')}</small>{(facts.length>0||sources)&&<small className="chain-card-meta">{facts.join(' · ')}{facts.length>0&&sources?' · ':''}{sources}</small>}</div></a>}) : <p className="inline-empty">暂无攻击链。检测结果形成可验证关联后会出现在这里。</p>}</section>
    </>}
  </>
}
