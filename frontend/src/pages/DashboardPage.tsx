import * as echarts from 'echarts/core'
import { BarChart } from 'echarts/charts'
import { GridComponent, TooltipComponent } from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'
import { AlertTriangle, CheckCircle2, GitBranch, RadioTower } from 'lucide-react'
import { useEffect, useRef } from 'react'
import { EmptyState } from '../components/EmptyState'
import { PageHeader } from '../components/PageHeader'
import { useApi } from '../hooks/useApi'

interface RecentChain { chain_id:string;title:string;score:number;status:string;technique_ids:string[];entity_ids?:string[];evidence_ids?:string[];sources?:string[];steps?:{stage:string}[] }
interface Dashboard { counts: Record<string,number>; sources: {source:string;event_count:number;last_event_time:string;status:string}[]; recent_chains: RecentChain[]; time_quality:{synced:number;other:number} }
interface SystemHealth { status:string; mode:'live'|'replay'|'snapshot' }

echarts.use([BarChart, GridComponent, TooltipComponent, CanvasRenderer])

const sourceDisplayName: Record<string, string> = {
  windows_security: 'Windows Security',
  sysmon: 'Sysmon',
  zeek: 'Zeek',
  wazuh: 'Wazuh',
  auditd: 'Auditd',
}

const sourceStatusText: Record<string, string> = {
  healthy: '正常',
  normal: '正常',
  delayed: '延迟',
  stale: '延迟',
  unhealthy: '异常',
  error: '异常',
  failed: '异常',
}

const sourceStatusClass = (status: string) => {
  if (['healthy', 'normal'].includes(status)) return 'healthy'
  if (['delayed', 'stale'].includes(status)) return 'delayed'
  if (['unhealthy', 'error', 'failed'].includes(status)) return 'error'
  return 'neutral'
}

const stageDisplayName: Record<string, string> = {
  initial_access: '初始访问',
  execution: '执行',
  persistence: '持久化',
  privilege_escalation: '权限提升',
  credential_access: '凭证访问',
  discovery: '发现',
  lateral_movement: '横向移动',
  collection: '收集',
  command_and_control: 'C2',
  exfiltration: '外传',
}

const chainStatusText: Record<string, string> = {
  candidate: '候选',
  confirmed: '已确认',
  dismissed: '已排除',
}

export function DashboardPage() {
  const { data, error, loading } = useApi<Dashboard>('/api/dashboard')
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
  return <><PageHeader title="安全态势总览" description="先确认数据是否可信，再进入当前最重要的攻击链。" aside={data ? <span className="freshness"><CheckCircle2 size={15}/> {pipelineStatusText}</span> : undefined} />
    {loading && <div className="skeleton-hero" />}{error && <EmptyState kind="error" title="总览读取失败" detail={error} />}
    {data && <>
      <section className="metric-strip"><div><RadioTower/><span>已接入来源</span><strong>{data.sources.length}</strong></div><div><AlertTriangle/><span>确定性检测</span><strong>{data.counts.detections}</strong></div><div><GitBranch/><span>候选攻击链</span><strong>{data.counts.attack_chains}</strong></div><div><CheckCircle2/><span>时间同步事件</span><strong>{data.time_quality.synced}</strong></div></section>
      {data.sources.length === 0 ? <EmptyState title="尚未收到安全事件" detail="运行场景回放或接入 Sysmon / Zeek 后，总览才会显示真实结果。" /> : <div className="dashboard-layout"><section className="panel chart-panel"><div className="panel-title"><h2>来源事件量</h2><span>当前分析窗口</span></div><div ref={chartRef} className="chart" role="img" aria-label="各数据来源事件数量柱状图" /></section><section className="panel source-health"><div className="panel-title"><h2>数据源健康</h2><span>{data.sources.length} 个来源</span></div>{data.sources.map(source=><div className="source-row" key={source.source}><span className="status-dot"/><div><div className="source-row-primary"><strong>{sourceDisplayName[source.source] ?? source.source}</strong><span className={`source-status-pill ${sourceStatusClass(source.status)}`}>{sourceStatusText[source.status] ?? source.status}</span></div><div className="source-row-meta"><span>{source.event_count} 条事件</span><time>{new Date(source.last_event_time).toLocaleTimeString('zh-CN')}</time></div></div></div>)}</section></div>}
      <section className="chain-list"><div className="section-heading"><h2>最近攻击链</h2><span>候选链不会自动标记为已确认</span></div>{data.recent_chains.length ? data.recent_chains.map(chain=>{const stages=[...(new Set(chain.steps?.map(step=>stageDisplayName[step.stage]??step.stage).filter(Boolean)??[]))];const facts=[typeof chain.evidence_ids?.length==='number'?`${chain.evidence_ids.length} 条证据`:null,typeof chain.entity_ids?.length==='number'?`${chain.entity_ids.length} 个实体`:null].filter(Boolean);const sources=chain.sources?.map(source=>sourceDisplayName[source]??source).join(' / ');return <a className="chain-card" href={`/chains?chain=${chain.chain_id}`} key={chain.chain_id}><span className="chain-score"><strong>{Math.round(chain.score*100)}%</strong><small>置信度</small></span><div className="chain-card-main"><div className="chain-card-head"><strong>{chain.title}</strong><span className={`badge ${chain.status==='candidate'?'candidate':'neutral'}`}>{chainStatusText[chain.status]??chain.status}</span></div>{stages.length>0&&<small className="chain-stage-path">{stages.join(' → ')}</small>}<small className="chain-technique-path">{chain.technique_ids.join(' → ')}</small>{(facts.length>0||sources)&&<small className="chain-card-meta">{facts.join(' · ')}{facts.length>0&&sources?' · ':''}{sources}</small>}</div></a>}) : <p className="inline-empty">暂无攻击链。检测结果形成可验证关联后会出现在这里。</p>}</section>
    </>}
  </>
}
