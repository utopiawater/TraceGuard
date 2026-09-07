import * as echarts from 'echarts/core'
import { BarChart } from 'echarts/charts'
import { GridComponent, TooltipComponent } from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'
import { AlertTriangle, CheckCircle2, GitBranch, RadioTower } from 'lucide-react'
import { useEffect, useRef } from 'react'
import { EmptyState } from '../components/EmptyState'
import { PageHeader } from '../components/PageHeader'
import { useApi } from '../hooks/useApi'

interface Dashboard { counts: Record<string,number>; sources: {source:string;event_count:number;last_event_time:string;status:string}[]; recent_chains: {chain_id:string;title:string;score:number;status:string;technique_ids:string[]}[]; time_quality:{synced:number;other:number} }

echarts.use([BarChart, GridComponent, TooltipComponent, CanvasRenderer])

export function DashboardPage() {
  const { data, error, loading } = useApi<Dashboard>('/api/dashboard')
  const chartRef = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!chartRef.current || !data?.sources.length) return
    const chart = echarts.init(chartRef.current)
    chart.setOption({ animationDuration: 180, grid:{left:38,right:12,top:18,bottom:30}, xAxis:{type:'category',data:data.sources.map(s=>s.source),axisLine:{lineStyle:{color:'oklch(0.89 0.012 250)'}}}, yAxis:{type:'value',splitLine:{lineStyle:{color:'oklch(0.94 0.008 250)'}}}, tooltip:{trigger:'axis'}, series:[{type:'bar',data:data.sources.map(s=>s.event_count),barWidth:24,itemStyle:{color:'oklch(0.62 0.17 53)',borderRadius:[4,4,0,0]}}] })
    const resize = () => chart.resize(); addEventListener('resize',resize)
    return () => { removeEventListener('resize',resize); chart.dispose() }
  }, [data])
  return <><PageHeader title="安全态势总览" description="先确认数据是否可信，再进入当前最重要的攻击链。" aside={data ? <span className="freshness"><CheckCircle2 size={15}/> 数据来自真实管道</span> : undefined} />
    {loading && <div className="skeleton-hero" />}{error && <EmptyState kind="error" title="总览读取失败" detail={error} />}
    {data && <>
      <section className="metric-strip"><div><RadioTower/><span>已接入来源</span><strong>{data.sources.length}</strong></div><div><AlertTriangle/><span>确定性检测</span><strong>{data.counts.detections}</strong></div><div><GitBranch/><span>候选攻击链</span><strong>{data.counts.attack_chains}</strong></div><div><CheckCircle2/><span>时间同步事件</span><strong>{data.time_quality.synced}</strong></div></section>
      {data.sources.length === 0 ? <EmptyState title="尚未收到安全事件" detail="运行场景回放或接入 Sysmon / Zeek 后，总览才会显示真实结果。" /> : <div className="dashboard-layout"><section className="panel chart-panel"><div className="panel-title"><h2>来源事件量</h2><span>当前分析窗口</span></div><div ref={chartRef} className="chart" role="img" aria-label="各数据来源事件数量柱状图" /></section><section className="panel source-health"><div className="panel-title"><h2>数据源健康</h2><span>{data.sources.length} 个来源</span></div>{data.sources.map(source=><div className="source-row" key={source.source}><span className="status-dot"/><strong>{source.source}</strong><span>{source.event_count} 条</span><time>{new Date(source.last_event_time).toLocaleTimeString('zh-CN')}</time></div>)}</section></div>}
      <section className="chain-list"><div className="section-heading"><h2>最近攻击链</h2><span>候选链不会自动标记为已确认</span></div>{data.recent_chains.length ? data.recent_chains.map(chain=><a href={`/chains?chain=${chain.chain_id}`} key={chain.chain_id}><span className="chain-score">{Math.round(chain.score*100)}</span><div><strong>{chain.title}</strong><small>{chain.technique_ids.join(' → ')}</small></div><span className="badge candidate">候选</span></a>) : <p className="inline-empty">暂无攻击链。检测结果形成可验证关联后会出现在这里。</p>}</section>
    </>}
  </>
}
