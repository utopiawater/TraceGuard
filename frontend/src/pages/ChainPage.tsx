import cytoscape from 'cytoscape'
import { useEffect, useRef, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import type { components } from '../api/generated'
import { EmptyState } from '../components/EmptyState'
import { PageHeader } from '../components/PageHeader'
import { useApi } from '../hooks/useApi'

type ChainStep = components['schemas']['ChainStep']
type Chain = components['schemas']['AttackChain']
type Evidence = components['schemas']['Evidence']
interface Graph { nodes:components['schemas']['GraphEntity'][];edges:components['schemas']['GraphRelation'][];runtime?:{configured:boolean;connected:boolean;uri?:string;error?:string|null} }

export function ChainPage() {
  const { data: chains, error, loading } = useApi<Chain[]>('/api/chains')
  const { data: graph } = useApi<Graph>('/api/graph')
  const { data: evidence } = useApi<Evidence[]>('/api/evidence?limit=500')
  const [params] = useSearchParams()
  const requested = params.get('chain')
  const requestedEvidence = params.get('evidence')
  const chain = chains?.find(item=>item.chain_id===requested) ?? (chains ? [...chains].sort((a,b)=>b.completeness-a.completeness||Date.parse(b.end_time)-Date.parse(a.end_time))[0] : undefined)
  const canvas = useRef<HTMLDivElement>(null)
  const [selected, setSelected] = useState<ChainStep|null>(null)
  useEffect(() => {
    if (!chain) return
    const matched = requestedEvidence ? chain.steps.find(step=>step.evidence_ids.includes(requestedEvidence)) : undefined
    setSelected(matched ?? chain.steps[0] ?? null)
  }, [chain?.chain_id, requestedEvidence])
  useEffect(() => {
    if (!canvas.current || !graph?.nodes.length || !chain) return
    const included = new Set([...(chain.entity_ids??[]),...(chain.detection_ids??[]),...(chain.technique_ids??[])])
    const visibleNodes = graph.nodes.filter(node=>included.has(node.entity_id))
    const nodeIds = new Set(visibleNodes.map(node=>node.entity_id))
    const visibleEdges = graph.edges.filter(edge=>nodeIds.has(edge.source_entity_id)&&nodeIds.has(edge.target_entity_id))
    const cy = cytoscape({container:canvas.current,elements:[...visibleNodes.map(n=>({data:{id:n.entity_id,label:n.display_name||n.entity_type,type:n.entity_type}})),...visibleEdges.map(e=>({data:{id:e.relation_id,source:e.source_entity_id,target:e.target_entity_id,label:e.relation_type,derived:e.derived}}))],layout:{name:'breadthfirst',directed:true,padding:28},style:[{selector:'node',style:{'background-color':'#efbd78','border-color':'#a9531e','border-width':'1px','label':'data(label)','font-size':'10px','text-wrap':'wrap','text-max-width':'90px','color':'#26323f'}},{selector:'edge',style:{'width':'1.4px','line-color':'#929aa3','target-arrow-color':'#929aa3','target-arrow-shape':'triangle','curve-style':'bezier','label':'data(label)','font-size':'8px','text-background-color':'#ffffff','text-background-opacity':1,'text-background-padding':'2px'}},{selector:'edge[derived]',style:{'line-style':'dashed','line-color':'#c35f22'}}]})
    return () => cy.destroy()
  },[graph,chain])
  return <><PageHeader title="攻击链溯源" description="逐步核对时间、实体、会话、ATT&CK 映射和原始证据。" />
    {loading && <div className="skeleton-hero"/>}{error && <EmptyState kind="error" title="攻击链读取失败" detail={error}/>} {!loading && !error && !chain && <EmptyState title="尚未形成攻击链" detail="主管道产生带证据的检测并满足关联约束后，候选链会出现在这里。"/>}
    {chain && <><section className="chain-summary"><div><span className="badge candidate">{chain.status === 'candidate' ? '候选' : chain.status}</span><h2>{chain.title}</h2></div><dl><div><dt>链分数</dt><dd>{Math.round(chain.score*100)}</dd></div><div><dt>完整度</dt><dd>{Math.round(chain.completeness*100)}%</dd></div><div><dt>步骤</dt><dd>{chain.steps.length}</dd></div></dl></section>
      <ol className="stage-track">{chain.steps.map((step,i)=><li className={selected?.step_id===step.step_id?'active':''} key={step.step_id}><button onClick={()=>setSelected(step)}><span>{i+1}</span><small>{stageName(step.stage)}</small><strong>{step.technique_id}</strong></button></li>)}</ol>
      <div className="investigation-grid"><section className="graph-panel"><div className="panel-title"><h2>跨源关系图</h2><span>{graph?.runtime?.connected ? 'Neo4j 已连接' : '内存切片 · Neo4j 未连接'} · 实线为事实 · 虚线为派生</span></div>{graph?.nodes.length ? <div className="graph-canvas" ref={canvas}/> : <EmptyState title="图投影尚不可用" detail="API 已返回攻击链，但当前进程中没有可用的图投影。"/>}</section><aside className="inspector"><h2>{requestedEvidence?'Evidence 下钻':'步骤检查器'}</h2>{requestedEvidence&&(()=>{const item=evidence?.find(value=>value.evidence_id===requestedEvidence);return item?<article className="evidence-focus"><code>{item.evidence_id}</code><strong>{String((item.excerpt as Record<string,unknown>)?.action??item.kind)}</strong><small>{item.source_ref}</small><p>可靠性：{item.reliability} · 关联事件 {item.event_ids?.length??0} 个</p></article>:<p>该 Evidence 当前不可用。</p>})()}{selected&&<><span className="badge neutral">{stageName(selected.stage)}</span><h3>{selected.technique_id}</h3><p>{selected.explanation}</p><dl><dt>可信度</dt><dd>{Math.round(selected.score*100)}%</dd><dt>证据引用</dt><dd>{selected.evidence_ids.length} 条</dd></dl><div className="evidence-list">{selected.evidence_ids.map(id=>{const item=evidence?.find(value=>value.evidence_id===id);return <article key={id}><code>{id}</code>{item&&<><strong>{String((item.excerpt as Record<string,unknown>)?.action??item.kind)}</strong><small>{item.source_ref}</small></>}</article>})}</div></>}</aside></div>
      {!!chain.uncertainties?.length&&<section className="uncertainty"><strong>尚未证实</strong>{chain.uncertainties.map(item=><p key={item}>{item}</p>)}</section>}</>}
  </>
}
const stageName=(stage:string)=>({initial_access:'初始访问',execution:'执行',command_and_control:'命令与控制',persistence:'持久化',privilege_escalation:'权限提升',lateral_movement:'横向移动',collection:'收集',exfiltration:'外传'}[stage]??stage)
