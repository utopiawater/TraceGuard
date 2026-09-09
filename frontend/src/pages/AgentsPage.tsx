import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { apiGet, apiPost } from '../api/client'
import { EmptyState } from '../components/EmptyState'
import { PageHeader } from '../components/PageHeader'
import { useAnalysis } from '../context/AnalysisContext'
import { useApi } from '../hooks/useApi'
import { executionModeName, pct, taskStatusName } from '../lib/display'

type Status='queued'|'running'|'succeeded'|'partial'|'failed'|'cancelled'
interface Chain { chain_id:string;title:string;steps:unknown[];completeness:number }
interface Investigation { case_id:string;attack_chain:string;scope:'full'|'quick';status:Status;created_at?:string;finished_at?:string;final_confidence:number;task_count:number;model_fallback:boolean;execution_mode:'real_llm'|'deterministic_fallback'|'pending' }
interface Finding { claim:string;confidence:number;evidence_ids:string[];alternatives:string[] }
interface ToolCall { tool:string;input_summary:Record<string,unknown>;output_refs:string[];status:string }
interface Task { task_id:string;agent_role:string;objective:string;status:Status;started_at?:string;finished_at?:string;model_fallback:boolean;execution_mode:'real_llm'|'deterministic_fallback'|'pending';error?:string;result?:{findings:Finding[];tool_calls:ToolCall[];model_info:{provider:string;model:string};errors:{code:string;message:string}[]};artifact:Record<string,unknown> }
interface Detail { case_id:string;chain_id:string;tasks:Task[] }

const roleName:Record<string,string>={coordinator:'Coordinator',host:'Host Agent',network:'Network Agent',correlation:'Correlation',attribution:'Attribution',report:'Report'}

export function AgentsPage(){
  const [params,setParams]=useSearchParams()
  const { currentRunId: runId, runScopedPath } = useAnalysis()
  const scoped = runId ? `run_id=${encodeURIComponent(runId)}` : ''
  const {data:chains}=useApi<Chain[]>(`/api/chains${scoped ? `?${scoped}` : ''}`)
  const [items,setItems]=useState<Investigation[]>([])
  const [detail,setDetail]=useState<Detail|null>(null)
  const [selectedTask,setSelectedTask]=useState<string|null>(null)
  const [chainId,setChainId]=useState(params.get('chain')??'')
  const [loading,setLoading]=useState(true)
  const [starting,setStarting]=useState<'quick'|'full'|null>(null)
  const [error,setError]=useState<string|null>(null)
  const selectedCase=params.get('case')

  useEffect(()=>{
    setChainId('')
    setDetail(null)
    setSelectedTask(null)
    setItems([])
    setLoading(true)
    if (selectedCase) setParams(runId ? {run_id:runId} : {})
  },[runId])
  useEffect(()=>{if(chainId&&chains&&!chains.some(chain=>chain.chain_id===chainId))setChainId('')},[chains,chainId])
  useEffect(()=>{if(!chainId&&chains?.length)setChainId([...chains].sort((a,b)=>b.steps.length-a.steps.length||b.completeness-a.completeness)[0].chain_id)},[chains,chainId])
  const load=useCallback(async()=>{try{const value=await apiGet<Investigation[]>(`/api/agents${scoped ? `?${scoped}` : ''}`);setItems(value.data);setError(null)}catch(reason){setError((reason as Error).message)}finally{setLoading(false)}},[scoped])
  useEffect(()=>{void load()},[load])
  useEffect(()=>{if(!selectedCase){setDetail(null);return}apiGet<Detail>(`/api/agents/${selectedCase}`).then(value=>{setDetail(value.data);setSelectedTask(current=>current&&value.data.tasks.some(item=>item.task_id===current)?current:value.data.tasks[0]?.task_id??null)}).catch(reason=>setError((reason as Error).message))},[selectedCase,items])
  useEffect(()=>{if(!items.some(item=>['queued','running'].includes(item.status)))return;const timer=window.setInterval(()=>void load(),1600);return()=>window.clearInterval(timer)},[items,load])
  const task=detail?.tasks.find(item=>item.task_id===selectedTask)
  const start=async(scope:'quick'|'full')=>{if(!chainId)return;setStarting(scope);setError(null);try{const maxSteps=scope==='quick'?4:12;const value=await apiPost<{case_id:string}>(`/api/chains/${chainId}/investigate?scope=${scope}&max_steps=${maxSteps}`);setParams(runId ? {case:value.data.case_id, run_id:runId} : {case:value.data.case_id});await load()}catch(reason){setError((reason as Error).message)}finally{setStarting(null)}}
  const parentByRole=useMemo(()=>new Map(detail?.tasks.map(item=>[item.agent_role,item])??[]),[detail])
  return <><PageHeader title="Agent 调查中心" description="对当前 AttackChain 启动可选调查；Agent 只读取已有 Detection、Evidence 与链路。" aside={runId ? <span className="freshness">任务 {runId}</span> : undefined} />
    <section className="agent-launch panel"><div className="agent-target"><label htmlFor="chain-select">调查目标</label><select id="chain-select" value={chainId} onChange={event=>setChainId(event.target.value)}>{chains?.map(chain=><option key={chain.chain_id} value={chain.chain_id}>{chain.title} · {chain.steps.length} 阶段</option>)}</select></div><div className="agent-actions"><button className="primary-action" disabled={!chainId||!!starting} onClick={()=>start('quick')}>{starting==='quick'?'正在创建…':'快速调查 · 4 Agent'}</button><button className="secondary-action" disabled={!chainId||!!starting} onClick={()=>start('full')}>{starting==='full'?'正在创建…':'完整调查 · 6 Agent'}</button></div></section>
    {error&&<EmptyState kind="error" title="Agent 调查读取失败" detail={error}/>} {loading&&<div className="skeleton-list"><span/><span/><span/></div>}
    {!loading&&!error&&!items.length&&<EmptyState title="尚未运行 Agent 调查" detail="选择一条已有攻击链后开始调查；系统不会为 Agent 构造业务 Mock。"/>}
    {!!items.length&&<div className="agent-workspace"><aside className="investigation-list panel"><div className="panel-title"><h2>调查列表</h2><span>{items.length} 次</span></div>{items.map(item=><button className={selectedCase===item.case_id?'selected':''} key={item.case_id} onClick={()=>setParams(runId ? {case:item.case_id, run_id:runId} : {case:item.case_id})}><span className={`status-pill ${item.status}`}>{taskStatusName[item.status]}</span><time>{item.created_at?new Date(item.created_at).toLocaleString('zh-CN'):'—'}</time><strong>{chains?.find(chain=>chain.chain_id===item.attack_chain)?.title??'攻击链调查'}</strong><small>{item.scope==='quick'?'快速调查 · 4 Agent':'完整调查 · 6 Agent'} · {item.case_id}</small><span title="Final Confidence 是已通过证据校验的 Findings 平均置信度，不代表攻击者身份确认。">{pct(item.final_confidence)} 最终置信度 · <b>{executionModeName[item.execution_mode] ?? item.execution_mode}</b></span></button>)}</aside>
      <main className="agent-main">{!detail?<EmptyState title="选择一次调查" detail="选择左侧记录后查看 Agent 调用链和各节点结果。"/>:<><section className="orchestration panel"><div className="panel-title"><h2>Agent 编排</h2><span>{detail.chain_id}</span></div><div className="agent-flow"><AgentNode task={parentByRole.get('coordinator')} selected={selectedTask} onSelect={setSelectedTask}/><div className="parallel-branch"><AgentNode task={parentByRole.get('host')} selected={selectedTask} onSelect={setSelectedTask}/><AgentNode task={parentByRole.get('network')} selected={selectedTask} onSelect={setSelectedTask}/></div><AgentNode task={parentByRole.get('correlation')} selected={selectedTask} onSelect={setSelectedTask}/><AgentNode task={parentByRole.get('attribution')} selected={selectedTask} onSelect={setSelectedTask}/><AgentNode task={parentByRole.get('report')} selected={selectedTask} onSelect={setSelectedTask}/></div></section>{task&&<AgentInspector task={task} chainId={detail.chain_id} runScopedPath={runScopedPath}/>}</>}</main></div>}
  </>
}

function AgentNode({task,selected,onSelect}:{task?:Task;selected:string|null;onSelect:(id:string)=>void}){if(!task)return null;return <button className={`agent-node ${selected===task.task_id?'selected':''}`} onClick={()=>onSelect(task.task_id)}><span className={`status-dot ${task.status}`}/><strong>{roleName[task.agent_role]}</strong><small>{taskStatusName[task.status] ?? task.status}</small></button>}

function AgentInspector({task,chainId,runScopedPath}:{task:Task;chainId:string;runScopedPath:(path:string, extra?:Record<string,string|null|undefined>)=>string}){
  const toolCalls = task.result?.tool_calls ?? []
  const findings = task.result?.findings ?? []
  const errors = task.result?.errors ?? []
  return <section className="agent-detail panel"><div className="panel-title"><h2>{roleName[task.agent_role]} 详情</h2><span>{task.task_id}</span></div><div className="detail-grid"><div><h3>任务目标</h3><p>{task.objective}</p><h3>工具调用</h3><div className="tool-list">{toolCalls.length ? toolCalls.map((call,index)=><article key={`${call.tool}-${index}`}><span className={`status-pill ${call.status}`}>{taskStatusName[call.status] ?? call.status}</span><strong>{call.tool}</strong><code>{JSON.stringify(call.input_summary)}</code><small>{call.output_refs.length} 个引用</small></article>) : <p>尚无工具调用。</p>}</div></div><div><h3>Findings</h3><div className="finding-list">{findings.length ? findings.map((finding,index)=><article key={index}><header><strong title="Finding confidence：该结论在证据约束下的置信度。">{pct(finding.confidence)}</strong><span>{finding.evidence_ids.length} 条证据</span></header><p>{finding.claim}</p><div className="evidence-links">{finding.evidence_ids.map(id=><Link key={id} to={runScopedPath('/chains', { chain: chainId, evidence: id })}>{id}</Link>)}</div>{!!finding.alternatives.length&&<details><summary>替代解释</summary>{finding.alternatives.map(item=><p key={item}>{item}</p>)}</details>}</article>) : <p>尚无结构化 Finding。</p>}</div>{task.result&&<p className="model-note">{executionModeName[task.execution_mode] ?? task.execution_mode} · {task.result.model_info.model}</p>}{(task.error||errors.length > 0)&&<div className="error-note">{task.error??errors.map(item=>item.message).join('；')}</div>}</div></div></section>
}
