import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { apiGet, apiPost } from '../api/client'
import { EmptyState } from '../components/EmptyState'
import { PageHeader } from '../components/PageHeader'
import { useApi } from '../hooks/useApi'

type Status='queued'|'running'|'succeeded'|'partial'|'failed'|'cancelled'
interface Chain { chain_id:string;title:string;steps:unknown[];completeness:number }
interface Investigation { case_id:string;attack_chain:string;status:Status;created_at?:string;finished_at?:string;final_confidence:number;task_count:number;model_fallback:boolean }
interface Finding { claim:string;confidence:number;evidence_ids:string[];alternatives:string[] }
interface ToolCall { tool:string;input_summary:Record<string,unknown>;output_refs:string[];status:string }
interface Task { task_id:string;agent_role:string;objective:string;status:Status;started_at?:string;finished_at?:string;model_fallback:boolean;error?:string;result?:{findings:Finding[];tool_calls:ToolCall[];model_info:{provider:string;model:string};errors:{code:string;message:string}[]};artifact:Record<string,unknown> }
interface Detail { case_id:string;chain_id:string;tasks:Task[] }

const roleName:Record<string,string>={coordinator:'Coordinator',host:'Host Agent',network:'Network Agent',correlation:'Correlation',attribution:'Attribution',report:'Report'}
const statusName:Record<string,string>={queued:'等待',running:'运行中',succeeded:'完成',partial:'部分完成',failed:'失败',cancelled:'已取消'}

export function AgentsPage(){
  const {data:chains}=useApi<Chain[]>('/api/chains')
  const [params,setParams]=useSearchParams()
  const [items,setItems]=useState<Investigation[]>([])
  const [detail,setDetail]=useState<Detail|null>(null)
  const [selectedTask,setSelectedTask]=useState<string|null>(null)
  const [chainId,setChainId]=useState(params.get('chain')??'')
  const [loading,setLoading]=useState(true)
  const [starting,setStarting]=useState(false)
  const [error,setError]=useState<string|null>(null)
  const selectedCase=params.get('case')

  useEffect(()=>{if(!chainId&&chains?.length)setChainId([...chains].sort((a,b)=>b.steps.length-a.steps.length||b.completeness-a.completeness)[0].chain_id)},[chains,chainId])
  const load=useCallback(async()=>{try{const value=await apiGet<Investigation[]>('/api/agents');setItems(value.data);setError(null)}catch(reason){setError((reason as Error).message)}finally{setLoading(false)}},[])
  useEffect(()=>{void load()},[load])
  useEffect(()=>{if(!selectedCase){setDetail(null);return}apiGet<Detail>(`/api/agents/${selectedCase}`).then(value=>{setDetail(value.data);setSelectedTask(current=>current&&value.data.tasks.some(item=>item.task_id===current)?current:value.data.tasks[0]?.task_id??null)}).catch(reason=>setError((reason as Error).message))},[selectedCase,items])
  useEffect(()=>{if(!items.some(item=>['queued','running'].includes(item.status)))return;const timer=window.setInterval(()=>void load(),1600);return()=>window.clearInterval(timer)},[items,load])
  const task=detail?.tasks.find(item=>item.task_id===selectedTask)
  const start=async()=>{if(!chainId)return;setStarting(true);setError(null);try{const value=await apiPost<{case_id:string}>(`/api/chains/${chainId}/investigate`);setParams({case:value.data.case_id});await load()}catch(reason){setError((reason as Error).message)}finally{setStarting(false)}}
  const parentByRole=useMemo(()=>new Map(detail?.tasks.map(item=>[item.agent_role,item])??[]),[detail])
  return <><PageHeader title="Agent 调查中心" description="从既有攻击链启动受约束调查，查看任务编排、只读工具调用、结构化 Findings 与证据校验结果。" />
    <section className="agent-launch panel"><div><label htmlFor="chain-select">调查目标</label><select id="chain-select" value={chainId} onChange={event=>setChainId(event.target.value)}>{chains?.map(chain=><option key={chain.chain_id} value={chain.chain_id}>{chain.title} · {chain.steps.length} 阶段</option>)}</select></div><button className="primary-action" disabled={!chainId||starting} onClick={start}>{starting?'正在创建调查…':'开始 Agent 调查'}</button></section>
    {error&&<EmptyState kind="error" title="Agent 调查读取失败" detail={error}/>} {loading&&<div className="skeleton-list"><span/><span/><span/></div>}
    {!loading&&!error&&!items.length&&<EmptyState title="尚未运行 Agent 调查" detail="选择一条已有攻击链后开始调查；系统不会为 Agent 构造业务 Mock。"/>}
    {!!items.length&&<div className="agent-workspace"><aside className="investigation-list panel"><div className="panel-title"><h2>调查列表</h2><span>{items.length} 次</span></div>{items.map(item=><button className={selectedCase===item.case_id?'selected':''} key={item.case_id} onClick={()=>setParams({case:item.case_id})}><span className={`status-pill ${item.status}`}>{statusName[item.status]}</span><strong>{item.case_id}</strong><small>{item.attack_chain}</small><span>{Math.round(item.final_confidence*100)}% 置信度 · {item.task_count} 节点</span>{item.model_fallback&&<em>deterministic fallback</em>}</button>)}</aside>
      <main className="agent-main">{!detail?<EmptyState title="选择一次调查" detail="选择左侧记录后查看 Agent 调用链和各节点结果。"/>:<><section className="orchestration panel"><div className="panel-title"><h2>Agent 编排</h2><span>{detail.chain_id}</span></div><div className="agent-flow"><AgentNode task={parentByRole.get('coordinator')} selected={selectedTask} onSelect={setSelectedTask}/><div className="parallel-branch"><AgentNode task={parentByRole.get('host')} selected={selectedTask} onSelect={setSelectedTask}/><AgentNode task={parentByRole.get('network')} selected={selectedTask} onSelect={setSelectedTask}/></div><AgentNode task={parentByRole.get('correlation')} selected={selectedTask} onSelect={setSelectedTask}/><AgentNode task={parentByRole.get('attribution')} selected={selectedTask} onSelect={setSelectedTask}/><AgentNode task={parentByRole.get('report')} selected={selectedTask} onSelect={setSelectedTask}/></div></section>{task&&<AgentInspector task={task} chainId={detail.chain_id}/>}</>}</main></div>}
  </>
}

function AgentNode({task,selected,onSelect}:{task?:Task;selected:string|null;onSelect:(id:string)=>void}){if(!task)return null;return <button className={`agent-node ${selected===task.task_id?'selected':''}`} onClick={()=>onSelect(task.task_id)}><span className={`status-dot ${task.status}`}/><strong>{roleName[task.agent_role]}</strong><small>{statusName[task.status]}</small></button>}

function AgentInspector({task,chainId}:{task:Task;chainId:string}){return <section className="agent-detail panel"><div className="panel-title"><h2>{roleName[task.agent_role]} 详情</h2><span>{task.task_id}</span></div><div className="detail-grid"><div><h3>Objective</h3><p>{task.objective}</p><h3>Tools used</h3><div className="tool-list">{task.result?.tool_calls.map((call,index)=><article key={`${call.tool}-${index}`}><span className={`status-pill ${call.status}`}>{call.status}</span><strong>{call.tool}</strong><code>{JSON.stringify(call.input_summary)}</code><small>{call.output_refs.length} 个引用</small></article>)||<p>尚无工具调用。</p>}</div></div><div><h3>Findings</h3><div className="finding-list">{task.result?.findings.map((finding,index)=><article key={index}><header><strong>{Math.round(finding.confidence*100)}%</strong><span>{finding.evidence_ids.length} 条证据</span></header><p>{finding.claim}</p><div className="evidence-links">{finding.evidence_ids.map(id=><Link key={id} to={`/chains?chain=${chainId}&evidence=${id}`}>{id}</Link>)}</div>{!!finding.alternatives.length&&<details><summary>替代解释</summary>{finding.alternatives.map(item=><p key={item}>{item}</p>)}</details>}</article>)||<p>尚无结构化 Finding。</p>}</div>{task.result&&<p className="model-note">{task.result.model_info.provider} · {task.result.model_info.model}{task.model_fallback?' · 已降级':''}</p>}{(task.error||task.result?.errors?.length)&&<div className="error-note">{task.error??task.result?.errors.map(item=>item.message).join('；')}</div>}</div></div></section>}
