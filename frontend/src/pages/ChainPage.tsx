import cytoscape from 'cytoscape'
import { useEffect, useRef, useState } from 'react'
import { Maximize2, Play, RotateCcw, ZoomIn, ZoomOut } from 'lucide-react'
import { useSearchParams } from 'react-router-dom'
import type { components } from '../api/generated'
import { EmptyState } from '../components/EmptyState'
import { PageHeader } from '../components/PageHeader'
import { useApi } from '../hooks/useApi'
import { chainStatusName, pct, stageName } from '../lib/display'

type ChainStep = components['schemas']['ChainStep']
type Chain = components['schemas']['AttackChain']
type Evidence = components['schemas']['Evidence']
type GraphEntity = components['schemas']['GraphEntity']
type GraphRelation = components['schemas']['GraphRelation']
type EntityType = GraphEntity['entity_type']
interface Graph { nodes:GraphEntity[];edges:GraphRelation[];runtime?:{configured:boolean;connected:boolean;uri?:string;error?:string|null} }
interface AttackTechnique { technique_id:string;technique_name:string }

type HoverInfo = { title:string;subtitle:string;detail?:string;x:number;y:number }

const relationLabel: Record<string, string> = {
  ACCESSED: '访问',
  COMMUNICATED_WITH: '通信',
  CORROBORATES: '佐证',
  CREATED: '创建',
  DELETED: '删除',
  EXECUTED_BY: '执行',
  FROM: '来源',
  INITIATED: '发起',
  LOGGED_IN: '登录',
  MODIFIED: '修改',
  ON_HOST: '主机',
  SPAWNED: '派生',
  TO: '目标',
  TRIGGERED: '触发',
  USED_TECHNIQUE: '技术',
}

const entityLabel: Record<string, string> = {
  host: 'Host',
  user: 'User',
  process: 'Process',
  ip: 'IP',
  domain: 'Domain',
  file: 'File',
  session: 'Session',
  technique: 'Technique',
}

const entityStyle: Record<string, { shape: cytoscape.Css.NodeShape; color: string; border: string }> = {
  host: { shape: 'round-rectangle', color: '#dbeafe', border: '#2563eb' },
  user: { shape: 'ellipse', color: '#dcfce7', border: '#16a34a' },
  process: { shape: 'rectangle', color: '#fef3c7', border: '#b45309' },
  ip: { shape: 'diamond', color: '#e0f2fe', border: '#0284c7' },
  domain: { shape: 'hexagon', color: '#ede9fe', border: '#7c3aed' },
  file: { shape: 'tag', color: '#fce7f3', border: '#be185d' },
  session: { shape: 'round-tag', color: '#ccfbf1', border: '#0f766e' },
  technique: { shape: 'vee', color: '#ffedd5', border: '#ea580c' },
  alert: { shape: 'octagon', color: '#fee2e2', border: '#dc2626' },
  c2: { shape: 'hexagon', color: '#fee2e2', border: '#b91c1c' },
  registry: { shape: 'barrel', color: '#f1f5f9', border: '#64748b' },
  evidence: { shape: 'round-rectangle', color: '#f8fafc', border: '#94a3b8' },
}

const legendTypes: EntityType[] = ['host', 'user', 'process', 'ip', 'domain', 'file', 'technique']

function graphLabel(value: string | null | undefined, fallback: string): string {
  const label = value || fallback
  const compact = label.replace(/^C:\\Windows\\System32\\/i, 'System32/').replace(/^C:\\Windows\\/i, 'Windows/')
  if (compact.length <= 22) return compact
  const parts = compact.split(/[\\/]/).filter(Boolean)
  if (parts.length > 1) return parts.at(-1) ?? compact.slice(0, 22)
  return `${compact.slice(0, 11)}...${compact.slice(-7)}`
}

function stageLabel(stage:string) {
  return stageName[stage] ?? stage
}

function stepForNode(chain: Chain, nodeId: string): ChainStep | undefined {
  return chain.steps.find(step => step.technique_id === nodeId)
    ?? chain.steps.find(step => (step.detection_ids ?? []).includes(nodeId))
    ?? chain.steps.find(step => (step.entity_ids ?? []).includes(nodeId))
    ?? chain.steps.find(step => (step.session_ids ?? []).includes(nodeId))
}

function nodeIdsForStep(step: ChainStep) {
  return new Set([step.technique_id, ...(step.entity_ids ?? []), ...(step.detection_ids ?? []), ...(step.session_ids ?? [])])
}

function stepIndexByNode(chain: Chain) {
  const map = new Map<string, number>()
  chain.steps.forEach((step, index) => nodeIdsForStep(step).forEach(id => map.set(id, index)))
  return map
}

function buildStepAnchors(chain: Chain, visibleIds: Set<string>) {
  const anchors = new Map<string, string>()
  chain.steps.forEach(step => {
    const candidates = [step.technique_id, ...(step.entity_ids ?? []), ...(step.detection_ids ?? []), ...(step.session_ids ?? [])]
    const anchor = candidates.find(id => visibleIds.has(id))
    if (anchor) anchors.set(step.step_id, anchor)
  })
  return anchors
}

function layoutPositions(nodes: GraphEntity[], chain: Chain, anchors: Map<string, string>) {
  const positions = new Map<string, { x: number; y: number }>()
  const indexByNode = stepIndexByNode(chain)
  const anchorIds = new Set([...anchors.values()])
  const perStep = new Map<number, number>()
  const centerY = 260
  const gapX = Math.max(220, 1320 / Math.max(chain.steps.length, 1))

  chain.steps.forEach((step, index) => {
    const anchor = anchors.get(step.step_id)
    if (anchor) positions.set(anchor, { x: 130 + index * gapX, y: centerY })
  })

  nodes.forEach(node => {
    if (positions.has(node.entity_id)) return
    const stepIndex = indexByNode.get(node.entity_id)
    if (stepIndex !== undefined) {
      const order = perStep.get(stepIndex) ?? 0
      perStep.set(stepIndex, order + 1)
      const side = order % 2 === 0 ? -1 : 1
      const ring = Math.floor(order / 2)
      positions.set(node.entity_id, {
        x: 130 + stepIndex * gapX + (side < 0 ? -42 : 42),
        y: centerY + side * (104 + ring * 70),
      })
      return
    }
    const fallbackIndex = positions.size
    positions.set(node.entity_id, {
      x: 130 + (fallbackIndex % Math.max(chain.steps.length, 1)) * gapX,
      y: centerY + (fallbackIndex % 2 === 0 ? -250 : 250),
    })
  })

  return { positions, anchorIds }
}

function fitElements(cy: cytoscape.Core, elements: cytoscape.Collection, padding = 70) {
  if (!elements.length) return
  cy.stop()
  cy.animate({ fit: { eles: elements, padding } }, { duration: 180, easing: 'ease-out' })
}

function applyStepFocus(cy: cytoscape.Core, step: ChainStep, anchors: Map<string, string>) {
  const ids = nodeIdsForStep(step)
  const stepNodes = cy.nodes().filter(node => ids.has(node.id()))
  const neighborhood = stepNodes.closedNeighborhood().union(cy.edges(`[stepId = "${step.step_id}"]`))
  cy.elements().removeClass('selected-step node-selected context-focus context-muted selected-path')
  cy.elements().not(neighborhood).addClass('context-muted')
  neighborhood.addClass('context-focus')
  stepNodes.addClass('selected-step')
  cy.edges(`[stepId = "${step.step_id}"]`).addClass('selected-path')
  const anchor = anchors.get(step.step_id)
  if (anchor) cy.getElementById(anchor).addClass('node-selected')
  fitElements(cy, neighborhood, 96)
}

function applyNodeFocus(cy: cytoscape.Core, node: cytoscape.NodeSingular) {
  const neighborhood = node.closedNeighborhood()
  cy.elements().removeClass('selected-step node-selected context-focus context-muted selected-path')
  cy.elements().not(neighborhood).addClass('context-muted')
  neighborhood.addClass('context-focus')
  node.addClass('node-selected')
  node.connectedEdges('[attackPath = true]').addClass('selected-path')
  fitElements(cy, neighborhood, 98)
}

export function ChainPage() {
  const [params] = useSearchParams()
  const runId = params.get('run_id')
  const scoped = runId ? `run_id=${encodeURIComponent(runId)}` : ''
  const { data: chains, error, loading } = useApi<Chain[]>(`/api/chains${scoped ? `?${scoped}` : ''}`)
  const { data: graph } = useApi<Graph>(`/api/graph${scoped ? `?${scoped}` : ''}`)
  const { data: evidence } = useApi<Evidence[]>(`/api/evidence?limit=500${scoped ? `&${scoped}` : ''}`)
  const { data: attack } = useApi<AttackTechnique[]>(`/api/attack${scoped ? `?${scoped}` : ''}`)
  const requested = params.get('chain')
  const requestedEvidence = params.get('evidence')
  const chain = chains?.find(item=>item.chain_id===requested) ?? (chains ? [...chains].sort((a,b)=>b.completeness-a.completeness||Date.parse(b.end_time)-Date.parse(a.end_time))[0] : undefined)
  const canvas = useRef<HTMLDivElement>(null)
  const cyRef = useRef<cytoscape.Core|null>(null)
  const anchorsRef = useRef<Map<string, string>>(new Map())
  const [selected, setSelected] = useState<ChainStep|null>(null)
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null)
  const [hoverInfo, setHoverInfo] = useState<HoverInfo | null>(null)
  const [mainOnly, setMainOnly] = useState(false)
  const [playing, setPlaying] = useState(false)

  useEffect(() => {
    if (!chain) return
    const matched = requestedEvidence ? chain.steps.find(step=>step.evidence_ids.includes(requestedEvidence)) : undefined
    const next = matched ?? chain.steps[0] ?? null
    setSelected(next)
    setSelectedNodeId(next?.technique_id ?? null)
    setPlaying(false)
  }, [chain?.chain_id, requestedEvidence])

  useEffect(() => {
    if (!canvas.current || !graph?.nodes.length || !chain) return
    const included = new Set([...(chain.entity_ids??[]),...(chain.detection_ids??[]),...(chain.technique_ids??[])])
    const visibleNodes = graph.nodes.filter(node=>included.has(node.entity_id))
    const nodeIds = new Set(visibleNodes.map(node=>node.entity_id))
    const visibleEdges = graph.edges.filter(edge=>nodeIds.has(edge.source_entity_id)&&nodeIds.has(edge.target_entity_id))
    const anchors = buildStepAnchors(chain, nodeIds)
    anchorsRef.current = anchors
    const { positions, anchorIds } = layoutPositions(visibleNodes, chain, anchors)
    const indexByNode = stepIndexByNode(chain)
    const anchorList = chain.steps.map(step => anchors.get(step.step_id)).filter(Boolean) as string[]
    const pathEdges = anchorList.slice(0, -1).map((source, index) => {
      const target = anchorList[index + 1]
      const step = chain.steps[index + 1] ?? chain.steps[index]
      return {
        data: {
          id: `attack-path-${index}-${source}-${target}`,
          source,
          target,
          label: '攻击路径',
          fullLabel: '攻击路径',
          derived: false,
          attackPath: true,
          stepId: step.step_id,
        },
        classes: 'attack-path-edge',
      }
    })

    const cy = cytoscape({
      container: canvas.current,
      minZoom: 0.2,
      maxZoom: 2.2,
      wheelSensitivity: 0.78,
      hideEdgesOnViewport: true,
      hideLabelsOnViewport: true,
      textureOnViewport: true,
      motionBlur: true,
      userPanningEnabled: true,
      userZoomingEnabled: true,
      autoungrabify: false,
      elements: [
        ...visibleNodes.map(n => {
          const style = entityStyle[n.entity_type] ?? entityStyle.evidence
          const step = stepForNode(chain, n.entity_id)
          const isAnchor = anchorIds.has(n.entity_id)
          return {
            data: {
              id: n.entity_id,
              label: graphLabel(n.display_name, n.entity_type),
              fullLabel: n.display_name || n.entity_id,
              entityId: n.entity_id,
              type: n.entity_type,
              typeLabel: entityLabel[n.entity_type] ?? n.entity_type,
              stepId: step?.step_id ?? '',
              confidence: step ? Math.round(step.score * 100) : null,
              evidenceCount: n.evidence_ids?.length ?? step?.evidence_ids.length ?? 0,
              mainNode: isAnchor,
              color: style.color,
              border: style.border,
            },
            position: positions.get(n.entity_id),
            classes: `${isAnchor ? 'main-node' : 'support-node'} ${step ? 'chain-node' : ''}`,
          }
        }),
        ...visibleEdges.map(e => {
          const sourceStep = indexByNode.get(e.source_entity_id)
          const targetStep = indexByNode.get(e.target_entity_id)
          const onMain = sourceStep !== undefined && targetStep !== undefined && Math.abs(sourceStep - targetStep) <= 1 && !e.derived
          return {
            data: {
              id: e.relation_id,
              source: e.source_entity_id,
              target: e.target_entity_id,
              label: relationLabel[e.relation_type] ?? e.relation_type,
              fullLabel: e.relation_type,
              derived: e.derived,
              attackPath: false,
              mainRelation: onMain,
              confidence: Math.round(e.confidence * 100),
              evidenceCount: e.evidence_ids?.length ?? 0,
            },
            classes: onMain ? 'main-relation' : '',
          }
        }),
        ...pathEdges,
      ],
      layout: { name: 'preset', fit: true, padding: 74 },
      style: [
        {
          selector: 'node',
          style: {
            width: 52,
            height: 42,
            shape: 'round-rectangle',
            'background-color': 'data(color)',
            'border-color': 'data(border)',
            'border-width': 2,
            label: 'data(label)',
            'font-size': 12,
            'font-weight': 700,
            'font-family': 'Inter, Noto Sans SC, Microsoft YaHei, sans-serif',
            'text-wrap': 'wrap',
            'text-max-width': '116px',
            'text-valign': 'bottom',
            'text-halign': 'center',
            'text-margin-y': 8,
            'text-background-color': '#ffffff',
            'text-background-opacity': 0.92,
            'text-background-padding': '3px',
            color: '#1f2937',
            opacity: 0.98,
          },
        },
        ...Object.entries(entityStyle).map(([type, style]) => ({
          selector: `node[type = "${type}"]`,
          style: {
            shape: style.shape,
            'background-color': style.color,
            'border-color': style.border,
          },
        })),
        {
          selector: 'node.main-node',
          style: {
            width: 64,
            height: 50,
            'border-width': 3,
            'font-size': 13,
            'text-background-opacity': 1,
            'z-index': 20,
          },
        },
        {
          selector: 'node.node-selected, node.selected-step',
          style: {
            'background-color': '#fed7aa',
            'border-color': '#ea580c',
            'border-width': 4,
            color: '#111827',
            'text-background-opacity': 1,
            'z-index': 50,
          },
        },
        {
          selector: 'edge',
          style: {
            width: 1.3,
            'line-color': '#b8c0ca',
            'target-arrow-color': '#b8c0ca',
            'target-arrow-shape': 'triangle',
            'target-arrow-fill': 'filled',
            'curve-style': 'bezier',
            label: '',
            'font-size': 9,
            'font-weight': 650,
            'font-family': 'Inter, Noto Sans SC, Microsoft YaHei, sans-serif',
            color: '#475569',
            'text-background-color': '#ffffff',
            'text-background-opacity': 0.95,
            'text-background-padding': '3px',
            opacity: 0.85,
          },
        },
        {
          selector: 'edge[derived = true]',
          style: {
            'line-style': 'dashed',
            'line-color': '#aab3be',
            'target-arrow-color': '#aab3be',
            opacity: 0.76,
          },
        },
        {
          selector: 'edge.main-relation',
          style: {
            width: 2.4,
            'line-color': '#64748b',
            'target-arrow-color': '#64748b',
            opacity: 0.95,
          },
        },
        {
          selector: 'edge[attackPath = true]',
          style: {
            width: 5,
            'line-color': '#0f766e',
            'target-arrow-color': '#0f766e',
            'target-arrow-shape': 'triangle',
            'curve-style': 'straight',
            opacity: 0.96,
            'z-index': 15,
          },
        },
        { selector: '.context-muted', style: { opacity: 0.16 } },
        { selector: '.context-focus', style: { opacity: 1 } },
        {
          selector: 'edge.context-focus',
          style: {
            width: 2.5,
            label: 'data(label)',
            'line-color': '#64748b',
            'target-arrow-color': '#64748b',
          },
        },
        {
          selector: 'edge.selected-path',
          style: {
            width: 5.6,
            'line-color': '#ea580c',
            'target-arrow-color': '#ea580c',
            opacity: 1,
            'z-index': 60,
          },
        },
        { selector: '.main-only-hidden', style: { display: 'none' } },
      ],
    })

    window.requestAnimationFrame(() => fitElements(cy, cy.elements(), 76))
    cy.on('mouseover', 'node', event => {
      const node = event.target
      const data = node.data()
      const position = node.renderedPosition()
      setHoverInfo({
        title: data.fullLabel,
        subtitle: `${data.typeLabel}${data.confidence ? ` · 置信度 ${data.confidence}%` : ''}`,
        detail: data.entityId,
        x: position.x,
        y: position.y,
      })
    })
    cy.on('mouseout', 'node', () => setHoverInfo(null))
    cy.on('mouseover', 'edge', event => {
      const edge = event.target
      const data = edge.data()
      const midpoint = edge.midpoint()
      const pan = cy.pan()
      setHoverInfo({
        title: data.fullLabel,
        subtitle: data.attackPath ? '攻击链路径视图' : data.derived ? '推断/派生关系' : '事实关系',
        detail: data.evidenceCount ? `Evidence ${data.evidenceCount} 条` : undefined,
        x: midpoint.x * cy.zoom() + pan.x,
        y: midpoint.y * cy.zoom() + pan.y,
      })
    })
    cy.on('mouseout', 'edge', () => setHoverInfo(null))
    cy.on('tap', 'node', event => {
      const node = event.target
      const nodeId = node.id()
      const next = stepForNode(chain, nodeId)
      setSelectedNodeId(nodeId)
      if (next) setSelected(next)
      applyNodeFocus(cy, node)
    })
    cy.on('tap', event => {
      if (event.target !== cy) return
      cy.elements().removeClass('selected-step node-selected context-focus context-muted selected-path')
      fitElements(cy, cy.elements(':visible'), 76)
    })

    cyRef.current = cy
    return () => {
      cyRef.current = null
      cy.destroy()
    }
  },[graph,chain])

  useEffect(() => {
    const cy = cyRef.current
    if (!cy) return
    cy.elements().removeClass('main-only-hidden')
    if (mainOnly) {
      cy.nodes().not('.main-node').addClass('main-only-hidden')
      cy.edges().not('.attack-path-edge').addClass('main-only-hidden')
      fitElements(cy, cy.elements(':visible'), 88)
    } else {
      fitElements(cy, cy.elements(), 76)
    }
  }, [mainOnly, graph, chain])

  useEffect(() => {
    if (!playing || !chain) return
    let index = Math.max(0, chain.steps.findIndex(step => step.step_id === selected?.step_id))
    const timer = window.setInterval(() => {
      const step = chain.steps[index]
      if (!step) {
        setPlaying(false)
        return
      }
      setSelected(step)
      setSelectedNodeId(anchorsRef.current.get(step.step_id) ?? step.technique_id)
      const cy = cyRef.current
      if (cy) applyStepFocus(cy, step, anchorsRef.current)
      index += 1
    }, 1250)
    return () => window.clearInterval(timer)
  }, [playing, chain?.chain_id])

  const selectedNode = graph?.nodes.find(node => node.entity_id === selectedNodeId)
  const techniqueName = (techniqueId?: string) => attack?.find(item=>item.technique_id===techniqueId)?.technique_name

  const handleStageClick = (step: ChainStep) => {
    setPlaying(false)
    setSelected(step)
    setSelectedNodeId(anchorsRef.current.get(step.step_id) ?? step.technique_id)
    const cy = cyRef.current
    if (cy) applyStepFocus(cy, step, anchorsRef.current)
  }

  const zoomBy = (factor: number) => {
    const cy = cyRef.current
    if (!cy) return
    cy.zoom({
      level: Math.max(cy.minZoom(), Math.min(cy.maxZoom(), cy.zoom() * factor)),
      renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 },
    })
  }

  const resetGraph = () => {
    const cy = cyRef.current
    setPlaying(false)
    setMainOnly(false)
    setHoverInfo(null)
    if (!cy) return
    cy.elements().removeClass('selected-step node-selected context-focus context-muted selected-path main-only-hidden')
    fitElements(cy, cy.elements(), 76)
  }

  return <><PageHeader title="攻击链溯源" description="逐步核对时间、实体、会话、ATT&CK 映射和原始证据。" />
    {loading && <div className="skeleton-hero"/>}{error && <EmptyState kind="error" title="攻击链读取失败" detail={error}/>} {!loading && !error && !chain && <EmptyState title="尚未形成攻击链" detail="主管道产生带证据的检测并满足关联约束后，候选链会出现在这里。"/>}
    {chain && <><section className="chain-summary"><div><span className={`badge ${chain.status==='candidate'?'candidate':'neutral'}`}>{chainStatusName[chain.status] ?? chain.status}</span><h2>{chain.title}</h2></div><dl><div><dt title="链可信评分：由步骤检测置信度和 ATT&CK 映射置信度综合得到。">链可信评分</dt><dd>{pct(chain.score)}</dd></div><div><dt title="完整度：当前链覆盖预期战术阶段的比例；不是检测准确率。">完整度</dt><dd>{pct(chain.completeness)}</dd></div><div><dt title="阶段数：系统恢复出的攻击链步骤数量。">阶段数</dt><dd>{chain.steps.length}</dd></div></dl></section>
      <ol className="stage-track">{chain.steps.map((step,i)=><li className={selected?.step_id===step.step_id?'active':''} key={step.step_id}><button onClick={()=>handleStageClick(step)}><span>{i+1}</span><small>{stageLabel(step.stage)}</small><strong>{step.technique_id}{techniqueName(step.technique_id)?` · ${techniqueName(step.technique_id)}`:''}</strong></button></li>)}</ol>
      <div className="investigation-grid"><section className="graph-panel"><div className="panel-title graph-title"><div><h2>跨源关系图</h2><span>{graph?.runtime?.connected ? 'Neo4j 已连接' : '内存切片 · Neo4j 未连接'} · 实线为事实 · 虚线为派生</span></div><div className="graph-toolbar" aria-label="图谱工具栏"><button onClick={()=>cyRef.current&&fitElements(cyRef.current, cyRef.current.elements(':visible'), 76)}><Maximize2 size={14}/>适应画布</button><button onClick={()=>zoomBy(1.18)}><ZoomIn size={14}/>放大</button><button onClick={()=>zoomBy(0.84)}><ZoomOut size={14}/>缩小</button><button onClick={resetGraph}><RotateCcw size={14}/>重置</button><button className={mainOnly?'active':''} onClick={()=>setMainOnly(true)}>只看主链</button><button onClick={()=>setMainOnly(false)}>显示全部</button><button className={playing?'active':''} onClick={()=>setPlaying(value=>!value)}><Play size={14}/>播放攻击链</button></div></div>{graph?.nodes.length ? <><div className="graph-legend"><div>{legendTypes.map(type=>{const style=entityStyle[type];return <span key={type}><i style={{background:style.color,borderColor:style.border}} />{entityLabel[type]}</span>})}</div><div><span><b className="legend-line fact"/>事实关系</span><span><b className="legend-line derived"/>推断关系</span><span><b className="legend-line path"/>当前攻击路径</span></div></div><div className="graph-canvas-wrap"><div className="graph-canvas" ref={canvas}/>{hoverInfo&&<div className="graph-hover-card" style={{left:hoverInfo.x,top:hoverInfo.y}}><strong>{hoverInfo.title}</strong><span>{hoverInfo.subtitle}</span>{hoverInfo.detail&&<small>{hoverInfo.detail}</small>}</div>}</div></> : <EmptyState title="图投影尚不可用" detail="API 已返回攻击链，但当前进程中没有可用的图投影。"/>}</section><aside className="inspector"><h2>{requestedEvidence?'Evidence 下钻':'步骤检查器'}</h2>{selectedNode&&<article className="node-focus"><span>{entityLabel[selectedNode.entity_type] ?? selectedNode.entity_type}</span><strong>{selectedNode.display_name ?? selectedNode.entity_id}</strong><code>{selectedNode.entity_id}</code></article>}{requestedEvidence&&(()=>{const item=evidence?.find(value=>value.evidence_id===requestedEvidence);return item?<article className="evidence-focus"><code>{item.evidence_id}</code><strong>{String((item.excerpt as Record<string,unknown>)?.action??item.kind)}</strong><small>{item.source_ref}</small><p>可靠性：{item.reliability} · 关联事件 {item.event_ids?.length??0} 个</p></article>:<p>该 Evidence 当前不可用。</p>})()}{selected&&<><span className="badge neutral">{stageLabel(selected.stage)}</span><h3>{selected.technique_id}{techniqueName(selected.technique_id)?` · ${techniqueName(selected.technique_id)}`:''}</h3><p>{selected.explanation}</p><dl><dt>Technique</dt><dd>{selected.technique_id}{techniqueName(selected.technique_id)?` · ${techniqueName(selected.technique_id)}`:''}</dd><dt title="该步骤可信度由 Detection 置信度和 ATT&CK 映射置信度相乘得到。">步骤可信度</dt><dd>{pct(selected.score)}</dd><dt>证据引用</dt><dd>{selected.evidence_ids.length} 条</dd></dl><div className="evidence-list">{selected.evidence_ids.map(id=>{const item=evidence?.find(value=>value.evidence_id===id);return <article key={id}><code>{id}</code>{item&&<><strong>{String((item.excerpt as Record<string,unknown>)?.action??item.kind)}</strong><small>{item.source_ref}</small></>}</article>})}</div></>}</aside></div>
      {!!chain.uncertainties?.length&&<section className="uncertainty"><strong>尚未证实</strong>{chain.uncertainties.map(item=><p key={item}>{item}</p>)}</section>}</>}
  </>
}
