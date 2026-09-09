import { EmptyState } from './EmptyState'
import { PageHeader } from './PageHeader'
import { useAnalysis } from '../context/AnalysisContext'
import { useApi } from '../hooks/useApi'

type Row = Record<string, unknown>

export function ResourcePage({ title, description, endpoint, columns }: { title: string; description: string; endpoint: string; columns: [string,string][] }) {
  const { currentRunId: runId } = useAnalysis()
  const scopedEndpoint = runId ? `${endpoint}${endpoint.includes('?') ? '&' : '?'}run_id=${encodeURIComponent(runId)}` : endpoint
  const { data, meta, loading, error } = useApi<Row[]>(scopedEndpoint)
  return <><PageHeader title={title} description={description} aside={runId ? <span className="freshness">任务 {runId}</span> : undefined} />
    {loading && <div className="skeleton-list" aria-label="正在加载"><span/><span/><span/></div>}
    {error && <EmptyState kind="error" title="无法读取该资源" detail={`${error}。系统不会用模拟数据替代失败结果。`} />}
    {!loading && !error && data?.length === 0 && <EmptyState title="当前没有可展示的数据" detail={meta?.warnings[0] ?? '接入对应数据源或调整筛选范围后，记录会出现在这里。'} />}
    {!!data?.length && <div className="table-wrap"><table><thead><tr>{columns.map(([key,label]) => <th key={key}>{label}</th>)}</tr></thead><tbody>{data.map((row,index) => <tr key={String(row.id ?? row.event_id ?? row.detection_id ?? row.session_id ?? index)}>{columns.map(([key]) => <td key={key}>{formatCell(valueAt(row,key), key)}</td>)}</tr>)}</tbody></table></div>}
  </>
}

function valueAt(row: Row, path: string): unknown {
  for (const candidate of path.split('|')) {
    const value = candidate.split('.').reduce<unknown>((current, key) => current && typeof current === 'object' ? (current as Record<string, unknown>)[key] : undefined, row)
    if (value != null && value !== '') return value
  }
  return undefined
}

function formatCell(value: unknown, key = '') {
  if (value == null) return '—'
  if (Array.isArray(value)) return value.map(String).join(' · ') || '—'
  if (typeof value === 'object') return JSON.stringify(value)
  if (typeof value === 'number' && /confidence|score|completeness|mapping_rate|rate/.test(key) && value >= 0 && value <= 1) return `${(value * 100).toFixed(0)}%`
  if (typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(value)) return new Date(value).toLocaleString('zh-CN')
  return String(value)
}
