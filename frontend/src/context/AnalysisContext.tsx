import { createContext, type ReactNode, useContext, useEffect, useMemo, useState } from 'react'
import { useLocation, useNavigate, useSearchParams } from 'react-router-dom'
import { useApi } from '../hooks/useApi'

export interface AnalysisRunSummary {
  task_id: string
  status?: string
  created_at?: string
  updated_at?: string
  upload?: { filename?: string; size?: number }
  result?: null | Record<string, unknown>
}

interface AnalysisContextValue {
  currentRunId: string | null
  currentRun: AnalysisRunSummary | null
  runs: AnalysisRunSummary[]
  setCurrentRunId: (runId: string | null, navigateToWorkspace?: boolean) => void
  runScopedPath: (path: string, extra?: Record<string, string | null | undefined>) => string
}

const AnalysisContext = createContext<AnalysisContextValue | null>(null)
const STORAGE_KEY = 'traceguard.current_run_id'

export function AnalysisProvider({ children }: { children: ReactNode }) {
  const location = useLocation()
  const navigate = useNavigate()
  const [params] = useSearchParams()
  const { data } = useApi<AnalysisRunSummary[]>('/api/v1/analysis/tasks')
  const runs = data ?? []
  const [currentRunId, setCurrentRunIdState] = useState<string | null>(() => localStorage.getItem(STORAGE_KEY))
  const urlRunId = params.get('run_id')

  useEffect(() => {
    if (urlRunId && urlRunId !== currentRunId) setCurrentRunIdState(urlRunId)
  }, [urlRunId, currentRunId])

  useEffect(() => {
    if (!currentRunId && runs[0]?.task_id) setCurrentRunIdState(runs[0].task_id)
  }, [currentRunId, runs])

  useEffect(() => {
    if (currentRunId) localStorage.setItem(STORAGE_KEY, currentRunId)
    else localStorage.removeItem(STORAGE_KEY)
  }, [currentRunId])

  const runScopedPath = (path: string, extra?: Record<string, string | null | undefined>) => {
    const [base, query = ''] = path.split('?')
    const next = new URLSearchParams(query)
    if (currentRunId) next.set('run_id', currentRunId)
    else next.delete('run_id')
    Object.entries(extra ?? {}).forEach(([key, value]) => {
      if (value == null || value === '') next.delete(key)
      else next.set(key, value)
    })
    const suffix = next.toString()
    return suffix ? `${base}?${suffix}` : base
  }

  const setCurrentRunId = (runId: string | null, navigateToWorkspace = false) => {
    setCurrentRunIdState(runId)
    const target = navigateToWorkspace ? '/' : `${location.pathname}${location.search}`
    const [base, query = ''] = target.split('?')
    const next = new URLSearchParams(query)
    if (runId) next.set('run_id', runId)
    else next.delete('run_id')
    const suffix = next.toString()
    navigate(suffix ? `${base}?${suffix}` : base)
  }

  const value = useMemo<AnalysisContextValue>(() => ({
    currentRunId,
    currentRun: runs.find(item => item.task_id === currentRunId) ?? null,
    runs,
    setCurrentRunId,
    runScopedPath,
  }), [currentRunId, runs, location.pathname, location.search])

  return <AnalysisContext.Provider value={value}>{children}</AnalysisContext.Provider>
}

export function useAnalysis() {
  const value = useContext(AnalysisContext)
  if (!value) throw new Error('useAnalysis must be used inside AnalysisProvider')
  return value
}
