import { createContext, type ReactNode, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'
import { useLocation, useNavigate, useSearchParams } from 'react-router-dom'
import { apiGet } from '../api/client'

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
const ALL_RUNS = '__all__'

export function AnalysisProvider({ children }: { children: ReactNode }) {
  const location = useLocation()
  const navigate = useNavigate()
  const [params] = useSearchParams()
  const [runs, setRuns] = useState<AnalysisRunSummary[]>([])
  const initialStoredRun = useRef(localStorage.getItem(STORAGE_KEY))
  const shouldAutoSelectRun = useRef(initialStoredRun.current == null)
  const [currentRunId, setCurrentRunIdState] = useState<string | null>(() => {
    const stored = initialStoredRun.current
    return stored === ALL_RUNS ? null : stored
  })
  const urlRunId = params.get('run_id')

  const refreshRuns = useCallback(() => {
    apiGet<AnalysisRunSummary[]>('/api/v1/analysis/tasks')
      .then(response => setRuns(response.data ?? []))
      .catch(() => undefined)
  }, [])

  useEffect(() => {
    refreshRuns()
    const id = window.setInterval(refreshRuns, 5000)
    window.addEventListener('focus', refreshRuns)
    window.addEventListener('traceguard:runs-updated', refreshRuns)
    return () => {
      window.clearInterval(id)
      window.removeEventListener('focus', refreshRuns)
      window.removeEventListener('traceguard:runs-updated', refreshRuns)
    }
  }, [refreshRuns])

  useEffect(() => {
    if (urlRunId && urlRunId !== currentRunId) setCurrentRunIdState(urlRunId)
  }, [urlRunId, currentRunId])

  useEffect(() => {
    if (!currentRunId && shouldAutoSelectRun.current && runs[0]?.task_id) {
      shouldAutoSelectRun.current = false
      setCurrentRunIdState(runs[0].task_id)
    }
  }, [currentRunId, runs])

  useEffect(() => {
    if (currentRunId) localStorage.setItem(STORAGE_KEY, currentRunId)
    else if (!shouldAutoSelectRun.current) localStorage.setItem(STORAGE_KEY, ALL_RUNS)
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
    shouldAutoSelectRun.current = false
    setCurrentRunIdState(runId)
    const target = navigateToWorkspace ? '/' : `${location.pathname}${location.search}`
    const [base, query = ''] = target.split('?')
    const next = new URLSearchParams(query)
    if (runId) next.set('run_id', runId)
    else next.delete('run_id')
    const suffix = next.toString()
    navigate(suffix ? `${base}?${suffix}` : base)
  }

  const visibleRuns = useMemo(() => {
    if (!currentRunId || runs.some(item => item.task_id === currentRunId)) return runs
    return [{ task_id: currentRunId, upload: { filename: currentRunId } }, ...runs]
  }, [currentRunId, runs])

  const value = useMemo<AnalysisContextValue>(() => ({
    currentRunId,
    currentRun: visibleRuns.find(item => item.task_id === currentRunId) ?? null,
    runs: visibleRuns,
    setCurrentRunId,
    runScopedPath,
  }), [currentRunId, visibleRuns, location.pathname, location.search])

  return <AnalysisContext.Provider value={value}>{children}</AnalysisContext.Provider>
}

export function useAnalysis() {
  const value = useContext(AnalysisContext)
  if (!value) throw new Error('useAnalysis must be used inside AnalysisProvider')
  return value
}
