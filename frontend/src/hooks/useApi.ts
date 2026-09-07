import { useEffect, useState } from 'react'
import { apiGet, type ApiEnvelope } from '../api/client'

export function useApi<T>(path: string) {
  const [result, setResult] = useState<ApiEnvelope<T> | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  useEffect(() => {
    const controller = new AbortController()
    setLoading(true); setError(null)
    apiGet<T>(path, controller.signal).then(setResult).catch((reason: Error) => {
      if (reason.name !== 'AbortError') setError(reason.message)
    }).finally(() => setLoading(false))
    return () => controller.abort()
  }, [path])
  return { data: result?.data ?? null, meta: result?.meta ?? null, error, loading }
}

