export interface ApiMeta {
  request_id: string
  schema_version: string
  mode: 'live' | 'replay' | 'snapshot'
  generated_at: string
  next_cursor: string | null
  warnings: string[]
}

export interface ApiEnvelope<T> { data: T; meta: ApiMeta }

export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message) }
}

export async function apiGet<T>(path: string, signal?: AbortSignal): Promise<ApiEnvelope<T>> {
  const result = await fetch(path, { signal, headers: { Accept: 'application/json' } })
  if (!result.ok) throw new ApiError(result.status, `请求失败（${result.status}）`)
  return result.json() as Promise<ApiEnvelope<T>>
}

export async function apiPost<T>(path: string, body?: unknown): Promise<ApiEnvelope<T>> {
  const result = await fetch(path, { method: 'POST', headers: { Accept: 'application/json', 'Content-Type': 'application/json' }, body: body == null ? undefined : JSON.stringify(body) })
  if (!result.ok) throw new ApiError(result.status, `请求失败（${result.status}）`)
  return result.json() as Promise<ApiEnvelope<T>>
}

export async function apiUpload<T>(path: string, file: File): Promise<ApiEnvelope<T>> {
  const form = new FormData()
  form.append('file', file)
  const result = await fetch(path, { method: 'POST', headers: { Accept: 'application/json' }, body: form })
  if (!result.ok) throw new ApiError(result.status, `请求失败（${result.status}）`)
  return result.json() as Promise<ApiEnvelope<T>>
}
