import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, apiGet } from './client'

describe('apiGet', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('returns the resource envelope without inventing fallback data', async () => {
    const envelope = { data: [], meta: { request_id: 'req_1', schema_version: '1.0', mode: 'replay', generated_at: '2026-09-07T08:00:00Z', next_cursor: null, warnings: ['尚未接入'] } }
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => envelope }))
    await expect(apiGet('/api/agents')).resolves.toEqual(envelope)
  })

  it('surfaces HTTP failures instead of returning mock data', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, status: 503 }))
    await expect(apiGet('/api/events')).rejects.toEqual(expect.objectContaining({ status: 503 }))
  })
})
