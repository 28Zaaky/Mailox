/**
 * 401 handling: single-flight refresh.
 *
 * The backend rotates refresh tokens with reuse detection, so two concurrent
 * POST /auth/refresh revoke the whole session family. These tests drive the real
 * axios client through an in-memory adapter.
 */
import { AxiosError, type AxiosAdapter, type AxiosResponse, type InternalAxiosRequestConfig } from 'axios'
import { beforeEach, describe, expect, it, vi } from 'vitest'

type ApiModule = typeof import('./api')

let api: ApiModule
let calls: { method: string; url: string; auth: string | undefined }[]

function ok(config: InternalAxiosRequestConfig, data: unknown): AxiosResponse {
  return { data, status: 200, statusText: 'OK', headers: {}, config }
}

function fail(config: InternalAxiosRequestConfig, status: number, detail = 'nope'): never {
  const response = { data: { detail }, status, statusText: String(status), headers: {}, config }
  throw new AxiosError(`HTTP ${status}`, AxiosError.ERR_BAD_REQUEST, config, null, response)
}

/**
 * Fake backend: /auth/refresh answers `refresh` (after a tick so callers overlap);
 * every other route accepts only `Bearer fresh`.
 */
function installBackend(refresh: (config: InternalAxiosRequestConfig) => AxiosResponse) {
  const adapter: AxiosAdapter = async (config) => {
    const url = config.url ?? ''
    const auth = config.headers?.Authorization as string | undefined
    calls.push({ method: (config.method ?? 'get').toUpperCase(), url, auth })
    await new Promise((r) => setTimeout(r, 5))
    if (url.includes('/auth/refresh')) return refresh(config)
    if (url.includes('/auth/login')) return fail(config, 401, 'Invalid credentials')
    if (auth === 'Bearer fresh') return ok(config, { url })
    return fail(config, 401)
  }
  api.apiClient.defaults.adapter = adapter
}

const refreshCalls = () => calls.filter((c) => c.url.includes('/auth/refresh')).length

beforeEach(async () => {
  vi.resetModules() // fresh module state (token, in-flight promise, expiry flag)
  api = await import('./api')
  calls = []
  api.setAccessToken('stale')
})

describe('single-flight refresh', () => {
  it('two concurrent 401s trigger exactly one /auth/refresh, then both requests are retried', async () => {
    installBackend((config) => ok(config, { access_token: 'fresh', token_type: 'bearer', expires_in: 900 }))

    const [a, b] = await Promise.all([
      api.apiClient.get('/orgs'),
      api.apiClient.get('/auth/me'),
    ])

    expect(refreshCalls()).toBe(1)
    expect(a.data).toEqual({ url: '/orgs' })
    expect(b.data).toEqual({ url: '/auth/me' })
    expect(api.getAccessToken()).toBe('fresh')
    // each original request: once with the stale token, once retried with the fresh one
    expect(calls.filter((c) => c.url === '/orgs').map((c) => c.auth)).toEqual(['Bearer stale', 'Bearer fresh'])
    expect(calls.filter((c) => c.url === '/auth/me').map((c) => c.auth)).toEqual(['Bearer stale', 'Bearer fresh'])
  })

  it('bootstrap refresh and a 401 retry share the same in-flight call', async () => {
    installBackend((config) => ok(config, { access_token: 'fresh', token_type: 'bearer', expires_in: 900 }))

    const [token, res] = await Promise.all([api.auth.refresh(), api.apiClient.get('/orgs')])

    expect(token).toBe('fresh')
    expect(res.data).toEqual({ url: '/orgs' })
    expect(refreshCalls()).toBe(1)
  })

  it('on refresh failure: no refresh retry, failure handler runs once, all requests reject', async () => {
    installBackend((config) => fail(config, 401, 'Refresh token reuse detected'))
    const onFailure = vi.fn()
    api.setAuthFailureHandler(onFailure)

    const results = await Promise.allSettled([
      api.apiClient.get('/orgs'),
      api.apiClient.get('/auth/me'),
      api.apiClient.get('/scans'),
    ])

    expect(results.every((r) => r.status === 'rejected')).toBe(true)
    expect(refreshCalls()).toBe(1)
    expect(onFailure).toHaveBeenCalledTimes(1)
    expect(api.getAccessToken()).toBeNull()

    // Later 401s fail fast: no new refresh storm, no second redirect
    await expect(api.apiClient.get('/orgs')).rejects.toBeInstanceOf(AxiosError)
    expect(refreshCalls()).toBe(1)
    expect(onFailure).toHaveBeenCalledTimes(1)
  })

  it('does not try to refresh on a 401 from an auth endpoint', async () => {
    installBackend((config) => ok(config, { access_token: 'fresh', token_type: 'bearer', expires_in: 900 }))

    await expect(api.auth.login('a@b.c', 'wrong')).rejects.toBeInstanceOf(AxiosError)
    expect(refreshCalls()).toBe(0)
  })

  it('a 401 for a request sent before a completed refresh is replayed without refreshing again', async () => {
    installBackend((config) => ok(config, { access_token: 'fresh', token_type: 'bearer', expires_in: 900 }))

    await api.apiClient.get('/orgs') // refresh #1 → token is now "fresh"
    expect(refreshCalls()).toBe(1)

    // Simulate a late response: /scans leaves with the old token, and its 401 only
    // comes back after another refresh has already installed the new token.
    let release!: () => void
    const gate = new Promise<void>((r) => { release = r })
    const backend = api.apiClient.defaults.adapter as AxiosAdapter
    api.apiClient.defaults.adapter = async (config) => {
      if (config.url === '/scans' && config.headers.Authorization === 'Bearer stale') {
        calls.push({ method: 'GET', url: '/scans', auth: 'Bearer stale' })
        await gate
        return fail(config, 401)
      }
      return backend(config)
    }

    api.setAccessToken('stale')
    const late = api.apiClient.get('/scans')
    await vi.waitFor(() => expect(calls.some((c) => c.url === '/scans')).toBe(true))
    api.setAccessToken('fresh')
    release()
    await expect(late).resolves.toMatchObject({ data: { url: '/scans' } })
    expect(refreshCalls()).toBe(1)
  })
})
