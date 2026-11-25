/**
 * AuthProvider — MFA login wiring and logout robustness.
 */
import { act, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { AuthProvider, useAuth, type LoginResult } from './auth'

const api = vi.hoisted(() => ({
  auth: {
    login: vi.fn(),
    mfaAuthenticate: vi.fn(),
    me: vi.fn(),
    refresh: vi.fn(),
    localSession: vi.fn(),
    logout: vi.fn(),
    register: vi.fn(),
  },
  orgs: { list: vi.fn() },
  edition: { info: vi.fn() },
  setAccessToken: vi.fn(),
  setAuthFailureHandler: vi.fn(),
}))

vi.mock('./api', () => api)

const clearSpy = vi.hoisted(() => vi.fn())
vi.mock('./queryClient', () => ({ queryClient: { clear: clearSpy } }))

const user = { id: 'u1', email: 'a@b.c', full_name: null, is_active: true, mfa_enabled: true, is_platform_admin: false, created_at: '' }

let ctx: ReturnType<typeof useAuth>
function Probe() {
  ctx = useAuth()
  return <div>{ctx.loading ? 'loading' : ctx.user ? `user:${ctx.user.email}` : 'anon'}</div>
}

async function mountSignedOut() {
  render(<AuthProvider><Probe /></AuthProvider>)
  await screen.findByText('anon')
}

beforeEach(() => {
  vi.clearAllMocks()
  api.edition.info.mockResolvedValue({ auth: 'accounts' })
  api.auth.refresh.mockRejectedValue(new Error('no session'))
  api.orgs.list.mockResolvedValue([])
  api.auth.me.mockResolvedValue(user)
})

describe('AuthProvider', () => {
  it('login returns mfa_required without touching the token or /me', async () => {
    api.auth.login.mockResolvedValue({ mfa_required: true, mfa_token: 'mfa-tok' })
    await mountSignedOut()

    let result: LoginResult | undefined
    await act(async () => { result = await ctx.login('a@b.c', 'pw') })

    expect(result).toEqual({ status: 'mfa_required', mfaToken: 'mfa-tok' })
    expect(api.setAccessToken).not.toHaveBeenCalledWith(expect.any(String))
    expect(api.auth.me).not.toHaveBeenCalled()
    expect(screen.getByText('anon')).toBeInTheDocument()
  })

  it('completeMfa exchanges the code and finishes login', async () => {
    api.auth.mfaAuthenticate.mockResolvedValue({ access_token: 'at', token_type: 'bearer', expires_in: 900 })
    await mountSignedOut()

    await act(async () => { await ctx.completeMfa('mfa-tok', '123456') })

    expect(api.auth.mfaAuthenticate).toHaveBeenCalledWith('mfa-tok', '123456')
    expect(api.setAccessToken).toHaveBeenCalledWith('at')
    expect(screen.getByText('user:a@b.c')).toBeInTheDocument()
  })

  it('login without MFA sets the token and loads the user', async () => {
    api.auth.login.mockResolvedValue({ access_token: 'at', token_type: 'bearer', expires_in: 900 })
    await mountSignedOut()

    let result: LoginResult | undefined
    await act(async () => { result = await ctx.login('a@b.c', 'pw') })

    expect(result).toEqual({ status: 'ok' })
    expect(api.setAccessToken).toHaveBeenCalledWith('at')
    expect(screen.getByText('user:a@b.c')).toBeInTheDocument()
  })

  it('logout clears state and the query cache even when the API call fails', async () => {
    api.auth.login.mockResolvedValue({ access_token: 'at', token_type: 'bearer', expires_in: 900 })
    api.auth.logout.mockRejectedValue(new Error('network down'))
    await mountSignedOut()
    await act(async () => { await ctx.login('a@b.c', 'pw') })
    expect(screen.getByText('user:a@b.c')).toBeInTheDocument()

    await act(async () => {
      await expect(ctx.logout(true)).rejects.toThrow('network down')
    })

    expect(api.auth.logout).toHaveBeenCalledWith(true)
    expect(clearSpy).toHaveBeenCalled()
    expect(api.setAccessToken).toHaveBeenLastCalledWith(null)
    await waitFor(() => expect(screen.getByText('anon')).toBeInTheDocument())
  })

  it('registers a session-expired handler that clears state', async () => {
    await mountSignedOut()
    const handler = api.setAuthFailureHandler.mock.calls.find(([h]) => typeof h === 'function')?.[0] as () => void
    expect(handler).toBeTypeOf('function')
    act(() => handler())
    expect(clearSpy).toHaveBeenCalled()
  })
})
