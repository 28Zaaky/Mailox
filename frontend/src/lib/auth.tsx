import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from 'react'
import { auth as authApi, edition as editionApi, setAccessToken, setAuthFailureHandler } from './api'
import { isMfaRequired, type Organization, type User } from '../types'
import { orgs as orgsApi } from './api'
import { queryClient } from './queryClient'

// Per-user UI data persisted in localStorage that must not survive the session
// (shared workstation): scan notifications and the legacy unscoped display name.
const SESSION_STORAGE_PREFIXES = ['mailox_notifications', 'mailox_display_name']

function purgeSessionStorage() {
  try {
    const keys: string[] = []
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i)
      if (k && SESSION_STORAGE_PREFIXES.some((p) => k.startsWith(p))) keys.push(k)
    }
    keys.forEach((k) => localStorage.removeItem(k))
  } catch {
    /* storage unavailable */
  }
}

interface AuthState {
  user: User | null
  orgs: Organization[]
  currentOrg: Organization | null
  loading: boolean
  orgsLoaded: boolean
  /** Self-hosted tool: no accounts, no sign-in or sign-out */
  localMode: boolean
}

/**
 * Outcome of the first login step. On `mfa_required` the caller keeps `mfaToken`
 * in memory only (component state) and calls `completeMfa` with the user's code.
 */
export type LoginResult =
  | { status: 'ok' }
  | { status: 'mfa_required'; mfaToken: string }

interface AuthActions {
  login: (email: string, password: string) => Promise<LoginResult>
  completeMfa: (mfaToken: string, code: string) => Promise<void>
  register: (email: string, password: string, full_name?: string, invite?: string) => Promise<void>
  logout: (allDevices?: boolean) => Promise<void>
  setCurrentOrg: (org: Organization) => void
  refreshOrgs: () => Promise<void>
  refreshUser: () => Promise<void>
}

const AuthContext = createContext<(AuthState & AuthActions) | null>(null)

// Module-level lock: React Strict Mode double-invokes effects (mount → unmount → remount).
// Backend uses token rotation with family revocation — a second concurrent refresh call
// sends the already-consumed token and revokes the entire session family.
// This flag prevents the second invocation from reaching the backend.
let _refreshLock = false

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>({
    user: null,
    orgs: [],
    currentOrg: null,
    loading: true,
    orgsLoaded: false,
    localMode: false,
  })

  const loadOrgs = useCallback(async () => {
    try {
      const list = await orgsApi.list()
      setState((s) => {
        // Keep the current org only if it still exists (it may have been deleted)
        const keep = s.currentOrg ? list.find((o) => o.id === s.currentOrg!.id) : undefined
        const next = keep ?? list[0] ?? null
        // Org changed under us: drop cached data scoped to the previous org
        if (s.currentOrg && s.currentOrg.id !== next?.id) queryClient.clear()
        return { ...s, orgs: list, currentOrg: next, orgsLoaded: true }
      })
    } catch {
      setState((s) => ({ ...s, orgsLoaded: true }))
    }
  }, [])

  useEffect(() => {
    if (_refreshLock) return
    _refreshLock = true
    const start = async () => {
      const info = await editionApi.info().catch(() => null)
      const localMode = info?.auth === 'local'
      setState((s) => ({ ...s, localMode }))
      try {
        await authApi.refresh() // single-flight; stores the new access token
      } catch {
        if (!localMode) throw new Error('signed out')
        const data = await authApi.localSession()
        setAccessToken(data.access_token)
      }
      const user = await authApi.me()
      setState((s) => ({ ...s, user }))
      await loadOrgs()
      setState((s) => ({ ...s, loading: false }))
    }
    start()
      .catch(() => {
        setState((s) => ({ ...s, loading: false, orgsLoaded: true }))
      })
      .finally(() => { _refreshLock = false })
  }, [loadOrgs])

  const clearSession = useCallback(() => {
    setAccessToken(null)
    queryClient.clear()
    purgeSessionStorage()
    setState((s) => ({ ...s, user: null, orgs: [], currentOrg: null, loading: false, orgsLoaded: true }))
  }, [])

  // Refresh failed in the API layer (session revoked/expired): drop local state
  // once; ProtectedRoute then redirects to /login.
  useEffect(() => {
    setAuthFailureHandler(clearSession)
    return () => setAuthFailureHandler(null)
  }, [clearSession])

  const finishLogin = useCallback(async (accessToken: string) => {
    setAccessToken(accessToken)
    const user = await authApi.me()
    setState((s) => ({ ...s, user }))
    await loadOrgs()
  }, [loadOrgs])

  const login = useCallback(async (email: string, password: string): Promise<LoginResult> => {
    const data = await authApi.login(email, password)
    if (isMfaRequired(data)) {
      return { status: 'mfa_required', mfaToken: data.mfa_token }
    }
    await finishLogin(data.access_token)
    return { status: 'ok' }
  }, [finishLogin])

  const completeMfa = useCallback(async (mfaToken: string, code: string) => {
    const data = await authApi.mfaAuthenticate(mfaToken, code)
    await finishLogin(data.access_token)
  }, [finishLogin])

  const register = useCallback(
    async (email: string, password: string, full_name?: string, invite?: string) => {
      await authApi.register(email, password, full_name, invite)
    },
    []
  )

  // Local state is always cleared, even if the API call fails (network down,
  // token already revoked…); the error is still surfaced to the caller.
  const logout = useCallback(async (allDevices = false) => {
    try {
      await authApi.logout(allDevices)
    } finally {
      clearSession()
    }
  }, [clearSession])

  const setCurrentOrg = useCallback((org: Organization) => {
    // Clear all cached queries on org switch — prevents cross-tenant data leak
    queryClient.clear()
    setState((s) => ({ ...s, currentOrg: org }))
  }, [])

  const refreshOrgs = loadOrgs

  const refreshUser = useCallback(async () => {
    try {
      const user = await authApi.me()
      setState((s) => ({ ...s, user }))
    } catch {
      // not fatal
    }
  }, [])

  return (
    <AuthContext.Provider
      value={{ ...state, login, completeMfa, register, logout, setCurrentOrg, refreshOrgs, refreshUser }}
    >
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider')
  return ctx
}
