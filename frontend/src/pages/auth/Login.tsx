import { useEffect, useRef, useState } from 'react'
import { Link, useNavigate, useLocation } from 'react-router-dom'
import { useAuth } from '../../lib/auth'

/** Backend issues the mfa_token with a 5 min lifetime; drop it slightly earlier. */
const MFA_TOKEN_TTL_MS = 4.5 * 60 * 1000

type ApiError = { response?: { status?: number; data?: { detail?: unknown } } }

function errorDetail(err: unknown, fallback: string): string {
  const detail = (err as ApiError)?.response?.data?.detail
  if (Array.isArray(detail)) {
    return detail.map((e: { msg?: string }) => e.msg ?? JSON.stringify(e)).join(', ')
  }
  return typeof detail === 'string' ? detail : fallback
}

const labelStyle = { color: '#E8173A', letterSpacing: '2px' }
const linkButtonStyle = {
  color: '#3a3a44',
  letterSpacing: '1px',
  background: 'transparent',
  border: 'none',
  cursor: 'pointer',
  padding: 0,
}

function hoverIn(e: React.MouseEvent<HTMLElement>) { e.currentTarget.style.color = '#c8ccd4' }
function hoverOut(e: React.MouseEvent<HTMLElement>) { e.currentTarget.style.color = '#3a3a44' }

function ErrorBox({ message }: { message: string }) {
  return (
    <div
      role="alert"
      className="text-xs px-3 py-2 border"
      style={{
        color: '#E8173A',
        background: 'rgba(232,23,58,0.05)',
        borderColor: 'rgba(232,23,58,0.3)',
        letterSpacing: '0.5px',
      }}
    >
      {message}
    </div>
  )
}

export default function Login() {
  const { login, completeMfa } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const from = (location.state as { from?: { pathname: string } })?.from?.pathname ?? '/'
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  // Second factor. The mfa_token only ever lives in this component's state
  // (memory) — never in localStorage/sessionStorage.
  const [mfaToken, setMfaToken] = useState<string | null>(null)
  const [code, setCode] = useState('')
  const [useBackup, setUseBackup] = useState(false)
  const expiryTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  function clearExpiryTimer() {
    if (expiryTimer.current) clearTimeout(expiryTimer.current)
    expiryTimer.current = null
  }

  function backToCredentials(message: string | null) {
    clearExpiryTimer()
    setMfaToken(null)
    setCode('')
    setUseBackup(false)
    setPassword('')
    setError(message)
  }

  useEffect(() => clearExpiryTimer, [])

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    setLoading(true)
    try {
      const result = await login(email, password)
      if (result.status === 'mfa_required') {
        setMfaToken(result.mfaToken)
        setCode('')
        clearExpiryTimer()
        expiryTimer.current = setTimeout(
          () => backToCredentials('verification timed out — sign in again'),
          MFA_TOKEN_TTL_MS,
        )
        return
      }
      navigate(from, { replace: true })
    } catch (err: unknown) {
      setError(errorDetail(err, 'authentication failed'))
    } finally {
      setLoading(false)
    }
  }

  async function handleMfaSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!mfaToken) return
    setError(null)
    setLoading(true)
    const normalized = useBackup
      ? code.replace(/[\s-]/g, '').toUpperCase()
      : code.replace(/\s/g, '')
    try {
      await completeMfa(mfaToken, normalized)
      clearExpiryTimer()
      setMfaToken(null)
      navigate(from, { replace: true })
    } catch (err: unknown) {
      const status = (err as ApiError)?.response?.status
      const detail = errorDetail(err, 'verification failed')
      if (status === 401 && /mfa token|invalid request/i.test(detail)) {
        // mfa_token expired or rejected: the challenge is dead, restart at step 1
        backToCredentials('verification session expired — sign in again')
      } else {
        setCode('')
        setError(detail)
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <div
      className="min-h-screen flex items-center justify-center p-4"
      style={{ background: '#0a0a0a' }}
    >
      <div className="w-full max-w-sm">
        {/* Logo */}
        <div className="mb-12 text-center">
          <div className="text-3xl mb-2" style={{ letterSpacing: '5px' }}>
            <span style={{ color: '#E8173A' }}>MAIL</span>
            <span style={{ color: '#E8173A' }}>Ø</span>
            <span style={{ color: '#e8ecf2' }}>X</span>
          </div>
          <div className="text-xs" style={{ color: '#3a3a44', letterSpacing: '2px' }}>
            Khaøtic Security
          </div>
        </div>

        {/* Card */}
        <div
          className="border border-border p-8"
          style={{ borderTop: '2px solid #E8173A', background: '#121212' }}
        >
          <div className="mb-7">
            <div className="text-sm text-text-primary mb-1.5" style={{ letterSpacing: '3px' }}>
              {mfaToken ? 'TWO-FACTOR' : 'SIGN IN'}
            </div>
            <div className="text-sm" style={{ color: '#3a3a44', letterSpacing: '1px' }}>
              {mfaToken
                ? useBackup
                  ? 'enter one of your backup codes'
                  : 'enter the 6-digit code from your authenticator'
                : 'email infrastructure security assessment'}
            </div>
          </div>

          {mfaToken ? (
            <form onSubmit={handleMfaSubmit} className="space-y-5">
              <div>
                <label htmlFor="login-mfa-code" className="block mb-1.5 text-xs" style={labelStyle}>
                  {useBackup ? 'BACKUP CODE' : 'AUTHENTICATION CODE'}
                </label>
                <input
                  id="login-mfa-code"
                  key={useBackup ? 'backup' : 'totp'}
                  type="text"
                  className="input font-mono"
                  value={code}
                  onChange={(e) =>
                    setCode(useBackup ? e.target.value : e.target.value.replace(/\D/g, '').slice(0, 6))
                  }
                  placeholder={useBackup ? 'XXXXXXXXXX' : '000000'}
                  inputMode={useBackup ? 'text' : 'numeric'}
                  autoComplete="one-time-code"
                  maxLength={useBackup ? 24 : 6}
                  style={{ letterSpacing: '4px' }}
                  required
                  autoFocus
                />
              </div>

              {error && <ErrorBox message={error} />}

              <button
                type="submit"
                disabled={loading || (!useBackup && code.length !== 6)}
                className="btn-primary w-full justify-center disabled:opacity-50"
              >
                {loading ? 'verifying…' : 'verify'}
              </button>
            </form>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-5">
              <div>
                <label htmlFor="login-email" className="block mb-1.5 text-xs" style={labelStyle}>
                  EMAIL
                </label>
                <input
                  id="login-email"
                  type="email"
                  className="input"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="you@example.com"
                  required
                  autoFocus
                />
              </div>
              <div>
                <label htmlFor="login-password" className="block mb-1.5 text-xs" style={labelStyle}>
                  PASSWORD
                </label>
                <input
                  id="login-password"
                  type="password"
                  className="input"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  required
                />
              </div>

              {error && <ErrorBox message={error} />}

              <button
                type="submit"
                disabled={loading}
                className="btn-primary w-full justify-center disabled:opacity-50"
              >
                {loading ? 'signing in…' : 'sign in'}
              </button>
            </form>
          )}

          {mfaToken ? (
            <div className="mt-5 flex items-center justify-between">
              <button
                type="button"
                onClick={() => { setUseBackup((b) => !b); setCode(''); setError(null) }}
                className="text-xs transition-colors"
                style={linkButtonStyle}
                onMouseEnter={hoverIn}
                onMouseLeave={hoverOut}
              >
                {useBackup ? 'use authenticator code' : 'use a backup code'}
              </button>
              <button
                type="button"
                onClick={() => backToCredentials(null)}
                className="text-xs transition-colors"
                style={linkButtonStyle}
                onMouseEnter={hoverIn}
                onMouseLeave={hoverOut}
              >
                ← back to sign in
              </button>
            </div>
          ) : (
            <div className="mt-5 flex items-center justify-between">
              <Link
                to="/forgot-password"
                className="text-xs transition-colors"
                style={{ color: '#3a3a44', letterSpacing: '1px' }}
                onMouseEnter={hoverIn}
                onMouseLeave={hoverOut}
              >
                forgot password?
              </Link>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
