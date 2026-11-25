import { useEffect, useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { useAuth } from '../../lib/auth'
import { edition as editionApi, type EditionInfo } from '../../lib/api'

const REQUEST_ACCESS_URL = import.meta.env.VITE_REQUEST_ACCESS_URL as string | undefined

export default function Register() {
  const { register } = useAuth()
  const navigate = useNavigate()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [fullName, setFullName] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [params] = useSearchParams()
  const invite = params.get('invite') ?? undefined
  const [info, setInfo] = useState<EditionInfo | null>(null)
  const [inviteEmail, setInviteEmail] = useState<string | null>(null)
  const [inviteInvalid, setInviteInvalid] = useState(false)

  useEffect(() => {
    // No invite token = redirect to login (registration is invite-only)
    if (!invite) {
      navigate('/login', { replace: true })
      return
    }
    editionApi.info().then(setInfo).catch(() => setInfo(null))
    editionApi
      .lookupInvite(invite)
      .then((r) => {
        if (r.valid && r.email) {
          setInviteEmail(r.email)
          setEmail(r.email)
        } else {
          setInviteInvalid(true)
        }
      })
      .catch(() => setInviteInvalid(true))
  }, [invite, navigate])

  // Invite-only instance and no usable invite: explain instead of showing a form that will fail
  const blocked = info?.registration === 'invite' && (!invite || inviteInvalid)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    setLoading(true)
    try {
      await register(email, password, fullName || undefined, invite)
      navigate('/login')
    } catch (err: unknown) {
      const detail = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
      const msg = Array.isArray(detail)
        ? detail.map((e: { msg?: string }) => e.msg ?? JSON.stringify(e)).join(', ')
        : typeof detail === 'string'
        ? detail
        : 'registration failed'
      setError(msg)
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
              CREATE ACCOUNT
            </div>
            <div className="text-sm" style={{ color: '#3a3a44', letterSpacing: '1px' }}>
              join MAILØX
            </div>
          </div>

          {blocked ? (
            <div className="space-y-4 text-sm" style={{ color: '#9a9aa4' }}>
              <p>
                {inviteInvalid
                  ? 'This invitation link is invalid, expired or already used.'
                  : 'Accounts on this instance are created by invitation only.'}
              </p>
              {info?.edition === 'saas' && REQUEST_ACCESS_URL ? (
                <a href={REQUEST_ACCESS_URL} className="btn-primary w-full justify-center">
                  request access
                </a>
              ) : (
                <p>Ask the administrator of this instance for an invitation.</p>
              )}
            </div>
          ) : (
          <form onSubmit={handleSubmit} className="space-y-5">
            <div>
              <label
                className="block mb-1.5 text-xs"
                style={{ color: '#E8173A', letterSpacing: '2px' }}
              >
                FULL NAME <span style={{ color: '#3a3a44' }}>(optional)</span>
              </label>
              <input
                type="text"
                className="input"
                value={fullName}
                onChange={(e) => setFullName(e.target.value)}
                placeholder="Alex Analyst"
              />
            </div>
            <div>
              <label
                className="block mb-1.5 text-xs"
                style={{ color: '#E8173A', letterSpacing: '2px' }}
              >
                EMAIL
              </label>
              <input
                type="email"
                className="input"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@example.com"
                required
                readOnly={!!inviteEmail}
                style={inviteEmail ? { opacity: 0.7 } : undefined}
              />
              {inviteEmail && (
                <div className="text-xs mt-1" style={{ color: '#3a3a44', letterSpacing: '0.5px' }}>
                  invitation issued for this address
                </div>
              )}
            </div>
            <div>
              <label
                className="block mb-1.5 text-xs"
                style={{ color: '#E8173A', letterSpacing: '2px' }}
              >
                PASSWORD
              </label>
              <input
                type="password"
                className="input"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                required
                minLength={12}
              />
              <div className="text-xs mt-1" style={{ color: '#3a3a44', letterSpacing: '0.5px' }}>
                12–128 chars · upper · lower · digit · special
              </div>
            </div>

            {error && (
              <div
                className="text-xs px-3 py-2 border"
                style={{
                  color: '#E8173A',
                  background: 'rgba(232,23,58,0.05)',
                  borderColor: 'rgba(232,23,58,0.3)',
                  letterSpacing: '0.5px',
                }}
              >
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="btn-primary w-full justify-center disabled:opacity-50"
            >
              {loading ? 'creating account…' : 'create account'}
            </button>
          </form>
          )}

          <p className="text-sm mt-5 text-center" style={{ color: '#3a3a44', letterSpacing: '1px' }}>
            already registered?{' '}
            <Link
              to="/login"
              className="transition-colors"
              style={{ color: '#666672', borderBottom: '1px solid #3a3a44' }}
              onMouseEnter={(e) => (e.currentTarget.style.color = '#c8ccd4')}
              onMouseLeave={(e) => (e.currentTarget.style.color = '#666672')}
            >
              sign in
            </Link>
          </p>
        </div>
      </div>
    </div>
  )
}
