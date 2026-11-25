import { useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { auth as authApi } from '../../lib/api'

export default function ResetPassword() {
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const token = searchParams.get('token') ?? ''

  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  if (!token) {
    return (
      <div className="min-h-screen flex items-center justify-center p-4" style={{ background: '#0a0a0a' }}>
        <div className="w-full max-w-sm border border-border p-8 text-center" style={{ borderTop: '2px solid #E8173A', background: '#121212' }}>
          <div className="text-sm mb-4" style={{ color: '#E8173A' }}>INVALID LINK</div>
          <p className="text-sm text-text-muted mb-6">This reset link is invalid or has expired.</p>
          <Link to="/forgot-password" className="btn-secondary" style={{ display: 'inline-flex', padding: '9px 20px', fontSize: '13px' }}>
            Request a new link
          </Link>
        </div>
      </div>
    )
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    if (password !== confirm) { setError('Passwords do not match'); return }
    setLoading(true)
    try {
      await authApi.resetPassword(token, password)
      navigate('/login?reset=1')
    } catch (err: unknown) {
      const detail = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
      setError(typeof detail === 'string' ? detail : 'Reset failed. The link may have expired.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center p-4" style={{ background: '#0a0a0a' }}>
      <div className="w-full max-w-sm">
        <div className="mb-12 text-center">
          <div className="text-3xl mb-2" style={{ letterSpacing: '5px' }}>
            <span style={{ color: '#E8173A' }}>MAIL</span>
            <span style={{ color: '#E8173A' }}>Ø</span>
            <span style={{ color: '#e8ecf2' }}>X</span>
          </div>
          <div className="text-xs" style={{ color: '#3a3a44', letterSpacing: '2px' }}>Khaøtic Security</div>
        </div>

        <div className="border border-border p-8" style={{ borderTop: '2px solid #E8173A', background: '#121212' }}>
          <div className="mb-7">
            <div className="text-sm text-text-primary mb-1.5" style={{ letterSpacing: '3px' }}>NEW PASSWORD</div>
            <div className="text-sm" style={{ color: '#3a3a44', letterSpacing: '1px' }}>
              Min. 12 chars · uppercase · lowercase · digit · special
            </div>
          </div>

          <form onSubmit={handleSubmit} className="space-y-5">
            <div>
              <label className="block mb-1.5 text-xs" style={{ color: '#E8173A', letterSpacing: '2px' }}>PASSWORD</label>
              <input
                type="password"
                className="input"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                required
                autoFocus
              />
            </div>
            <div>
              <label className="block mb-1.5 text-xs" style={{ color: '#E8173A', letterSpacing: '2px' }}>CONFIRM</label>
              <input
                type="password"
                className="input"
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                placeholder="••••••••••••"
                required
              />
            </div>

            {error && (
              <div className="text-xs px-3 py-2 border" style={{ color: '#E8173A', background: 'rgba(232,23,58,0.05)', borderColor: 'rgba(232,23,58,0.3)' }}>
                {error}
              </div>
            )}

            <button
              type="submit"
              className="btn-primary w-full"
              style={{ padding: '11px', letterSpacing: '2px', fontSize: '12px' }}
              disabled={loading}
            >
              {loading ? 'SAVING…' : 'SET NEW PASSWORD'}
            </button>
          </form>
        </div>
      </div>
    </div>
  )
}
