import { useState } from 'react'
import { Link } from 'react-router-dom'
import { auth as authApi } from '../../lib/api'

export default function ForgotPassword() {
  const [email, setEmail] = useState('')
  const [sent, setSent] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    setLoading(true)
    try {
      await authApi.forgotPassword(email)
      setSent(true)
    } catch {
      setError('Request failed. Try again.')
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
          {sent ? (
            <div>
              <div className="text-sm text-text-primary mb-4" style={{ letterSpacing: '2px' }}>CHECK YOUR EMAIL</div>
              <p className="text-sm text-text-muted mb-6" style={{ lineHeight: 1.6 }}>
                If an account exists for <span style={{ color: '#c8ccd4' }}>{email}</span>, a reset link has been sent. Check your inbox.
              </p>
              <Link to="/login" className="btn-secondary" style={{ display: 'inline-flex', padding: '9px 20px', fontSize: '13px' }}>
                Back to sign in
              </Link>
            </div>
          ) : (
            <>
              <div className="mb-7">
                <div className="text-sm text-text-primary mb-1.5" style={{ letterSpacing: '3px' }}>RESET PASSWORD</div>
                <div className="text-sm" style={{ color: '#3a3a44', letterSpacing: '1px' }}>Enter your email to receive a reset link</div>
              </div>

              <form onSubmit={handleSubmit} className="space-y-5">
                <div>
                  <label className="block mb-1.5 text-xs" style={{ color: '#E8173A', letterSpacing: '2px' }}>EMAIL</label>
                  <input
                    type="email"
                    className="input"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="you@example.com"
                    required
                    autoFocus
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
                  {loading ? 'SENDING…' : 'SEND RESET LINK'}
                </button>
              </form>

              <div className="mt-6 text-center">
                <Link to="/login" className="text-xs text-text-muted" style={{ letterSpacing: '1px' }}
                  onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.color = '#c8ccd4' }}
                  onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.color = '' }}
                >
                  ← Back to sign in
                </Link>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  )
}
