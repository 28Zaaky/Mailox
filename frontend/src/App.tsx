import React, { Suspense, lazy, useState } from 'react'
import { Routes, Route, Navigate, useLocation } from 'react-router-dom'
import { useAuth } from './lib/auth'
import { orgs as orgsApi } from './lib/api'
import { ScanMonitorProvider } from './lib/scan-monitor'
import { Layout } from './components/Layout'
import { ErrorBoundary } from './components/ErrorBoundary'
import Login from './pages/auth/Login'
import Register from './pages/auth/Register'
import ForgotPassword from './pages/auth/ForgotPassword'
import ResetPassword from './pages/auth/ResetPassword'

// Authenticated pages are split per route to keep the initial bundle small.
const Overview = lazy(() => import('./pages/Overview'))
const Assessments = lazy(() => import('./pages/Assessments'))
const AssessmentDetail = lazy(() => import('./pages/AssessmentDetail'))
const Findings = lazy(() => import('./pages/Findings'))
const Reports = lazy(() => import('./pages/Reports'))
const Team = lazy(() => import('./pages/Team'))
const Settings = lazy(() => import('./pages/Settings'))
const DNSAuth = lazy(() => import('./pages/modules/DNSAuth'))
const SMTPDiscovery = lazy(() => import('./pages/modules/SMTPDiscovery'))
const SMTPSecurity = lazy(() => import('./pages/modules/SMTPSecurity'))
const WebmailSecurity = lazy(() => import('./pages/modules/WebmailSecurity'))
const VulnIntel = lazy(() => import('./pages/modules/VulnIntel'))
const IntelDashboard = lazy(() => import('./pages/modules/IntelDashboard'))
const CredentialExposure = lazy(() => import('./pages/modules/CredentialExposure'))
const Assets = lazy(() => import('./pages/modules/Assets'))
const WebPentest = lazy(() => import('./pages/modules/WebPentest'))
const PentestProbes = lazy(() => import('./pages/modules/PentestProbes'))
const Account = lazy(() => import('./pages/Account'))
const FindingDetail = lazy(() => import('./pages/FindingDetail'))
const Projects = lazy(() => import('./pages/Projects'))
const Domains = lazy(() => import('./pages/Domains'))
const AdminAccess = lazy(() => import('./pages/AdminAccess'))
const ProjectDetail = lazy(() => import('./pages/ProjectDetail'))

function PageFallback() {
  return <div className="text-text-muted text-sm font-mono p-6">Loading…</div>
}

function CreateOrgScreen() {
  const { refreshOrgs } = useAuth()
  const [name, setName] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!name.trim()) return
    setLoading(true)
    setError('')
    try {
      await orgsApi.create(name.trim())
      await refreshOrgs()
    } catch {
      setError('Failed to create organization')
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-bg-base flex items-center justify-center p-4">
      <div className="card p-8 w-full max-w-sm">
        <div style={{ marginBottom: '24px' }}>
          <div style={{ fontSize: '18px', fontWeight: 600, color: '#F5F5F5', marginBottom: '6px' }}>
            Create your workspace
          </div>
          <div style={{ fontSize: '13px', color: '#71717A' }}>
            Your organization groups projects, scans and team members.
          </div>
        </div>
        <form onSubmit={handleSubmit}>
          <label className="label block mb-1.5">Organization name</label>
          <input
            className="input w-full mb-4"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Acme Security"
            autoFocus
            required
          />
          {error && <div className="text-xs mb-3" style={{ color: 'var(--color-accent)' }}>{error}</div>}
          <button
            type="submit"
            disabled={loading || !name.trim()}
            className="btn-primary w-full"
          >
            {loading ? 'Creating…' : 'Create workspace'}
          </button>
        </form>
      </div>
    </div>
  )
}

function RequireAuth({ children }: { children: React.ReactNode }) {
  const { user, orgs, loading, orgsLoaded } = useAuth()
  const location = useLocation()
  if (loading || !orgsLoaded) {
    return (
      <div className="min-h-screen bg-bg-base flex items-center justify-center">
        <div className="text-text-muted text-sm font-mono">Loading…</div>
      </div>
    )
  }
  if (!user) return <Navigate to="/login" state={{ from: location }} replace />
  if (orgs.length === 0) return <CreateOrgScreen />
  return <>{children}</>
}

function RequireNoAuth({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth()
  if (loading) return null
  if (user) return <Navigate to="/" replace />
  return <>{children}</>
}

export default function App() {
  return (
    <Routes>
      {/* Public */}
      <Route
        path="/login"
        element={
          <RequireNoAuth>
            <Login />
          </RequireNoAuth>
        }
      />
      <Route
        path="/register"
        element={
          <RequireNoAuth>
            <Register />
          </RequireNoAuth>
        }
      />
      <Route
        path="/forgot-password"
        element={
          <RequireNoAuth>
            <ForgotPassword />
          </RequireNoAuth>
        }
      />
      <Route path="/reset-password" element={<ResetPassword />} />

      {/* Protected */}
      <Route
        path="/*"
        element={
          <RequireAuth>
            <ScanMonitorProvider>
            <Layout>
              <ErrorBoundary>
              <Suspense fallback={<PageFallback />}>
              <Routes>
                <Route path="/" element={<Overview />} />
                <Route path="/assessments" element={<Assessments />} />
                <Route path="/assessments/new" element={<Assessments />} />
                <Route path="/assessments/:scanId" element={<AssessmentDetail />} />
                <Route path="/findings" element={<Findings />} />
                <Route path="/findings/:findingId" element={<FindingDetail />} />
                <Route path="/reports" element={<Reports />} />
                <Route path="/team" element={<Team />} />
                <Route path="/domains" element={<Domains />} />
                <Route path="/admin/access" element={<AdminAccess />} />
                <Route path="/settings" element={<Settings />} />
                <Route path="/settings/orgs/new" element={<Settings />} />
                {/* Module pages */}
                <Route path="/dns-auth" element={<DNSAuth />} />
                <Route path="/smtp-discovery" element={<SMTPDiscovery />} />
                <Route path="/smtp-security" element={<SMTPSecurity />} />
                <Route path="/webmail" element={<WebmailSecurity />} />
                <Route path="/tls" element={<Navigate to="/webmail" replace />} />
                <Route path="/vuln-intel" element={<VulnIntel />} />
                <Route path="/intel" element={<IntelDashboard />} />
                <Route path="/secrets" element={<CredentialExposure />} />
                <Route path="/assets" element={<Assets />} />
                {/* Pentest section */}
                <Route path="/web-pentest" element={<WebPentest />} />
                <Route path="/pentest" element={<PentestProbes />} />
                <Route path="/active-probes" element={<Navigate to="/pentest?tab=active" replace />} />
                <Route path="/canary-probes" element={<Navigate to="/pentest?tab=canary" replace />} />
                <Route path="/credential-test" element={<Navigate to="/pentest?tab=credential" replace />} />
                <Route path="/projects" element={<Projects />} />
                <Route path="/projects/:projectId" element={<ProjectDetail />} />
                <Route path="/account" element={<Account />} />
                <Route path="/preferences" element={<Navigate to="/settings" replace />} />
                <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
              </Suspense>
              </ErrorBoundary>
            </Layout>
            </ScanMonitorProvider>
          </RequireAuth>
        }
      />
    </Routes>
  )
}
