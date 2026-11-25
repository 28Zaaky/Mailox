/**
 * Overview page — empty state detection tests.
 *
 * Strategy: mock the API hooks so we can control what stats / scanList return
 * and assert which UI renders.
 */
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { vi, describe, it, expect, beforeEach } from 'vitest'
import Overview from './Overview'

// ── Shared mocks ──────────────────────────────────────────────────────────────

vi.mock('../lib/auth', () => ({
  useAuth: () => ({ currentOrg: { id: 'org-1' } }),
}))

vi.mock('../lib/api', () => ({
  findings: {
    summary: vi.fn(),
    list: vi.fn(),
  },
  orgs: {
    stats: vi.fn(),
  },
  scans: {
    list: vi.fn(),
  },
}))

import { findings as findingsApi, orgs as orgsApi, scans as scansApi } from '../lib/api'

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeStats(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    total_scans: 0,
    active_scans: 0,
    open_critical: 0,
    open_high: 0,
    latest_scan_id: null,
    latest_risk_score: null,
    latest_risk_posture: null,
    ...overrides,
  }
}

function makeQueryClient() {
  return new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  })
}

function makeScan(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    id: 'scan-1',
    target_domain: 'example.com',
    status: 'completed',
    risk_score: 42,
    finding_count: 3,
    created_at: '2024-01-01T00:00:00Z',
    started_at: '2024-01-01T00:00:00Z',
    completed_at: '2024-01-01T00:05:00Z',
    progress_pct: 100,
    current_engine: null,
    ...overrides,
  }
}

function renderOverview() {
  const qc = makeQueryClient()
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <Overview />
      </MemoryRouter>
    </QueryClientProvider>
  )
}

// ── Setup ─────────────────────────────────────────────────────────────────────

beforeEach(() => {
  vi.clearAllMocks()
  // Default: silence findings queries
  ;(findingsApi.summary as ReturnType<typeof vi.fn>).mockResolvedValue({ total: 0, by_severity: {}, by_status: {}, by_engine: {} })
  ;(findingsApi.list as ReturnType<typeof vi.fn>).mockResolvedValue({ items: [], total: 0 })
})

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('Overview — empty state (zero assessments)', () => {
  it('shows empty state when org has zero assessments', async () => {
    ;(orgsApi.stats as ReturnType<typeof vi.fn>).mockResolvedValue(makeStats({ total_scans: 0 }))
    ;(scansApi.list as ReturnType<typeof vi.fn>).mockResolvedValue([])

    renderOverview()

    expect(await screen.findByText('Start your first assessment')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: /your first assessment/i })).toBeInTheDocument()
    expect(screen.getByText('Understand your email infrastructure exposure in minutes.')).toBeInTheDocument()
  })

  it('does not show redundant zero-value KPI cards in empty state', async () => {
    ;(orgsApi.stats as ReturnType<typeof vi.fn>).mockResolvedValue(makeStats({ total_scans: 0 }))
    ;(scansApi.list as ReturnType<typeof vi.fn>).mockResolvedValue([])

    renderOverview()

    await screen.findByText('Start your first assessment')

    // KPI strip must not exist
    expect(screen.queryByText('Assessments')).not.toBeInTheDocument()
    expect(screen.queryByText('Running')).not.toBeInTheDocument()
    expect(screen.queryByText('Critical')).not.toBeInTheDocument()
    // Repeated "No data" messages must not exist
    expect(screen.queryByText('No engine data')).not.toBeInTheDocument()
    expect(screen.queryByText('No findings recorded')).not.toBeInTheDocument()
    expect(screen.queryByText('Assessment baseline unavailable')).not.toBeInTheDocument()
    // No redundant "Overview" heading
    expect(screen.queryByRole('heading', { name: /^overview$/i })).not.toBeInTheDocument()
  })

  it('CTA "Start your first assessment" navigates to /assessments/new', async () => {
    ;(orgsApi.stats as ReturnType<typeof vi.fn>).mockResolvedValue(makeStats({ total_scans: 0 }))
    ;(scansApi.list as ReturnType<typeof vi.fn>).mockResolvedValue([])

    renderOverview()

    const cta = await screen.findByRole('link', { name: /start your first assessment/i })
    expect(cta).toHaveAttribute('href', '/assessments/new')
  })

  it('empty state is a single focused CTA under a "Workspace" title, without the engine catalogue', async () => {
    ;(orgsApi.stats as ReturnType<typeof vi.fn>).mockResolvedValue(makeStats({ total_scans: 0 }))
    ;(scansApi.list as ReturnType<typeof vi.fn>).mockResolvedValue([])

    renderOverview()

    await screen.findByText('Start your first assessment')
    expect(screen.getByRole('heading', { level: 1, name: 'Workspace' })).toBeInTheDocument()
    expect(screen.getAllByRole('link')).toHaveLength(1)
    // The engine list was removed from the empty state
    expect(screen.queryByText('DNS Authentication')).not.toBeInTheDocument()
    expect(screen.queryByText(/engines loaded/i)).not.toBeInTheDocument()
  })
})

describe('Overview — normal dashboard (assessments exist)', () => {
  it('shows normal dashboard when a queued scan exists', async () => {
    ;(orgsApi.stats as ReturnType<typeof vi.fn>).mockResolvedValue(makeStats({ total_scans: 1, active_scans: 1 }))
    ;(scansApi.list as ReturnType<typeof vi.fn>).mockResolvedValue([makeScan({ status: 'queued' })])

    renderOverview()

    // KPI strip present
    expect(await screen.findByText('Assessments')).toBeInTheDocument()
    expect(screen.queryByText('Start your first assessment')).not.toBeInTheDocument()
  })

  it('shows normal dashboard when a running scan exists', async () => {
    ;(orgsApi.stats as ReturnType<typeof vi.fn>).mockResolvedValue(makeStats({ total_scans: 1, active_scans: 1 }))
    ;(scansApi.list as ReturnType<typeof vi.fn>).mockResolvedValue([makeScan({ status: 'running', progress_pct: 45, current_engine: 'dns_auth' })])

    renderOverview()

    expect(await screen.findByText('Assessments')).toBeInTheDocument()
    expect(screen.queryByText('YOUR SECURITY WORKSPACE')).not.toBeInTheDocument()
  })

  it('shows normal dashboard for completed scan with zero findings — not empty state', async () => {
    ;(orgsApi.stats as ReturnType<typeof vi.fn>).mockResolvedValue(makeStats({
      total_scans: 1,
      latest_scan_id: 'scan-1',
      latest_risk_score: 0,
      latest_risk_posture: 'clean',
    }))
    ;(scansApi.list as ReturnType<typeof vi.fn>).mockResolvedValue([makeScan({ finding_count: 0, risk_score: 0 })])

    renderOverview()

    // Normal dashboard: KPI strip
    expect(await screen.findByText('Assessments')).toBeInTheDocument()
    // Empty state must not appear
    expect(screen.queryByText('YOUR SECURITY WORKSPACE')).not.toBeInTheDocument()
  })

  it('shows normal dashboard for completed scan with findings', async () => {
    ;(orgsApi.stats as ReturnType<typeof vi.fn>).mockResolvedValue(makeStats({
      total_scans: 1,
      active_scans: 0,
      open_critical: 2,
      open_high: 5,
      latest_scan_id: 'scan-1',
      latest_risk_score: 72,
      latest_risk_posture: 'high',
    }))
    ;(scansApi.list as ReturnType<typeof vi.fn>).mockResolvedValue([makeScan({ finding_count: 7, risk_score: 72 })])

    renderOverview()

    expect(await screen.findByText('Assessments')).toBeInTheDocument()
    expect(screen.queryByText('YOUR SECURITY WORKSPACE')).not.toBeInTheDocument()
  })

  it('shows normal dashboard for partial assessment — not empty state', async () => {
    ;(orgsApi.stats as ReturnType<typeof vi.fn>).mockResolvedValue(makeStats({ total_scans: 1, latest_scan_id: 'scan-1' }))
    ;(scansApi.list as ReturnType<typeof vi.fn>).mockResolvedValue([makeScan({ status: 'partial', finding_count: 2 })])

    renderOverview()

    expect(await screen.findByText('Assessments')).toBeInTheDocument()
    expect(screen.queryByText('YOUR SECURITY WORKSPACE')).not.toBeInTheDocument()
  })

  it('shows normal dashboard for failed assessment — not empty state', async () => {
    ;(orgsApi.stats as ReturnType<typeof vi.fn>).mockResolvedValue(makeStats({ total_scans: 1, latest_scan_id: 'scan-1' }))
    ;(scansApi.list as ReturnType<typeof vi.fn>).mockResolvedValue([makeScan({ status: 'failed', finding_count: 0, risk_score: null })])

    renderOverview()

    expect(await screen.findByText('Assessments')).toBeInTheDocument()
    expect(screen.queryByText('YOUR SECURITY WORKSPACE')).not.toBeInTheDocument()
  })
})

describe('Overview — loading and error states', () => {
  it('shows loading skeleton while data is fetching — not empty state', () => {
    // Queries never resolve
    ;(orgsApi.stats as ReturnType<typeof vi.fn>).mockReturnValue(new Promise(() => {}))
    ;(scansApi.list as ReturnType<typeof vi.fn>).mockReturnValue(new Promise(() => {}))

    renderOverview()

    // Empty state must not flash during loading
    expect(screen.queryByText('YOUR SECURITY WORKSPACE')).not.toBeInTheDocument()
    expect(screen.queryByText('Start your first assessment')).not.toBeInTheDocument()
  })
})
