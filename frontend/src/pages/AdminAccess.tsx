import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Copy, UserPlus } from 'lucide-react'
import { toast } from 'sonner'
import { PageHeader } from '../components/Layout'
import { admin as adminApi, edition as editionApi, type AdminOrg, type InviteIssued } from '../lib/api'
import { useAuth } from '../lib/auth'

type Tab = 'requests' | 'invites' | 'users' | 'organizations' | 'emails'
type ApiError = { response?: { data?: { detail?: string } } }

const errorText = (e: unknown, fallback: string) => (e as ApiError)?.response?.data?.detail ?? fallback
const fmt = (iso: string | null) => (iso ? new Date(iso).toLocaleString() : '—')

/** Shows the signup link when the invite email could not be sent. */
function IssuedNotice({ issued, onClose }: { issued: InviteIssued; onClose: () => void }) {
  return (
    <div className="card p-4 mb-6 text-sm">
      {issued.email_sent ? (
        <p className="text-text-secondary">
          Invitation emailed to <span className="font-mono text-text-primary">{issued.email}</span>.
        </p>
      ) : (
        <>
          <p className="text-text-secondary mb-2">
            The email could not be sent. Pass this single-use link to{' '}
            <span className="font-mono text-text-primary">{issued.email}</span> yourself:
          </p>
          <div className="flex items-center gap-2">
            <code className="flex-1 truncate text-xs font-mono px-2 py-1.5 border border-border">{issued.invite_url}</code>
            <button
              className="btn-secondary flex items-center gap-1.5"
              onClick={() => {
                navigator.clipboard.writeText(issued.invite_url ?? '')
                toast.success('Link copied')
              }}
            >
              <Copy size={13} /> Copy
            </button>
          </div>
        </>
      )}
      <button className="text-xs text-text-muted mt-3" onClick={onClose}>
        Dismiss
      </button>
    </div>
  )
}

export default function AdminAccess() {
  const { user } = useAuth()
  const qc = useQueryClient()
  const { data: info } = useQuery({ queryKey: ['edition'], queryFn: editionApi.info, staleTime: Infinity })
  // Access requests only exist on the hosted service; self-hosted instances just issue invites
  const tabs: Tab[] =
    info?.edition === 'saas' ? ['requests', 'invites', 'users', 'organizations', 'emails'] : ['invites', 'users', 'organizations', 'emails']
  const [chosenTab, setTab] = useState<Tab | null>(null)
  const tab: Tab = chosenTab && tabs.includes(chosenTab) ? chosenTab : tabs[0]
  const [status, setStatus] = useState<string>('pending')
  const [issued, setIssued] = useState<InviteIssued | null>(null)
  const [inviteEmail, setInviteEmail] = useState('')
  const [inviteName, setInviteName] = useState('')

  const requests = useQuery({
    queryKey: ['admin', 'requests', status],
    queryFn: () => adminApi.requests(status || undefined),
    enabled: tab === 'requests',
  })
  const invites = useQuery({ queryKey: ['admin', 'invites'], queryFn: adminApi.invites, enabled: tab === 'invites' })
  const users = useQuery({ queryKey: ['admin', 'users'], queryFn: adminApi.users, enabled: tab === 'users' })
  const orgs = useQuery({ queryKey: ['admin', 'orgs'], queryFn: adminApi.orgs, enabled: tab === 'organizations' })
  const emails = useQuery({ queryKey: ['admin', 'emails'], queryFn: adminApi.emailLogs, enabled: tab === 'emails' })

  const refresh = () => qc.invalidateQueries({ queryKey: ['admin'] })

  const approve = useMutation({
    mutationFn: adminApi.approve,
    onSuccess: (data) => {
      setIssued(data)
      refresh()
    },
    onError: (e) => toast.error(errorText(e, 'Approval failed')),
  })
  const reject = useMutation({
    mutationFn: adminApi.reject,
    onSuccess: () => {
      toast.success('Request rejected')
      refresh()
    },
    onError: (e) => toast.error(errorText(e, 'Rejection failed')),
  })
  const createInvite = useMutation({
    mutationFn: () => adminApi.invite(inviteEmail, inviteName),
    onSuccess: (data) => {
      setIssued(data)
      setInviteEmail('')
      setInviteName('')
      refresh()
    },
    onError: (e) => toast.error(errorText(e, 'Invitation failed')),
  })
  const revoke = useMutation({
    mutationFn: adminApi.revokeInvite,
    onSuccess: () => {
      toast.success('Invitation revoked')
      refresh()
    },
  })
  const setActive = useMutation({
    mutationFn: ({ id, active }: { id: string; active: boolean }) =>
      active ? adminApi.activate(id) : adminApi.suspend(id),
    onSuccess: (u) => {
      toast.success(u.is_active ? 'Account reactivated' : 'Account suspended')
      refresh()
    },
    onError: (e) => toast.error(errorText(e, 'Update failed')),
  })

  const userAction = useMutation({
    mutationFn: ({ id, action }: { id: string; action: 'grant' | 'revoke-admin' | 'sessions' | 'mfa' }) =>
      action === 'grant'
        ? adminApi.setPlatformAdmin(id, true)
        : action === 'revoke-admin'
          ? adminApi.setPlatformAdmin(id, false)
          : action === 'sessions'
            ? adminApi.revokeSessions(id)
            : adminApi.resetMfa(id),
    onSuccess: (_, { action }) => {
      toast.success(
        {
          grant: 'Admin rights granted',
          'revoke-admin': 'Admin rights removed',
          sessions: 'Sessions revoked',
          mfa: 'Two-factor authentication reset',
        }[action],
      )
      refresh()
    },
    onError: (e) => toast.error(errorText(e, 'Update failed')),
  })
  const updateOrg = useMutation({
    mutationFn: ({ id, body }: { id: string; body: Parameters<typeof adminApi.updateOrg>[1] }) =>
      adminApi.updateOrg(id, body),
    onSuccess: () => {
      toast.success('Organization updated')
      refresh()
    },
    onError: (e) => toast.error(errorText(e, 'Update failed')),
  })

  if (!user?.is_platform_admin) {
    return <PageHeader title="Access" subtitle="Platform administrators only" />
  }

  return (
    <div>
      <PageHeader
        title="Access"
        subtitle={
          info?.edition === 'saas'
            ? 'Accounts, rights and limits. Assessments stay private to each organization.'
            : 'Invitations, accounts and organization limits'
        }
      />

      <div className="flex gap-1 mb-6 border-b border-border">
        {tabs.map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className="px-3 py-2 text-sm capitalize"
            style={{
              color: tab === t ? '#e8ecf2' : '#666672',
              borderBottom: tab === t ? '2px solid #E8173A' : '2px solid transparent',
              marginBottom: '-1px',
            }}
          >
            {t}
          </button>
        ))}
      </div>

      {issued && <IssuedNotice issued={issued} onClose={() => setIssued(null)} />}

      {tab === 'requests' && (
        <>
          <div className="flex gap-2 mb-4">
            {['pending', 'approved', 'rejected', ''].map((s) => (
              <button
                key={s || 'all'}
                onClick={() => setStatus(s)}
                className={status === s ? 'btn-primary text-xs' : 'btn-secondary text-xs'}
              >
                {s || 'all'}
              </button>
            ))}
          </div>
          <div className="card overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border">
                  <th className="text-left label px-4 py-2.5">Requester</th>
                  <th className="text-left label px-4 py-2.5">Company</th>
                  <th className="text-left label px-4 py-2.5">Message</th>
                  <th className="text-left label px-4 py-2.5">Received</th>
                  <th className="px-4 py-2.5" />
                </tr>
              </thead>
              <tbody>
                {requests.isLoading && (
                  <tr>
                    <td colSpan={5} className="px-4 py-6 text-center text-text-muted">Loading…</td>
                  </tr>
                )}
                {requests.data?.length === 0 && (
                  <tr>
                    <td colSpan={5} className="px-4 py-10 text-center text-text-muted">No requests.</td>
                  </tr>
                )}
                {requests.data?.map((r) => (
                  <tr key={r.id} className="border-b border-border/50 align-top">
                    <td className="px-4 py-3">
                      <div className="text-text-primary">{r.name}</div>
                      <div className="text-xs font-mono text-text-muted">{r.email}</div>
                      {r.topic !== 'access' && <div className="text-xs text-text-muted mt-1">topic: {r.topic}</div>}
                    </td>
                    <td className="px-4 py-3">
                      <div className="text-text-secondary">{r.company}</div>
                      {r.role && <div className="text-xs text-text-muted">{r.role}</div>}
                    </td>
                    <td className="px-4 py-3 text-xs text-text-secondary max-w-xs whitespace-pre-wrap">{r.message ?? '—'}</td>
                    <td className="px-4 py-3 text-xs font-mono text-text-muted">
                      {fmt(r.created_at)}
                      {r.ip_address && <div>{r.ip_address}</div>}
                    </td>
                    <td className="px-4 py-3 text-right whitespace-nowrap">
                      {r.status === 'pending' ? (
                        <div className="flex justify-end gap-2">
                          {r.topic === 'access' && (
                            <button
                              className="btn-primary text-xs disabled:opacity-50"
                              disabled={approve.isPending}
                              onClick={() => approve.mutate(r.id)}
                            >
                              Approve
                            </button>
                          )}
                          <button
                            className="btn-secondary text-xs disabled:opacity-50"
                            disabled={reject.isPending}
                            onClick={() => reject.mutate(r.id)}
                          >
                            {r.topic === 'access' ? 'Reject' : 'Mark handled'}
                          </button>
                        </div>
                      ) : (
                        <span className="text-xs font-mono text-text-muted">{r.status}</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {tab === 'invites' && (
        <>
          <form
            className="card p-4 mb-6 flex items-end gap-3 flex-wrap"
            onSubmit={(e) => {
              e.preventDefault()
              createInvite.mutate()
            }}
          >
            <div className="flex-1 min-w-48">
              <label className="label block mb-1.5">Email</label>
              <input
                type="email"
                className="input"
                required
                value={inviteEmail}
                onChange={(e) => setInviteEmail(e.target.value)}
                placeholder="person@company.com"
              />
            </div>
            <div className="flex-1 min-w-40">
              <label className="label block mb-1.5">Name</label>
              <input className="input" value={inviteName} onChange={(e) => setInviteName(e.target.value)} />
            </div>
            <button type="submit" className="btn-primary flex items-center gap-1.5 disabled:opacity-50" disabled={createInvite.isPending}>
              <UserPlus size={14} /> Invite
            </button>
          </form>
          <div className="card overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border">
                  <th className="text-left label px-4 py-2.5">Email</th>
                  <th className="text-left label px-4 py-2.5">State</th>
                  <th className="text-left label px-4 py-2.5">Expires</th>
                  <th className="px-4 py-2.5" />
                </tr>
              </thead>
              <tbody>
                {invites.data?.map((i) => {
                  const state = i.used_at
                    ? 'used'
                    : i.revoked_at
                      ? 'revoked'
                      : new Date(i.expires_at) < new Date()
                        ? 'expired'
                        : 'open'
                  return (
                    <tr key={i.id} className="border-b border-border/50">
                      <td className="px-4 py-3 font-mono text-xs text-text-primary">{i.email}</td>
                      <td className="px-4 py-3 text-xs font-mono text-text-secondary">{state}</td>
                      <td className="px-4 py-3 text-xs font-mono text-text-muted">{fmt(i.expires_at)}</td>
                      <td className="px-4 py-3 text-right">
                        {state === 'open' && (
                          <button className="text-xs text-text-muted hover:text-severity-critical" onClick={() => revoke.mutate(i.id)}>
                            Revoke
                          </button>
                        )}
                      </td>
                    </tr>
                  )
                })}
                {invites.data?.length === 0 && (
                  <tr>
                    <td colSpan={4} className="px-4 py-10 text-center text-text-muted">No invitations yet.</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </>
      )}

      {tab === 'users' && (
        <div className="card overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left label px-4 py-2.5">Account</th>
                <th className="text-left label px-4 py-2.5">Organizations</th>
                <th className="text-left label px-4 py-2.5">Security</th>
                <th className="text-left label px-4 py-2.5">State</th>
                <th className="px-4 py-2.5" />
              </tr>
            </thead>
            <tbody>
              {users.data?.map((u) => (
                <tr key={u.id} className="border-b border-border/50 align-top">
                  <td className="px-4 py-3">
                    <div className="text-text-primary">{u.full_name ?? u.email}</div>
                    <div className="text-xs font-mono text-text-muted">{u.email}</div>
                    <div className="text-xs text-text-muted mt-0.5">since {new Date(u.created_at).toLocaleDateString()}</div>
                  </td>
                  <td className="px-4 py-3 text-xs text-text-secondary">
                    {u.orgs?.length
                      ? u.orgs.map((o) => (
                          <div key={o.id}>
                            {o.name} <span className="text-text-muted">· {o.role}</span>
                          </div>
                        ))
                      : '—'}
                  </td>
                  <td className="px-4 py-3 text-xs font-mono text-text-secondary">
                    <div>{u.is_platform_admin ? 'platform admin' : 'user'}</div>
                    <div className="text-text-muted">2FA {u.mfa_enabled ? 'on' : 'off'}</div>
                  </td>
                  <td className="px-4 py-3 text-xs font-mono text-text-secondary">{u.is_active ? 'active' : 'suspended'}</td>
                  <td className="px-4 py-3 text-right">
                    {u.id !== user.id && (
                      <div className="flex flex-col items-end gap-1 text-xs">
                        <button
                          className="text-text-muted hover:text-severity-critical disabled:opacity-50"
                          disabled={setActive.isPending}
                          onClick={() => setActive.mutate({ id: u.id, active: !u.is_active })}
                        >
                          {u.is_active ? 'Suspend' : 'Reactivate'}
                        </button>
                        <button
                          className="text-text-muted hover:text-text-primary"
                          onClick={() => userAction.mutate({ id: u.id, action: u.is_platform_admin ? 'revoke-admin' : 'grant' })}
                        >
                          {u.is_platform_admin ? 'Remove admin' : 'Make admin'}
                        </button>
                        <button
                          className="text-text-muted hover:text-text-primary"
                          onClick={() => userAction.mutate({ id: u.id, action: 'sessions' })}
                        >
                          Sign out everywhere
                        </button>
                        {u.mfa_enabled && (
                          <button
                            className="text-text-muted hover:text-text-primary"
                            onClick={() => userAction.mutate({ id: u.id, action: 'mfa' })}
                          >
                            Reset 2FA
                          </button>
                        )}
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {tab === 'organizations' && (
        <div className="card overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left label px-4 py-2.5">Organization</th>
                <th className="text-left label px-4 py-2.5">Usage</th>
                <th className="text-left label px-4 py-2.5">Scans / day</th>
                <th className="text-left label px-4 py-2.5">Offensive modules</th>
                <th className="text-left label px-4 py-2.5">State</th>
              </tr>
            </thead>
            <tbody>
              {orgs.data?.map((o) => (
                <OrgRow
                  key={o.id}
                  org={o}
                  busy={updateOrg.isPending}
                  onChange={(body) => updateOrg.mutate({ id: o.id, body })}
                />
              ))}
              {orgs.data?.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-4 py-10 text-center text-text-muted">No organizations yet.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {tab === 'emails' && (
        <div className="card overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left label px-4 py-2.5">Recipient</th>
                <th className="text-left label px-4 py-2.5">Subject</th>
                <th className="text-left label px-4 py-2.5">Template</th>
                <th className="text-left label px-4 py-2.5">Status</th>
                <th className="text-left label px-4 py-2.5">Date</th>
              </tr>
            </thead>
            <tbody>
              {emails.data?.map((e) => (
                <tr key={e.id} className="border-b border-border/50">
                  <td className="px-4 py-3 font-mono text-xs text-text-primary">{e.recipient}</td>
                  <td className="px-4 py-3 text-text-secondary truncate max-w-[200px]" title={e.subject}>{e.subject}</td>
                  <td className="px-4 py-3 text-xs text-text-muted">{e.template}</td>
                  <td className="px-4 py-3">
                    {e.status === 'sent' ? (
                      <span className="text-xs px-2 py-0.5 rounded" style={{ background: 'rgba(54,179,126,0.15)', color: '#36B37E' }}>sent</span>
                    ) : (
                      <span className="text-xs px-2 py-0.5 rounded" style={{ background: 'rgba(239,68,68,0.15)', color: '#EF4444' }} title={e.error_message ?? ''}>failed</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-xs text-text-muted">{fmt(e.created_at)}</td>
                </tr>
              ))}
              {emails.data?.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-4 py-10 text-center text-text-muted">No emails sent yet.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

type OrgChange = Partial<{ daily_scan_quota: number | null; offensive_modules_allowed: boolean; is_active: boolean }>

function OrgRow({ org, busy, onChange }: { org: AdminOrg; busy: boolean; onChange: (body: OrgChange) => void }) {
  const saved = org.daily_scan_quota === null ? '' : String(org.daily_scan_quota)
  const [quota, setQuota] = useState(saved)
  return (
    <tr className="border-b border-border/50 align-top">
      <td className="px-4 py-3">
        <div className="text-text-primary">{org.name}</div>
        {org.members.map((m) => (
          <div key={m.email} className="text-xs font-mono text-text-muted">
            {m.email} · {m.role}
          </div>
        ))}
      </td>
      <td className="px-4 py-3 text-xs font-mono text-text-secondary">
        <div>{org.scans_24h} scans today</div>
        <div className="text-text-muted">{org.scans_30d} in 30 days</div>
        <div className="text-text-muted">{org.verified_domains} verified domain(s)</div>
      </td>
      <td className="px-4 py-3">
        <form
          className="flex items-center gap-2"
          onSubmit={(e) => {
            e.preventDefault()
            onChange({ daily_scan_quota: quota === '' ? null : Number(quota) })
          }}
        >
          <input
            className="input w-20 text-xs"
            type="number"
            min={0}
            max={10000}
            value={quota}
            placeholder={String(org.effective_daily_scan_quota)}
            onChange={(e) => setQuota(e.target.value)}
            title="Empty = service default"
          />
          {quota !== saved && (
            <button type="submit" className="btn-secondary text-xs disabled:opacity-50" disabled={busy}>
              Save
            </button>
          )}
        </form>
      </td>
      <td className="px-4 py-3">
        <button
          className="text-xs font-mono disabled:opacity-50"
          style={{ color: org.offensive_modules_allowed ? '#22c55e' : '#666672' }}
          disabled={busy}
          onClick={() => onChange({ offensive_modules_allowed: !org.offensive_modules_allowed })}
        >
          {org.offensive_modules_allowed ? 'allowed' : 'blocked'}
        </button>
      </td>
      <td className="px-4 py-3">
        <button
          className="text-xs font-mono disabled:opacity-50"
          style={{ color: org.is_active ? '#c8ccd4' : '#E8173A' }}
          disabled={busy}
          onClick={() => onChange({ is_active: !org.is_active })}
          title={org.is_active ? 'Deactivate: no more scans' : 'Reactivate'}
        >
          {org.is_active ? 'active' : 'deactivated'}
        </button>
      </td>
    </tr>
  )
}
