import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { UserPlus } from 'lucide-react'
import { toast } from 'sonner'
import { PageHeader } from '../components/Layout'
import { useAuth } from '../lib/auth'
import { orgs as orgsApi } from '../lib/api'

export default function Team() {
  const { currentOrg } = useAuth()
  const orgId = currentOrg?.id ?? ''
  const qc = useQueryClient()

  const [showInvite, setShowInvite] = useState(false)
  const [inviteEmail, setInviteEmail] = useState('')
  const [inviteRole, setInviteRole] = useState('analyst')
  const [confirmRemove, setConfirmRemove] = useState<string | null>(null)

  const { data: members = [], isLoading } = useQuery({
    queryKey: ['members', orgId],
    queryFn: () => orgsApi.members(orgId),
    enabled: !!orgId,
  })

  const inviteMutation = useMutation({
    mutationFn: () => orgsApi.inviteMember(orgId, inviteEmail, inviteRole),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['members', orgId] })
      setInviteEmail('')
      setShowInvite(false)
      toast.success(`Invite sent to ${inviteEmail}`)
    },
    onError: (e: { response?: { data?: { detail?: string } } }) =>
      toast.error(e?.response?.data?.detail ?? 'Invitation failed'),
  })

  const removeMutation = useMutation({
    mutationFn: (userId: string) => orgsApi.removeMember(orgId, userId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['members', orgId] })
      setConfirmRemove(null)
      toast.success('Member removed')
    },
    onError: () => toast.error('Failed to remove member'),
  })

  return (
    <div>
      <PageHeader
        title="Team"
        subtitle={currentOrg?.name}
        action={
          <button
            onClick={() => setShowInvite(true)}
            className="btn-primary flex items-center gap-1.5 text-sm"
          >
            <UserPlus size={14} />
            Invite member
          </button>
        }
      />

      {showInvite && (
        <div className="card p-4 mb-6">
          <form
            onSubmit={(e) => {
              e.preventDefault()
              inviteMutation.mutate()
            }}
            className="flex items-end gap-3"
          >
            <div className="flex-1">
              <label className="label block mb-1.5">Email</label>
              <input
                type="email"
                className="input"
                value={inviteEmail}
                onChange={(e) => setInviteEmail(e.target.value)}
                required
                autoFocus
                placeholder="analyst@example.com"
              />
            </div>
            <div>
              <label className="label block mb-1.5">Role</label>
              <select
                className="input w-auto"
                value={inviteRole}
                onChange={(e) => setInviteRole(e.target.value)}
              >
                <option value="admin">Admin</option>
                <option value="analyst">Analyst</option>
                <option value="pentester">Pentester</option>
                <option value="auditor">Auditor</option>
              </select>
            </div>
            <div className="flex gap-2">
              <button type="button" onClick={() => setShowInvite(false)} className="btn-secondary">
                Cancel
              </button>
              <button
                type="submit"
                disabled={inviteMutation.isPending}
                className="btn-primary disabled:opacity-50"
              >
                {inviteMutation.isPending ? 'Inviting…' : 'Send invite'}
              </button>
            </div>
          </form>
          {inviteMutation.isError && (
            <div className="mt-2 text-xs text-severity-critical">
              {String(
                (inviteMutation.error as { response?: { data?: { detail?: string } } })?.response
                  ?.data?.detail ?? 'Invitation failed'
              )}
            </div>
          )}
        </div>
      )}

      <div className="card overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border">
              <th className="text-left label px-4 py-2.5">Member</th>
              <th className="text-left label px-4 py-2.5">Role</th>
              <th className="text-left label px-4 py-2.5">Joined</th>
              <th className="px-4 py-2.5" />
            </tr>
          </thead>
          <tbody>
            {isLoading && (
              <tr>
                <td colSpan={4} className="px-4 py-6 text-center text-text-muted text-sm">
                  Loading…
                </td>
              </tr>
            )}
            {!isLoading && members.length === 0 && (
              <tr>
                <td colSpan={4} className="px-4 py-10 text-center text-text-muted text-sm">
                  No members yet. Invite someone to get started.
                </td>
              </tr>
            )}
            {members.map((m) => (
              <tr key={m.user_id} className="border-b border-border/50">
                <td className="px-4 py-3">
                  <div className="text-sm text-text-primary">{m.full_name ?? m.email}</div>
                  <div className="text-xs font-mono text-text-muted">{m.email}</div>
                </td>
                <td className="px-4 py-3">
                  <span className="text-xs font-mono text-text-secondary capitalize">{m.role}</span>
                </td>
                <td className="px-4 py-3 text-xs text-text-muted font-mono">
                  {new Date(m.joined_at).toLocaleDateString()}
                </td>
                <td className="px-4 py-3 text-right">
                  {confirmRemove === m.user_id ? (
                    <div className="flex items-center justify-end gap-2">
                      <span className="text-xs text-text-muted">Remove?</span>
                      <button
                        onClick={() => removeMutation.mutate(m.user_id)}
                        disabled={removeMutation.isPending}
                        className="text-xs text-severity-critical disabled:opacity-50"
                      >
                        Yes
                      </button>
                      <button
                        onClick={() => setConfirmRemove(null)}
                        className="text-xs text-text-muted"
                      >
                        No
                      </button>
                    </div>
                  ) : (
                    <button
                      onClick={() => setConfirmRemove(m.user_id)}
                      className="text-xs text-text-muted hover:text-severity-critical"
                      style={{ transition: 'color 100ms var(--ease-out)' }}
                    >
                      Remove
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
