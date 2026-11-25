import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { CheckCircle2, Copy, Plus, Trash2 } from 'lucide-react'
import { toast } from 'sonner'
import { PageHeader } from '../components/Layout'
import { domains as domainsApi, edition as editionApi } from '../lib/api'
import { useAuth } from '../lib/auth'

type ApiError = { response?: { data?: { detail?: string } } }

function CopyValue({ value }: { value: string }) {
  return (
    <div className="flex items-center gap-2">
      <code className="flex-1 truncate text-xs font-mono px-2 py-1.5 border border-border text-text-primary">{value}</code>
      <button
        className="btn-secondary flex items-center gap-1.5 text-xs"
        onClick={() => {
          navigator.clipboard.writeText(value)
          toast.success('Copied')
        }}
      >
        <Copy size={12} /> Copy
      </button>
    </div>
  )
}

export default function Domains() {
  const { currentOrg } = useAuth()
  const orgId = currentOrg?.id ?? ''
  const qc = useQueryClient()
  const [domain, setDomain] = useState('')
  const [lastCheck, setLastCheck] = useState<Record<string, string[]>>({})

  const { data: info } = useQuery({ queryKey: ['edition'], queryFn: editionApi.info, staleTime: Infinity })
  const { data: rows = [], isLoading } = useQuery({
    queryKey: ['domains', orgId],
    queryFn: () => domainsApi.list(orgId),
    enabled: !!orgId,
  })
  const refresh = () => qc.invalidateQueries({ queryKey: ['domains', orgId] })

  const add = useMutation({
    mutationFn: () => domainsApi.add(orgId, domain),
    onSuccess: () => {
      setDomain('')
      refresh()
    },
    onError: (e) => toast.error((e as ApiError)?.response?.data?.detail ?? 'Could not add the domain'),
  })
  const verify = useMutation({
    mutationFn: (id: string) => domainsApi.verify(orgId, id),
    onSuccess: (r) => {
      setLastCheck((m) => ({ ...m, [r.domain.id]: r.txt_found }))
      if (r.verified) toast.success(`${r.domain.domain} verified`)
      else toast.error('TXT record not found yet. DNS changes can take a few minutes to propagate.')
      refresh()
    },
  })
  const remove = useMutation({
    mutationFn: (id: string) => domainsApi.remove(orgId, id),
    onSuccess: refresh,
  })

  return (
    <div>
      <PageHeader
        title="Domains"
        subtitle={
          info?.domain_verification_required
            ? 'Prove you control a domain before scanning it. Subdomains are covered too.'
            : 'Domain ownership proof (optional on this instance)'
        }
      />

      <form
        className="card p-4 mb-6 flex items-end gap-3"
        onSubmit={(e) => {
          e.preventDefault()
          add.mutate()
        }}
      >
        <div className="flex-1">
          <label className="label block mb-1.5">Domain</label>
          <input
            className="input"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="example.com"
            required
          />
        </div>
        <button type="submit" className="btn-primary flex items-center gap-1.5 disabled:opacity-50" disabled={add.isPending}>
          <Plus size={14} /> Add domain
        </button>
      </form>

      {isLoading && <div className="text-sm text-text-muted">Loading…</div>}
      {!isLoading && rows.length === 0 && (
        <div className="card p-10 text-center text-sm text-text-muted">No domain yet. Add the domain you want to assess.</div>
      )}

      <div className="space-y-4">
        {rows.map((d) => (
          <div key={d.id} className="card p-5">
            <div className="flex items-center justify-between gap-4 mb-4">
              <div className="flex items-center gap-2">
                <span className="font-mono text-text-primary">{d.domain}</span>
                {d.verified_at ? (
                  <span className="flex items-center gap-1 text-xs" style={{ color: '#22c55e' }}>
                    <CheckCircle2 size={13} /> verified
                  </span>
                ) : (
                  <span className="text-xs text-text-muted">not verified</span>
                )}
              </div>
              <div className="flex items-center gap-2">
                {!d.verified_at && (
                  <button
                    className="btn-primary text-xs disabled:opacity-50"
                    disabled={verify.isPending}
                    onClick={() => verify.mutate(d.id)}
                  >
                    {verify.isPending && verify.variables === d.id ? 'Checking…' : 'Check now'}
                  </button>
                )}
                <button
                  className="text-text-muted hover:text-severity-critical p-1.5"
                  title="Remove"
                  onClick={() => remove.mutate(d.id)}
                >
                  <Trash2 size={14} />
                </button>
              </div>
            </div>

            {!d.verified_at && (
              <div className="space-y-3 text-sm">
                <p className="text-text-secondary">
                  Add this TXT record at your DNS provider, then click <em>Check now</em>.
                </p>
                <div className="grid gap-2" style={{ gridTemplateColumns: '80px 1fr' }}>
                  <span className="label pt-2">Name</span>
                  <CopyValue value={d.txt_name} />
                  <span className="label pt-2">Value</span>
                  <CopyValue value={d.txt_value} />
                </div>
                {lastCheck[d.id] && (
                  <p className="text-xs text-text-muted">
                    TXT records currently published on {d.domain}:{' '}
                    {lastCheck[d.id].length ? lastCheck[d.id].map((v) => `"${v}"`).join(', ') : 'none'}
                  </p>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
