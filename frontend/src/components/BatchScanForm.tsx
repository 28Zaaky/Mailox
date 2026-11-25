import React, { useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { CheckCircle, XCircle, Upload } from 'lucide-react'
import { useMutation } from '@tanstack/react-query'
import { toast } from 'sonner'
import { scans as scansApi } from '../lib/api'
import type { BatchScanResult } from '../types'
import type { AssessmentProfile } from '../types'

interface BatchScanFormProps {
  orgId: string
  profileList: AssessmentProfile[]
  onCancel: () => void
}

function parseDomains(text: string): string[] {
  return text
    .split(/[\n,]+/)
    .map((d) => d.trim().replace(/^#.*/, ''))
    .filter((d) => d.length > 0)
}

export function BatchScanForm({ orgId, profileList, onCancel }: BatchScanFormProps) {
  const [text, setText] = useState('')
  const [selectedProfileId, setSelectedProfileId] = useState('')
  const [results, setResults] = useState<BatchScanResult[] | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)

  const domains = parseDomains(text)

  const mutation = useMutation({
    mutationFn: () =>
      scansApi.batchScanJson(orgId, domains, selectedProfileId || undefined),
    onSuccess: (data) => {
      setResults(data)
      const launched = data.filter((r) => r.status === 'queued').length
      const rejected = data.filter((r) => r.status === 'rejected').length
      if (rejected === 0) {
        toast.success(`${launched} scan${launched !== 1 ? 's' : ''} launched`)
      } else {
        toast.warning(`${launched} launched, ${rejected} rejected`)
      }
    },
    onError: (e: { response?: { data?: { detail?: string } } }) =>
      toast.error(e?.response?.data?.detail ?? 'Batch scan failed'),
  })

  function handleFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = (ev) => {
      const content = ev.target?.result
      if (typeof content === 'string') setText(content)
    }
    reader.readAsText(file)
    // Reset so the same file can be re-selected
    e.target.value = ''
  }

  if (results) {
    const launched = results.filter((r) => r.status === 'queued')
    const rejected = results.filter((r) => r.status === 'rejected')
    return (
      <div>
        <div className="mb-3 text-sm text-text-secondary">
          <span className="text-green-500 font-medium">{launched.length} launched</span>
          {rejected.length > 0 && (
            <span className="text-severity-critical font-medium ml-3">
              {rejected.length} rejected
            </span>
          )}
        </div>

        <div className="space-y-1 max-h-56 overflow-y-auto pr-1">
          {results.map((r, i) => (
            <div key={i} className="flex items-center gap-2 text-sm py-1">
              {r.status === 'queued' ? (
                <CheckCircle size={13} className="text-green-500 shrink-0" />
              ) : (
                <XCircle size={13} className="text-severity-critical shrink-0" />
              )}
              <span className="text-text-primary">{r.domain}</span>
              {r.status === 'queued' && r.scan_id && (
                <Link
                  to={`/assessments/${r.scan_id}`}
                  className="ml-auto text-xs text-accent hover:text-accent-hover"
                >
                  View →
                </Link>
              )}
              {r.status === 'rejected' && (
                <span className="ml-auto text-xs text-text-muted">{r.reason}</span>
              )}
            </div>
          ))}
        </div>

        <div className="mt-4 flex gap-2">
          <button
            onClick={() => { setResults(null); setText('') }}
            className="btn-secondary text-sm"
          >
            New batch
          </button>
          <button onClick={onCancel} className="btn-ghost text-sm">
            Close
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <label className="label text-sm">Domains (one per line)</label>
        <button
          type="button"
          onClick={() => fileRef.current?.click()}
          className="flex items-center gap-1.5 text-xs text-accent hover:text-accent-hover"
        >
          <Upload size={12} />
          Import CSV / TXT
        </button>
        <input
          ref={fileRef}
          type="file"
          accept=".csv,.txt,text/plain,text/csv"
          className="hidden"
          onChange={handleFileChange}
        />
      </div>

      <textarea
        className="input w-full font-mono text-xs resize-y"
        rows={6}
        value={text}
        onChange={(e) => setText(e.target.value)}
        placeholder={'mail.example.com\nsmtp.company.org\nexample.net'}
        spellCheck={false}
      />

      <div className="flex items-center justify-between gap-3 flex-wrap">
        <span className="text-xs text-text-muted">
          {domains.length > 0
            ? `${domains.length} domain${domains.length !== 1 ? 's' : ''} detected`
            : 'Paste domains above or import a file'}
        </span>
        <div style={{ minWidth: '160px' }}>
          <select
            className="input text-sm"
            value={selectedProfileId}
            onChange={(e) => setSelectedProfileId(e.target.value)}
          >
            <option value="">Default (Full)</option>
            {profileList.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}{p.is_builtin ? '' : ' (custom)'}
              </option>
            ))}
          </select>
        </div>
      </div>

      {domains.length > 50 && (
        <div className="text-xs text-severity-high">
          Maximum 50 domains per batch — trim the list before submitting.
        </div>
      )}

      <div className="flex gap-2">
        <button type="button" onClick={onCancel} className="btn-secondary">
          Cancel
        </button>
        <button
          type="button"
          disabled={domains.length === 0 || domains.length > 50 || mutation.isPending}
          onClick={() => mutation.mutate()}
          className="btn-primary disabled:opacity-50"
        >
          {mutation.isPending
            ? 'Launching…'
            : `Launch ${domains.length > 0 ? domains.length : ''} scan${domains.length !== 1 ? 's' : ''}`}
        </button>
      </div>

      {mutation.isError && (
        <div className="text-xs text-severity-critical">
          {String(
            (mutation.error as { response?: { data?: { detail?: string } } })?.response
              ?.data?.detail ?? 'Batch scan failed'
          )}
        </div>
      )}
    </div>
  )
}
