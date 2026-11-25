/**
 * ScanMonitorContext — global scan watcher.
 *
 * Polls active scans every 3s, emits toast notifications on state transitions,
 * tracks notifications in memory + localStorage. Persists across page navigation.
 */
import React, { createContext, useCallback, useContext, useEffect, useLayoutEffect, useRef, useState } from 'react'
import { toast } from 'sonner'
import { useQueryClient } from '@tanstack/react-query'
import { scans as scansApi } from './api'
import { useAuth } from './auth'
import type { Scan, ScanStatus } from '../types'

// ── Types ─────────────────────────────────────────────────────────────────────

export type NotifType =
  | 'scan_started'
  | 'scan_completed'
  | 'scan_partial'
  | 'scan_failed'
  | 'scan_cancelled'
  | 'critical_finding'
  | 'new_discovery'

export interface AppNotification {
  id: string
  type: NotifType
  title: string
  body: string
  scan_id?: string
  domain?: string
  timestamp: number
  read: boolean
}

interface ScanMonitorContextValue {
  activeScans: Scan[]
  notifications: AppNotification[]
  unreadCount: number
  markAllRead: () => void
  markRead: (id: string) => void
  clearNotifications: () => void
}

// ── Engine display labels ─────────────────────────────────────────────────────

export const ENGINE_LABELS: Record<string, string> = {
  dns_auth: 'DNS & Auth',
  smtp_discovery: 'SMTP Discovery',
  smtp_security: 'SMTP Security',
  webmail: 'Webmail',
  vuln_intel: 'Vuln Intel',
  active_probes: 'Active Probes',
  canary_probes: 'Canary Probes',
  credential_probes: 'Credential Test',
  web_pentest: 'Web Pentest',
  risk_correlation: 'Risk Analysis',
  secrets: 'Credentials',
  web_security: 'Web Security',
}

export function engineLabel(engine: string | null | undefined): string {
  if (!engine) return 'Preparing…'
  return ENGINE_LABELS[engine] ?? engine
}

// ── Storage helpers ───────────────────────────────────────────────────────────

// Scoped per user and org; all `mailox_notifications*` keys are purged on logout
// (see clearSession in auth.tsx).
const NOTIF_PREFIX = 'mailox_notifications'
const MAX_STORED = 50

function notifKey(userId: string | undefined, orgId: string | undefined): string | null {
  return userId && orgId ? `${NOTIF_PREFIX}:${userId}:${orgId}` : null
}

function loadNotifs(key: string | null): AppNotification[] {
  if (!key) return []
  try {
    const raw = localStorage.getItem(key)
    return raw ? JSON.parse(raw) : []
  } catch {
    return []
  }
}

function saveNotifs(key: string | null, notifs: AppNotification[]) {
  if (!key) return
  try {
    localStorage.setItem(key, JSON.stringify(notifs.slice(0, MAX_STORED)))
  } catch {}
}

// ── Context ───────────────────────────────────────────────────────────────────

const ScanMonitorContext = createContext<ScanMonitorContextValue>({
  activeScans: [],
  notifications: [],
  unreadCount: 0,
  markAllRead: () => {},
  markRead: () => {},
  clearNotifications: () => {},
})

export function ScanMonitorProvider({ children }: { children: React.ReactNode }) {
  const { user, currentOrg } = useAuth()
  const qc = useQueryClient()
  const storageKey = notifKey(user?.id, currentOrg?.id)
  const keyRef = useRef<string | null>(storageKey)
  const [activeScans, setActiveScans] = useState<Scan[]>([])
  const [notifications, setNotifications] = useState<AppNotification[]>(() => loadNotifs(storageKey))
  // Org currently in scope. Updated during commit (layout effect) so a poll that
  // resolves after an org switch can tell its results belong to a previous org.
  const activeOrgRef = useRef<string | undefined>(currentOrg?.id)
  useLayoutEffect(() => {
    activeOrgRef.current = currentOrg?.id
  }, [currentOrg?.id])

  // User or org changed: switch to that scope's notifications and forget the
  // previous org's scan states so no cross-org event is emitted.
  useEffect(() => {
    if (keyRef.current === storageKey) return
    keyRef.current = storageKey
    prevStates.current.clear()
    setActiveScans([])
    setNotifications(loadNotifs(storageKey))
  }, [storageKey])
  const prevStates = useRef<Map<string, { status: ScanStatus; finding_count: number; progress_pct: number }>>(new Map())
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const addNotif = useCallback((n: Omit<AppNotification, 'id' | 'timestamp' | 'read'>) => {
    const notif: AppNotification = {
      ...n,
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      timestamp: Date.now(),
      read: false,
    }
    setNotifications((prev) => {
      const next = [notif, ...prev].slice(0, MAX_STORED)
      saveNotifs(keyRef.current, next)
      return next
    })
    return notif
  }, [])

  const poll = useCallback(async () => {
    if (!currentOrg) return
    const orgId = currentOrg.id
    try {
      const all = await scansApi.list(orgId, 50, 0)
      // Org switched while the request was in flight: drop the stale result so it
      // can't repopulate activeScans, the query cache or prevStates of the new org.
      if (activeOrgRef.current !== orgId) return
      const active = all.filter((s) => s.status === 'running' || s.status === 'queued')
      setActiveScans(active)
      // Push fresh data into React Query cache — all pages update instantly
      qc.setQueryData(['scans', currentOrg.id], all)

      let statsInvalidated = false
      for (const scan of all) {
        const prev = prevStates.current.get(scan.id)
        const { status, finding_count, progress_pct, target_domain: domain } = scan

        if (!prev) {
          prevStates.current.set(scan.id, { status, finding_count, progress_pct })
          continue
        }

        // State transition events
        if (prev.status !== status) {
          if (prev.status === 'queued' && status === 'running') {
            addNotif({
              type: 'scan_started',
              title: 'Scan started',
              body: domain,
              scan_id: scan.id,
              domain,
            })
            // No toast.loading — ScanProgressBar already shows progress card
          } else if (status === 'completed') {
            addNotif({
              type: 'scan_completed',
              title: 'Scan completed',
              body: `${domain} — ${finding_count} finding${finding_count !== 1 ? 's' : ''}`,
              scan_id: scan.id,
              domain,
            })
            toast.success(`Scan complete — ${domain} (${finding_count} findings)`, {
              id: `scan-${scan.id}`,
              duration: 6000,
            })
            if (!statsInvalidated) { qc.invalidateQueries({ queryKey: ['org-stats', currentOrg.id] }); statsInvalidated = true }
          } else if (status === 'partial') {
            addNotif({
              type: 'scan_partial',
              title: 'Scan partial',
              body: `${domain} — some engines failed`,
              scan_id: scan.id,
              domain,
            })
            toast.warning(`Scan partial — ${domain}`, { id: `scan-${scan.id}`, duration: 6000 })
            if (!statsInvalidated) { qc.invalidateQueries({ queryKey: ['org-stats', currentOrg.id] }); statsInvalidated = true }
          } else if (status === 'failed') {
            addNotif({
              type: 'scan_failed',
              title: 'Scan failed',
              body: scan.error_msg ?? domain,
              scan_id: scan.id,
              domain,
            })
            toast.error(`Scan failed — ${domain}`, { id: `scan-${scan.id}`, duration: 8000 })
            if (!statsInvalidated) { qc.invalidateQueries({ queryKey: ['org-stats', currentOrg.id] }); statsInvalidated = true }
          } else if (status === 'cancelled') {
            addNotif({
              type: 'scan_cancelled',
              title: 'Scan cancelled',
              body: domain,
              scan_id: scan.id,
              domain,
            })
            toast.dismiss(`scan-${scan.id}`)
          }
        }

        // New findings while running
        if (
          status === 'running' &&
          finding_count > prev.finding_count &&
          finding_count - prev.finding_count >= 1
        ) {
          const delta = finding_count - prev.finding_count
          addNotif({
            type: 'new_discovery',
            title: `${delta} new finding${delta !== 1 ? 's' : ''}`,
            body: `${domain} — ${engineLabel(scan.current_engine)}`,
            scan_id: scan.id,
            domain,
          })
        }

        // Progress updates are shown by ScanProgressBar — no toast needed

        prevStates.current.set(scan.id, { status, finding_count, progress_pct })
      }
    } catch {
      // silent — network hiccup
    }
  }, [currentOrg, addNotif, qc])

  useEffect(() => {
    if (!currentOrg) return
    poll()
    // 3s when active scans present, 8s when idle
    function schedule() {
      intervalRef.current = setInterval(() => {
        poll()
      }, activeScans.length > 0 ? 3000 : 8000)
    }
    schedule()
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current)
    }
  }, [currentOrg, poll])

  // Re-schedule at faster rate when scans become active
  useEffect(() => {
    if (intervalRef.current) clearInterval(intervalRef.current)
    const delay = activeScans.length > 0 ? 3000 : 8000
    intervalRef.current = setInterval(poll, delay)
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current)
    }
  }, [activeScans.length, poll])

  const markAllRead = useCallback(() => {
    setNotifications((prev) => {
      const next = prev.map((n) => ({ ...n, read: true }))
      saveNotifs(keyRef.current, next)
      return next
    })
  }, [])

  const markRead = useCallback((id: string) => {
    setNotifications((prev) => {
      const next = prev.map((n) => (n.id === id ? { ...n, read: true } : n))
      saveNotifs(keyRef.current, next)
      return next
    })
  }, [])

  const clearNotifications = useCallback(() => {
    setNotifications([])
    saveNotifs(keyRef.current, [])
  }, [])

  const unreadCount = notifications.filter((n) => !n.read).length

  return (
    <ScanMonitorContext.Provider
      value={{ activeScans, notifications, unreadCount, markAllRead, markRead, clearNotifications }}
    >
      {children}
    </ScanMonitorContext.Provider>
  )
}

export function useScanMonitor() {
  return useContext(ScanMonitorContext)
}
