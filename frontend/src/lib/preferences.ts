// UI preferences — localStorage only, never tokens, scoped to UI state

function safeGet(key: string): string | null {
  try { return localStorage.getItem(key) } catch { return null }
}

function safeSet(key: string, value: string): void {
  try { localStorage.setItem(key, value) } catch {}
}

export const prefs = {
  getSidebarCollapsed: (): boolean => safeGet('mailox:sidebar-collapsed') === 'true',
  setSidebarCollapsed: (v: boolean): void => safeSet('mailox:sidebar-collapsed', String(v)),

  getDensity: (): 'compact' | 'comfortable' | 'spacious' =>
    (safeGet('mailox:density') as 'compact' | 'comfortable' | 'spacious') ?? 'comfortable',
  setDensity: (v: string): void => safeSet('mailox:density', v),

  getAccentColor: (): string => safeGet('mailox:accent') ?? '#E8173A',
  setAccentColor: (v: string): void => safeSet('mailox:accent', v),

  getReducedMotion: (): boolean => safeGet('mailox:reduced-motion') === 'true',
  setReducedMotion: (v: boolean): void => safeSet('mailox:reduced-motion', String(v)),
}
