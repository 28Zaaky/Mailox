import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { QueryClientProvider } from '@tanstack/react-query'
import { Toaster } from 'sonner'
import { AuthProvider } from './lib/auth'
import { queryClient } from './lib/queryClient'
import App from './App'
import { prefs } from './lib/preferences'
import './index.css'

function hexToRgb(hex: string): string {
  const h = hex.replace('#', '')
  const r = parseInt(h.slice(0, 2), 16)
  const g = parseInt(h.slice(2, 4), 16)
  const b = parseInt(h.slice(4, 6), 16)
  return `${r}, ${g}, ${b}`
}

export function applyAccent(color: string) {
  const root = document.documentElement
  root.style.setProperty('--color-accent', color)
  root.style.setProperty('--color-accent-rgb', hexToRgb(color))
}

// Apply stored preferences to <html> before first render
;(function applyPrefs() {
  const root = document.documentElement
  root.dataset.density = prefs.getDensity()
  applyAccent(prefs.getAccentColor())
  if (prefs.getReducedMotion()) root.dataset.reducedMotion = 'true'
})()

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <BrowserRouter>
      <QueryClientProvider client={queryClient}>
        <AuthProvider>
          <App />
          <Toaster
            position="bottom-right"
            toastOptions={{
              style: {
                background: '#121212',
                border: '1px solid #2a2a2e',
                color: '#c8ccd4',
                borderRadius: '10px',
                fontFamily: "'DM Sans', system-ui, sans-serif",
                fontSize: '13px',
                backdropFilter: 'blur(12px)',
              },
            }}
          />
        </AuthProvider>
      </QueryClientProvider>
    </BrowserRouter>
  </StrictMode>
)
