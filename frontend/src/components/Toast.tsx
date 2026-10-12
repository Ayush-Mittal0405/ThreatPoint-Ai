/**
 * Toast notification system — self-contained context + hook.
 * Usage:
 *   wrap your app with <ToastProvider>
 *   in any component: const { toast } = useToast()
 *   then: toast.success('Done!') / toast.error('Oops') / toast.warn('Watch out') / toast.info('FYI')
 */
import { createContext, useContext, useState, useCallback, useRef } from 'react'
import type { ReactNode } from 'react'
import { CheckCircle, AlertTriangle, XCircle, Info, X } from 'lucide-react'

// ── Types ─────────────────────────────────────────────────────────────────────

type ToastVariant = 'success' | 'error' | 'warn' | 'info'

interface ToastItem {
  id: string
  message: string
  variant: ToastVariant
}

interface ToastAPI {
  success: (msg: string) => void
  error:   (msg: string) => void
  warn:    (msg: string) => void
  info:    (msg: string) => void
}

const ToastContext = createContext<ToastAPI>({
  success: () => {}, error: () => {}, warn: () => {}, info: () => {},
})

// ── Styles ────────────────────────────────────────────────────────────────────

const VARIANT_STYLES: Record<ToastVariant, { bg: string; border: string; icon: typeof CheckCircle; iconColor: string }> = {
  success: { bg: 'rgba(74,222,128,0.10)',  border: 'rgba(74,222,128,0.30)',   icon: CheckCircle,    iconColor: 'var(--low)' },
  error:   { bg: 'rgba(255,77,109,0.10)',  border: 'rgba(255,77,109,0.30)',   icon: XCircle,        iconColor: 'var(--critical)' },
  warn:    { bg: 'rgba(250,204,21,0.10)',  border: 'rgba(250,204,21,0.30)',   icon: AlertTriangle,  iconColor: 'var(--medium)' },
  info:    { bg: 'rgba(99,179,237,0.10)',  border: 'rgba(99,179,237,0.30)',   icon: Info,           iconColor: 'var(--info)' },
}

// ── Provider ─────────────────────────────────────────────────────────────────

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([])
  const timerRef = useRef<Record<string, ReturnType<typeof setTimeout>>>({})

  const dismiss = useCallback((id: string) => {
    setToasts(prev => prev.filter(t => t.id !== id))
    clearTimeout(timerRef.current[id])
    delete timerRef.current[id]
  }, [])

  const push = useCallback((message: string, variant: ToastVariant) => {
    const id = `toast-${Date.now()}-${Math.random().toString(36).slice(2)}`
    setToasts(prev => [...prev.slice(-4), { id, message, variant }])   // max 5
    timerRef.current[id] = setTimeout(() => dismiss(id), 5000)
  }, [dismiss])

  const api: ToastAPI = {
    success: (m) => push(m, 'success'),
    error:   (m) => push(m, 'error'),
    warn:    (m) => push(m, 'warn'),
    info:    (m) => push(m, 'info'),
  }

  return (
    <ToastContext.Provider value={api}>
      {children}
      {/* ── Toast Stack ─────────────────────────────────────────── */}
      <div
        style={{
          position: 'fixed', bottom: 24, right: 24, zIndex: 9999,
          display: 'flex', flexDirection: 'column-reverse', gap: 10,
          pointerEvents: 'none',
        }}
        aria-live="polite"
        aria-label="Notifications"
      >
        {toasts.map(t => {
          const { bg, border, icon: Icon, iconColor } = VARIANT_STYLES[t.variant]
          return (
            <div
              key={t.id}
              role="alert"
              style={{
                display: 'flex', alignItems: 'center', gap: 12,
                background: `color-mix(in srgb, ${bg} 100%, var(--bg-surface) 0%)`,
                backdropFilter: 'blur(12px)',
                border: `1px solid ${border}`,
                borderRadius: 10,
                padding: '12px 16px',
                minWidth: 280, maxWidth: 380,
                boxShadow: '0 8px 32px rgba(0,0,0,0.4)',
                pointerEvents: 'all',
                animation: 'toast-slide-in 0.25s ease',
              }}
            >
              <Icon size={16} color={iconColor} style={{ flexShrink: 0 }} />
              <span style={{ flex: 1, fontSize: 13, color: 'var(--text-primary)', lineHeight: 1.4 }}>
                {t.message}
              </span>
              <button
                onClick={() => dismiss(t.id)}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 2, flexShrink: 0 }}
                aria-label="Dismiss"
              >
                <X size={13} />
              </button>
            </div>
          )
        })}
      </div>
    </ToastContext.Provider>
  )
}

// ── Hook ─────────────────────────────────────────────────────────────────────

export function useToast() {
  return useContext(ToastContext)
}
