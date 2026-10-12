/**
 * usePolling — generic hook that calls `fn` on a fixed interval.
 *
 * Usage:
 *   usePolling(() => fetchStats().then(setStats), 30_000)
 *
 * The first call fires immediately on mount.
 * Polling stops when the component unmounts.
 */
import { useEffect, useRef, useCallback } from 'react'

export function usePolling(
  fn: () => void | Promise<void>,
  intervalMs: number,
  enabled = true,
) {
  const fnRef = useRef(fn)
  fnRef.current = fn   // always latest reference, no stale closure

  useEffect(() => {
    if (!enabled) return

    let cancelled = false

    const run = async () => {
      if (!cancelled) {
        try { await fnRef.current() } catch { /* caller handles errors */ }
      }
    }

    // Immediate first call
    run()

    const id = setInterval(run, intervalMs)
    return () => {
      cancelled = true
      clearInterval(id)
    }
  }, [intervalMs, enabled])
}
