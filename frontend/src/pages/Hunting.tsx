import { useState, useEffect } from 'react'
import { Search, Play, Clock, CheckCircle, ChevronDown, ChevronUp } from 'lucide-react'
import { api } from '../services/api'
import { useToast } from '../components/Toast'

interface HuntEvidence {
  iteration: number
  tool: string
  args: Record<string, any>
  result: any
  duration_ms: number
}

interface HuntReport {
  hunt_id: string
  query: string
  hypothesis: string
  findings: string[]
  evidence: HuntEvidence[]
  mitre_hypotheses: string[]
  conclusion: string
  confidence: number
  iterations: number
  duration_seconds: number
  started_at: string
}

interface RecentHunt {
  hunt_id: string
  query: string
  conclusion: string
  confidence: number
  findings_count: number
  evidence_count: number
  duration_seconds: number
  started_at: string
}

export default function HuntingPage() {
  const [query, setQuery]     = useState('')
  const [host, setHost]       = useState('')
  const [loading, setLoading] = useState(false)
  const [report, setReport]   = useState<HuntReport | null>(null)
  const [recent, setRecent]   = useState<RecentHunt[]>([])
  const [expanded, setExpanded] = useState<number | null>(null)
  const [error, setError]     = useState<string | null>(null)
  const toast = useToast()

  // Load recent hunts on mount
  useEffect(() => {
    api.getRecentHunts().then(setRecent).catch(() => {})
  }, [])

  const runHunt = async () => {
    if (!query.trim()) return
    setLoading(true)
    setReport(null)
    setError(null)

    try {
      const result = await api.runHunt(query.trim(), host ? { host } : undefined)
      setReport(result)
      setRecent(prev => [
        {
          hunt_id: result.hunt_id,
          query: result.query,
          conclusion: result.conclusion,
          confidence: result.confidence,
          findings_count: result.findings.length,
          evidence_count: result.evidence.length,
          duration_seconds: result.duration_seconds,
          started_at: result.started_at,
        },
        ...prev.slice(0, 9),
      ])
    } catch (e: any) {
      toast.error(e?.response?.data?.detail || 'Threat hunt query failed to execute')
      setReport(null)
    } finally {
      setLoading(false)
    }
  }


  return (
    <div className="fade-in" style={{ display: 'grid', gridTemplateColumns: '1fr 300px', gap: 20, alignItems: 'start' }}>

      {/* ── Left: Query + Results ─────────────────────────────── */}
      <div>
        <div className="page-header">
          <div>
            <h1 className="page-title">Threat Hunting</h1>
            <p className="page-subtitle">
              Natural-language hunting powered by AI agents — searches your authorized telemetry
            </p>
          </div>
        </div>

        {/* Query Card */}
        <div className="card" style={{ marginBottom: 20 }}>
          <div className="card-title">Hunt Query</div>
          <textarea
            value={query}
            onChange={e => setQuery(e.target.value)}
            placeholder="Find endpoints with behavior similar to INC-2041, or hunt for encoded PowerShell executions originating from Office applications..."
            onKeyDown={e => { if (e.key === 'Enter' && e.ctrlKey) runHunt() }}
            style={{
              width: '100%', minHeight: 90,
              background: 'var(--bg-deep)', border: '1px solid var(--border-dim)',
              borderRadius: 'var(--radius-md)', padding: '10px 14px',
              color: 'var(--text-primary)', fontFamily: 'var(--font-sans)',
              fontSize: 14, resize: 'vertical', outline: 'none',
              marginBottom: 10,
            }}
          />
          <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
            <input
              value={host}
              onChange={e => setHost(e.target.value)}
              placeholder="Filter by host (optional)"
              style={{
                flex: 1, background: 'var(--bg-deep)', border: '1px solid var(--border-dim)',
                borderRadius: 'var(--radius-md)', padding: '8px 12px',
                color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', fontSize: 12, outline: 'none',
              }}
            />
            <button className="btn btn-primary" onClick={runHunt} disabled={loading || !query.trim()}>
              {loading
                ? <><span className="spinner" style={{ width: 13, height: 13 }} /> Hunting...</>
                : <><Play size={13} /> Hunt</>
              }
            </button>
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 6 }}>Ctrl+Enter to run</div>
        </div>

        {/* Error */}
        {error && (
          <div style={{ background: 'rgba(255,77,109,0.1)', border: '1px solid rgba(255,77,109,0.3)', borderRadius: 8, padding: '12px 16px', marginBottom: 16, color: 'var(--critical)', fontSize: 13 }}>
            {error}
          </div>
        )}

        {/* Hunt Report */}
        {report && (
          <div className="fade-in">
            {/* Summary */}
            <div className="card" style={{ marginBottom: 16 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 12 }}>
                <div>
                  <span className="mono" style={{ fontSize: 11 }}>{report.hunt_id}</span>
                  <div className="card-title" style={{ marginTop: 4, marginBottom: 0 }}>Hunt Conclusion</div>
                </div>
                <div style={{ display: 'flex', gap: 16, alignItems: 'center' }}>
                  <div style={{ textAlign: 'right' }}>
                    <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>Confidence</div>
                    <div style={{ fontSize: 22, fontWeight: 800, color: getConfColor(report.confidence), fontFamily: 'var(--font-mono)' }}>
                      {Math.round(report.confidence * 100)}%
                    </div>
                  </div>
                  <div style={{ textAlign: 'right' }}>
                    <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>Duration</div>
                    <div style={{ fontSize: 22, fontWeight: 800, color: 'var(--text-accent)', fontFamily: 'var(--font-mono)' }}>
                      {report.duration_seconds}s
                    </div>
                  </div>
                </div>
              </div>

              <p style={{ fontSize: 14, color: 'var(--text-secondary)', lineHeight: 1.7, marginBottom: 12 }}>
                {report.conclusion}
              </p>

              {/* MITRE hypotheses */}
              {report.mitre_hypotheses.length > 0 && (
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  {report.mitre_hypotheses.map(t => (
                    <span key={t} className="mono" style={{ fontSize: 11 }}>{t}</span>
                  ))}
                </div>
              )}
            </div>

            {/* Findings */}
            {report.findings.length > 0 && (
              <div className="card" style={{ marginBottom: 16 }}>
                <div className="card-title"><CheckCircle size={11} style={{ display: 'inline', marginRight: 4 }} />Findings ({report.findings.length})</div>
                {report.findings.map((f, i) => (
                  <div key={i} style={{ display: 'flex', gap: 10, padding: '8px 0', borderBottom: i < report.findings.length - 1 ? '1px solid var(--border-subtle)' : 'none' }}>
                    <span style={{ color: 'var(--low)', fontSize: 12, fontWeight: 700 }}>✓</span>
                    <span style={{ fontSize: 13, color: 'var(--text-secondary)' }}>{f}</span>
                  </div>
                ))}
              </div>
            )}

            {/* Evidence */}
            {report.evidence.length > 0 && (
              <div className="card">
                <div className="card-title">Evidence Trail ({report.evidence.length} tool calls)</div>
                {report.evidence.map((ev, i) => (
                  <div key={i} style={{ borderBottom: i < report.evidence.length - 1 ? '1px solid var(--border-subtle)' : 'none' }}>
                    <div
                      style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '10px 0', cursor: 'pointer' }}
                      onClick={() => setExpanded(expanded === i ? null : i)}
                    >
                      <div style={{ width: 22, height: 22, borderRadius: '50%', background: 'var(--bg-overlay)', border: '1px solid var(--border-dim)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 10, fontWeight: 700, color: 'var(--text-accent)', fontFamily: 'var(--font-mono)', flexShrink: 0 }}>
                        {ev.iteration}
                      </div>
                      <span className="mono" style={{ fontSize: 12, color: 'var(--text-accent)' }}>{ev.tool}</span>
                      <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                        {JSON.stringify(ev.args)}
                      </span>
                      <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                        {ev.duration_ms}ms
                      </span>
                      {expanded === i ? <ChevronUp size={13} color="var(--text-muted)" /> : <ChevronDown size={13} color="var(--text-muted)" />}
                    </div>
                    {expanded === i && (
                      <pre style={{ background: 'var(--bg-deep)', borderRadius: 6, padding: 12, fontSize: 11, color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', overflow: 'auto', maxHeight: 300, marginBottom: 10 }}>
                        {JSON.stringify(ev.result, null, 2)}
                      </pre>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* ── Right: Recent Hunts ───────────────────────────────── */}
      <div>
        <div className="card">
          <div className="card-title"><Clock size={11} style={{ display: 'inline', marginRight: 4 }} />Recent Hunts</div>
          {recent.length === 0
            ? <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>No hunts yet in this session.</div>
            : recent.map(h => (
              <div
                key={h.hunt_id}
                style={{ padding: '10px 0', borderBottom: '1px solid var(--border-subtle)', cursor: 'pointer' }}
                onClick={() => setQuery(h.query)}
              >
                <div style={{ fontSize: 12, color: 'var(--text-primary)', fontWeight: 500, marginBottom: 3, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {h.query}
                </div>
                <div style={{ display: 'flex', gap: 10, fontSize: 10, color: 'var(--text-muted)' }}>
                  <span style={{ color: getConfColor(h.confidence), fontWeight: 700 }}>{Math.round(h.confidence * 100)}%</span>
                  <span>{h.findings_count} findings</span>
                  <span>{h.duration_seconds}s</span>
                </div>
              </div>
            ))
          }
        </div>
      </div>
    </div>
  )
}

function getConfColor(c: number) {
  if (c >= 0.8) return 'var(--low)'
  if (c >= 0.5) return 'var(--medium)'
  return 'var(--high)'
}
