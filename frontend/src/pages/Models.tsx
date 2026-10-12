/**
 * Models Eval Page — per-agent precision/recall/F1, hallucination rate gauges,
 * and false positive rate trend sparklines.
 * Falls back to rich mock data when the backend /models/metrics endpoint is offline.
 */
import { useState, useEffect } from 'react'
import { BarChart2, Cpu, TrendingDown, AlertCircle, CheckCircle2, RefreshCw } from 'lucide-react'
import { api } from '../services/api'

// ── Types ─────────────────────────────────────────────────────────────────────

interface AgentMetrics {
  agent: string
  label: string
  precision: number
  recall: number
  f1: number
  hallucination_rate: number      // 0-1
  false_positive_rate: number     // 0-1
  total_invocations: number
  avg_latency_ms: number
  fp_trend: number[]              // last 7 data points
}

interface ModelMetrics {
  agents: AgentMetrics[]
  generated_at: string
  note: string
}

// ── Live Model Metrics ────────────────────────────────────────────────────────


// ── Helpers ───────────────────────────────────────────────────────────────────

function pct(v: number) { return `${Math.round(v * 100)}%` }
function ms(v: number)  { return v >= 1000 ? `${(v / 1000).toFixed(1)}s` : `${v}ms` }

function f1Color(f1: number) {
  if (f1 >= 0.90) return 'var(--low)'
  if (f1 >= 0.80) return 'var(--medium)'
  return 'var(--high)'
}
function hallColor(h: number) {
  if (h <= 0.05) return 'var(--low)'
  if (h <= 0.10) return 'var(--medium)'
  return 'var(--critical)'
}

// ── Circular Gauge ─────────────────────────────────────────────────────────────

function CircleGauge({ value, color, size = 60 }: { value: number; color: string; size?: number }) {
  const r = (size - 8) / 2
  const circ = 2 * Math.PI * r
  const filled = circ * value
  const cx = size / 2, cy = size / 2
  return (
    <svg width={size} height={size} style={{ transform: 'rotate(-90deg)' }}>
      <circle cx={cx} cy={cy} r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth={5} />
      <circle
        cx={cx} cy={cy} r={r}
        fill="none"
        stroke={color}
        strokeWidth={5}
        strokeDasharray={`${filled} ${circ - filled}`}
        strokeLinecap="round"
        style={{ transition: 'stroke-dasharray 0.6s ease' }}
      />
    </svg>
  )
}

// ── Sparkline ─────────────────────────────────────────────────────────────────

function Sparkline({ data, color }: { data: number[]; color: string }) {
  const W = 80, H = 28, pad = 2
  const max = Math.max(...data, 0.01)
  const pts = data.map((v, i) => {
    const x = pad + (i / (data.length - 1)) * (W - pad * 2)
    const y = H - pad - (v / max) * (H - pad * 2)
    return `${x},${y}`
  }).join(' ')
  const fill = data.map((v, i) => {
    const x = pad + (i / (data.length - 1)) * (W - pad * 2)
    const y = H - pad - (v / max) * (H - pad * 2)
    return `${x},${y}`
  })
  const fillPath = `M${fill[0]} L${fill.slice(1).join(' L')} L${W - pad},${H - pad} L${pad},${H - pad} Z`

  return (
    <svg width={W} height={H} style={{ overflow: 'visible' }}>
      <defs>
        <linearGradient id={`sg-${color.replace('#', '')}`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.3" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      <path d={fillPath} fill={`url(#sg-${color.replace('#', '')})`} />
      <polyline points={pts} fill="none" stroke={color} strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

// ── Main Component ─────────────────────────────────────────────────────────────

import { usePolling } from '../hooks/usePolling'

export default function ModelsPage() {
  const [metrics, setMetrics] = useState<ModelMetrics | null>(null)
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState<AgentMetrics | null>(null)
  const [daysRange, setDaysRange] = useState<number>(30)

  const load = async (days: number = daysRange) => {
    try {
      const data = await api.getModelMetrics(days)
      setMetrics(data)
    } catch {
      // Backend offline or no traces yet — show empty state gracefully
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load(daysRange) }, [daysRange])
  usePolling(() => load(daysRange), 2_000)

  const agents = metrics?.agents ?? []
  const avgF1  = agents.length ? agents.reduce((s, a) => s + a.f1, 0) / agents.length : 0
  const avgHall= agents.length ? agents.reduce((s, a) => s + a.hallucination_rate, 0) / agents.length : 0
  const totalInv = agents.reduce((s, a) => s + a.total_invocations, 0)

  return (
    <div className="fade-in">
      {/* ── Header ─────────────────────────────────────────────────── */}
      <div className="page-header">
        <div>
          <h1 className="page-title">Model Evaluation</h1>
          <p className="page-subtitle">
            Per-agent performance metrics — precision, recall, F1, hallucination rate, false positive rate
          </p>
        </div>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          {/* Time Range Selector */}
          <div style={{ display: 'flex', background: 'var(--bg-deep)', borderRadius: 8, padding: 3, border: '1px solid var(--border-dim)' }}>
            {[
              { label: '7D', days: 7 },
              { label: '30D', days: 30 },
              { label: '90D', days: 90 },
              { label: 'ALL', days: 365 },
            ].map(({ label, days }) => (
              <button
                key={label}
                onClick={() => setDaysRange(days)}
                style={{
                  background: daysRange === days ? 'var(--bg-raised)' : 'transparent',
                  color: daysRange === days ? 'var(--text-accent)' : 'var(--text-muted)',
                  border: daysRange === days ? '1px solid var(--border-bright)' : 'none',
                  borderRadius: 6,
                  padding: '3px 10px',
                  fontSize: 11,
                  fontWeight: 600,
                  cursor: 'pointer',
                  transition: 'all 0.15s ease',
                }}
              >
                {label}
              </button>
            ))}
          </div>

          <button className="btn btn-ghost" style={{ fontSize: 11 }} onClick={() => load(daysRange)} disabled={loading}>
            <RefreshCw size={11} /> Refresh
          </button>
        </div>
      </div>


      {/* ── Summary KPIs ────────────────────────────────────────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 14, marginBottom: 20 }}>
        {[
          { label: 'Avg F1 Score',       value: pct(avgF1),    icon: BarChart2,    color: f1Color(avgF1) },
          { label: 'Avg Hallucination',   value: pct(avgHall),  icon: AlertCircle,  color: hallColor(avgHall) },
          { label: 'Total Invocations',   value: totalInv.toLocaleString(), icon: Cpu, color: 'var(--text-accent)' },
          { label: 'Agents Tracked',      value: agents.length, icon: CheckCircle2, color: 'var(--low)' },
        ].map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="card" style={{ padding: '16px 20px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <div>
                <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700, letterSpacing: '0.05em', marginBottom: 6 }}>
                  {label}
                </div>
                <div style={{ fontSize: 26, fontWeight: 800, color, fontFamily: 'var(--font-mono)', letterSpacing: '-1px' }}>
                  {value}
                </div>
              </div>
              <div style={{ width: 32, height: 32, borderRadius: 8, background: `color-mix(in srgb, ${color} 15%, transparent)`, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <Icon size={15} color={color} />
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* ── Metrics Table ────────────────────────────────────────────── */}
      <div className="card" style={{ marginBottom: 20 }}>
        <div className="card-title">Per-Agent Metrics</div>
        {loading
          ? <div className="empty-state"><div className="spinner" /></div>
          : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Agent</th>
                  <th>Precision</th>
                  <th>Recall</th>
                  <th>F1 Score</th>
                  <th>Hallucination</th>
                  <th>False Positive</th>
                  <th>FP Trend (7d)</th>
                  <th>Invocations</th>
                  <th>Avg Latency</th>
                </tr>
              </thead>
              <tbody>
                {agents.map(a => (
                  <tr
                    key={a.agent}
                    onClick={() => setSelected(selected?.agent === a.agent ? null : a)}
                    style={{
                      cursor: 'pointer',
                      background: selected?.agent === a.agent ? 'var(--bg-raised)' : '',
                    }}
                  >
                    <td>
                      <div style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: 13 }}>{a.label}</div>
                      <div style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>{a.agent}</div>
                    </td>
                    <td>
                      <MetricBar value={a.precision} color="var(--info)" />
                    </td>
                    <td>
                      <MetricBar value={a.recall} color="var(--text-accent)" />
                    </td>
                    <td>
                      <span style={{ fontSize: 15, fontWeight: 800, color: f1Color(a.f1), fontFamily: 'var(--font-mono)' }}>
                        {pct(a.f1)}
                      </span>
                    </td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <CircleGauge value={a.hallucination_rate} color={hallColor(a.hallucination_rate)} size={36} />
                        <span style={{ fontSize: 12, fontFamily: 'var(--font-mono)', color: hallColor(a.hallucination_rate), fontWeight: 700 }}>
                          {pct(a.hallucination_rate)}
                        </span>
                      </div>
                    </td>
                    <td>
                      <span style={{ fontSize: 13, fontFamily: 'var(--font-mono)', color: a.false_positive_rate > 0.15 ? 'var(--high)' : 'var(--medium)', fontWeight: 600 }}>
                        {pct(a.false_positive_rate)}
                      </span>
                    </td>
                    <td>
                      <Sparkline data={a.fp_trend} color={a.false_positive_rate > 0.15 ? 'var(--high)' : 'var(--low)'} />
                    </td>
                    <td>
                      <span className="mono" style={{ fontSize: 12 }}>{a.total_invocations.toLocaleString()}</span>
                    </td>
                    <td>
                      <span className="mono" style={{ fontSize: 12, color: a.avg_latency_ms > 10000 ? 'var(--high)' : 'var(--text-secondary)' }}>
                        {ms(a.avg_latency_ms)}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )
        }
      </div>

      {/* ── Detail Panel (selected agent) ───────────────────────────── */}
      {selected && (
        <div className="card fade-in" style={{ marginBottom: 20 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16 }}>
            <div className="card-title" style={{ marginBottom: 0 }}>
              {selected.label} — Detailed Breakdown
            </div>
            <button
              onClick={() => setSelected(null)}
              style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 16 }}
            >✕</button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16 }}>
            {/* Confusion-matrix inspired breakdown */}
            <div style={{ background: 'var(--bg-deep)', borderRadius: 8, padding: 16 }}>
              <div style={{ fontSize: 10, textTransform: 'uppercase', fontWeight: 700, color: 'var(--text-muted)', marginBottom: 10 }}>Classification</div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                {[
                  { label: 'True Positive',  value: pct(selected.recall * selected.precision), color: 'var(--low)' },
                  { label: 'False Positive', value: pct(selected.false_positive_rate),          color: 'var(--high)' },
                  { label: 'True Negative',  value: pct(1 - selected.false_positive_rate),      color: 'var(--info)' },
                  { label: 'False Negative', value: pct(1 - selected.recall),                   color: 'var(--medium)' },
                ].map(({ label, value, color }) => (
                  <div key={label} style={{ background: 'var(--bg-surface)', borderRadius: 6, padding: '10px 12px', textAlign: 'center' }}>
                    <div style={{ fontSize: 18, fontWeight: 800, fontFamily: 'var(--font-mono)', color }}>{value}</div>
                    <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>{label}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Hallucination gauge full */}
            <div style={{ background: 'var(--bg-deep)', borderRadius: 8, padding: 16, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 8 }}>
              <div style={{ fontSize: 10, textTransform: 'uppercase', fontWeight: 700, color: 'var(--text-muted)' }}>Hallucination Rate</div>
              <div style={{ position: 'relative', display: 'inline-flex', alignItems: 'center', justifyContent: 'center' }}>
                <CircleGauge value={selected.hallucination_rate} color={hallColor(selected.hallucination_rate)} size={80} />
                <div style={{ position: 'absolute', fontFamily: 'var(--font-mono)', fontWeight: 800, fontSize: 16, color: hallColor(selected.hallucination_rate) }}>
                  {pct(selected.hallucination_rate)}
                </div>
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-secondary)', textAlign: 'center' }}>
                {selected.hallucination_rate <= 0.05 ? '✓ Well within acceptable range' :
                  selected.hallucination_rate <= 0.10 ? '⚠ Approaching threshold' :
                  '✗ Exceeds 10% — consider retraining'}
              </div>
            </div>

            {/* FP trend sparkline full */}
            <div style={{ background: 'var(--bg-deep)', borderRadius: 8, padding: 16, display: 'flex', flexDirection: 'column', gap: 10 }}>
              <div style={{ fontSize: 10, textTransform: 'uppercase', fontWeight: 700, color: 'var(--text-muted)' }}>False Positive Rate — 7-Day Trend</div>
              <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <svg width="100%" height={60} viewBox={`0 0 200 60`}>
                  {selected.fp_trend.map((v, i) => {
                    const max = Math.max(...selected.fp_trend, 0.01)
                    const x = 10 + (i / (selected.fp_trend.length - 1)) * 180
                    const y = 55 - (v / max) * 45
                    const color = v > 0.15 ? '#f97316' : '#4ade80'
                    return (
                      <g key={i}>
                        <circle cx={x} cy={y} r={3} fill={color} />
                        {i < selected.fp_trend.length - 1 && (
                          <line
                            x1={x} y1={y}
                            x2={10 + ((i + 1) / (selected.fp_trend.length - 1)) * 180}
                            y2={55 - (selected.fp_trend[i + 1] / max) * 45}
                            stroke={color} strokeWidth={1.5} strokeLinecap="round"
                          />
                        )}
                        <text x={x} y={56} fontSize={8} fill="var(--text-muted)" textAnchor="middle">
                          D{i + 1}
                        </text>
                      </g>
                    )
                  })}
                </svg>
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                Current: <span style={{ fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
                  {pct(selected.fp_trend[selected.fp_trend.length - 1])}
                </span>
                {' '}|{' '}
                Δ7d: <span style={{
                  fontWeight: 700, fontFamily: 'var(--font-mono)',
                  color: selected.fp_trend[6] < selected.fp_trend[0] ? 'var(--low)' : 'var(--high)',
                }}>
                  {selected.fp_trend[6] < selected.fp_trend[0] ? '↓' : '↑'}
                  {pct(Math.abs(selected.fp_trend[6] - selected.fp_trend[0]))}
                </span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── Gauge Legend row ─────────────────────────────────────────── */}
      <div className="card" style={{ padding: '14px 20px' }}>
        <div style={{ display: 'flex', gap: 24, alignItems: 'center', flexWrap: 'wrap' }}>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 700, textTransform: 'uppercase' }}>Legend</div>
          {[
            { color: 'var(--low)',      label: 'F1 ≥ 90%  /  Hall ≤ 5%  /  FP ≤ 10%' },
            { color: 'var(--medium)',   label: 'F1 80–90%  /  Hall 5–10%  /  FP 10–20%' },
            { color: 'var(--high)',     label: 'F1 < 80%  /  Hall > 10%  /  FP > 20%' },
          ].map(({ color, label }) => (
            <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <div style={{ width: 10, height: 10, borderRadius: '50%', background: color, flexShrink: 0 }} />
              <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{label}</span>
            </div>
          ))}
          {metrics?.generated_at && (
            <div style={{ marginLeft: 'auto', fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              Generated: {new Date(metrics.generated_at).toLocaleString()}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Inline metric bar ─────────────────────────────────────────────────────────

function MetricBar({ value, color }: { value: number; color: string }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <div style={{ width: 60, height: 5, background: 'rgba(255,255,255,0.06)', borderRadius: 3, overflow: 'hidden', flexShrink: 0 }}>
        <div style={{ width: `${value * 100}%`, height: '100%', background: color, borderRadius: 3, transition: 'width 0.5s ease' }} />
      </div>
      <span style={{ fontSize: 12, fontFamily: 'var(--font-mono)', color, fontWeight: 600 }}>
        {pct(value)}
      </span>
    </div>
  )
}
