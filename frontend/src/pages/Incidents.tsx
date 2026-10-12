import { useState, useEffect } from 'react'
import { AlertTriangle, Play, BookOpen, RefreshCw, Star, MessageSquare, Download, FileText } from 'lucide-react'
import { api, Incident } from '../services/api'
import { useToast } from '../components/Toast'
import { usePolling } from '../hooks/usePolling'

import AttackStoryView from '../components/AttackStoryView'
import FeedbackModal from '../components/FeedbackModal'

function SeverityBadge({ s }: { s: string }) {
  return <span className={`badge-severity ${s}`}>{s}</span>
}
function StatusBadge({ s }: { s: string }) {
  return <span className={`badge-status ${s}`}>{s.replace('_', ' ')}</span>
}
function getRiskColor(score?: number) {
  if (!score) return 'var(--text-muted)'
  if (score >= 81) return 'var(--critical)'
  if (score >= 61) return 'var(--high)'
  if (score >= 41) return 'var(--medium)'
  return 'var(--low)'
}

type DetailTab = 'trace' | 'story'

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [loading, setLoading]     = useState(true)
  const [selected, setSelected]   = useState<Incident | null>(null)
  const [trace, setTrace]         = useState<any[]>([])
  const [tab, setTab]             = useState<DetailTab>('trace')
  const [story, setStory]         = useState<any | null>(null)
  const [storyLoading, setStoryLoading] = useState(false)
  const [feedbackOpen, setFeedbackOpen] = useState(false)
  const toast = useToast()

  const load = async () => {
    try {
      const data = await api.getIncidents()
      setIncidents(data.incidents || [])
    } catch {
      // Backend offline or error — keep empty list gracefully
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])
  usePolling(load, 2_000)

  const openDetail = async (inc: Incident) => {
    setSelected(inc)
    setStory(inc.attack_story || null)
    setTab('trace')
    try {
      const t = await api.getIncidentTrace(inc.id)
      setTrace(t || [])
    } catch {
      setTrace([])
    }
  }

  const triggerInvestigation = async (e: React.MouseEvent, incId: string) => {
    e.stopPropagation()
    try {
      await api.triggerInvestigation(incId)
      toast.info('AI investigation started! Check trace for progress.')
      load()
    } catch {
      toast.warn('Demo mode: Simulated AI investigation started for ' + incId)
    }
  }

  const generateStory = async () => {
    if (!selected) return
    setStoryLoading(true)
    try {
      const s = await api.generateAttackStory(selected.id)
      setStory(s)
      setTab('story')
      toast.info('Attack Story generated successfully!')
    } catch {
      toast.error('Could not generate attack story for this incident.')
    }
    setStoryLoading(false)
  }

  return (
    <div className="fade-in" style={{ display: 'grid', gridTemplateColumns: selected ? '1fr 460px' : '1fr', gap: 20 }}>


      {/* ── Incident List ────────────────────────────────────── */}
      <div>
        <div className="page-header">
          <div>
            <h1 className="page-title">Incidents</h1>
            <p className="page-subtitle">Correlated security incidents</p>
          </div>
          <button className="btn btn-ghost" onClick={load} style={{ fontSize: 11 }}>
            <RefreshCw size={11} /> Refresh
          </button>
        </div>

        <div className="card">
          {loading
            ? <div className="empty-state"><div className="spinner" /></div>
            : (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>ID</th><th>Title</th><th>Severity</th>
                    <th>Risk</th><th>Status</th><th>MITRE</th><th></th>
                  </tr>
                </thead>
                <tbody>
                  {incidents.map(inc => (
                    <tr
                      key={inc.id}
                      onClick={() => openDetail(inc)}
                      style={{ cursor: 'pointer', background: selected?.id === inc.id ? 'var(--bg-raised)' : '' }}
                    >
                      <td><span className="mono">{inc.incident_id}</span></td>
                      <td style={{ color: 'var(--text-primary)', maxWidth: 240 }}>{inc.title}</td>
                      <td><SeverityBadge s={inc.severity} /></td>
                      <td>
                        <span style={{ color: getRiskColor(inc.risk_score), fontFamily: 'var(--font-mono)', fontSize: 13 }}>
                          {inc.risk_score ? `${inc.risk_score}/100` : '—'}
                        </span>
                      </td>
                      <td><StatusBadge s={inc.status} /></td>
                      <td style={{ fontSize: 11 }}>
                        {(inc.mitre_techniques || []).slice(0, 2).map(t =>
                          <span key={t} className="mono" style={{ marginRight: 4 }}>{t}</span>
                        )}
                      </td>
                      <td>
                        <button
                          className="btn btn-ghost"
                          style={{ padding: '3px 8px', fontSize: 10 }}
                          onClick={e => triggerInvestigation(e, inc.id)}
                        >
                          <Play size={9} /> Investigate
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )
          }
        </div>
      </div>

      {/* ── Detail Panel ─────────────────────────────────────── */}
      {selected && (
        <div>
          <div className="page-header" style={{ marginBottom: 12 }}>
            <div>
              <div className="mono" style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 2 }}>
                {selected.incident_id}
              </div>
              <h2 style={{ fontSize: 15, fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1.3 }}>
                {selected.title}
              </h2>
            </div>
            <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
              <a
                href={api.getIncidentMarkdownExportUrl(selected.id)}
                download={`${selected.incident_id}_report.md`}
                className="btn btn-ghost"
                style={{ fontSize: 11, padding: '4px 10px', textDecoration: 'none', color: 'var(--text-secondary)', borderColor: 'var(--border-dim)' }}
                title="Download Executive Markdown Report"
              >
                <Download size={12} style={{ marginRight: 4 }} /> Export MD
              </a>
              <button
                className="btn btn-ghost"
                style={{ fontSize: 11, padding: '4px 10px', color: 'var(--text-accent)', borderColor: 'var(--border-bright)' }}
                onClick={() => window.open(api.getIncidentHtmlExportUrl(selected.id), '_blank')}
                title="Open Printable HTML/PDF Report"
              >
                <FileText size={12} style={{ marginRight: 4 }} /> View Dossier
              </button>
              <button
                className="btn btn-ghost"
                style={{ fontSize: 11, padding: '4px 10px', color: 'var(--medium)', borderColor: 'var(--border-dim)' }}
                onClick={() => setFeedbackOpen(true)}
              >
                <Star size={12} style={{ marginRight: 4 }} /> Review AI
              </button>
              <button className="btn btn-ghost" style={{ fontSize: 10, padding: '4px 8px' }} onClick={() => setSelected(null)}>✕</button>
            </div>
          </div>


          {/* Entities quick-view */}
          {selected.entities && (
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 12 }}>
              {(selected.entities.hosts || []).map(h => (
                <span key={h} className="mono" style={{ fontSize: 11, padding: '2px 8px', background: 'rgba(99,179,237,0.08)', border: '1px solid var(--border-dim)', borderRadius: 4 }}>
                  🖥 {h}
                </span>
              ))}
              {(selected.entities.users || []).map(u => (
                <span key={u} className="mono" style={{ fontSize: 11, padding: '2px 8px', background: 'rgba(167,139,250,0.08)', border: '1px solid rgba(167,139,250,0.2)', borderRadius: 4 }}>
                  👤 {u}
                </span>
              ))}
            </div>
          )}

          {/* Tabs */}
          <div style={{ display: 'flex', gap: 4, marginBottom: 12, borderBottom: '1px solid var(--border-subtle)', paddingBottom: 8 }}>
            {(['trace', 'story'] as DetailTab[]).map(t => (
              <button
                key={t}
                onClick={() => setTab(t)}
                className="btn btn-ghost"
                style={{
                  fontSize: 11, padding: '4px 12px',
                  background: tab === t ? 'var(--bg-raised)' : 'transparent',
                  color: tab === t ? 'var(--text-accent)' : 'var(--text-secondary)',
                  borderColor: tab === t ? 'var(--border-bright)' : 'transparent',
                }}
              >
                {t === 'trace' ? '🔍 AI Trace' : '📖 Attack Story'}
              </button>
            ))}
            <button
              className="btn btn-ghost"
              style={{ fontSize: 11, padding: '4px 12px', marginLeft: 'auto' }}
              onClick={generateStory}
              disabled={storyLoading}
            >
              {storyLoading
                ? <><span className="spinner" style={{ width: 11, height: 11 }} /> Generating...</>
                : <><BookOpen size={11} /> Generate Story</>
              }
            </button>
          </div>

          {/* Tab Content */}
          {tab === 'trace' && (
            <div className="card">
              <div className="card-title">AI Investigation Trace</div>
              {trace.length === 0
                ? <div style={{ color: 'var(--text-muted)', fontSize: 12 }}>No trace yet. Click "Investigate" to start.</div>
                : trace.map((t, i) => (
                  <div key={i} className="trace-item">
                    <div className={`trace-step ${t.success ? 'success' : 'failed'}`}>{t.step}</div>
                    <div className="trace-content">
                      <div className="trace-agent">{t.agent_name}</div>
                      <div className="trace-action">{t.tool_name || t.action}</div>
                      {t.tool_args && (
                        <div style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginTop: 2 }}>
                          {JSON.stringify(t.tool_args)}
                        </div>
                      )}
                    </div>
                    <div className="trace-time">{t.duration_ms ? `${t.duration_ms}ms` : ''}</div>
                  </div>
                ))
              }
            </div>
          )}

          {tab === 'story' && (
            <AttackStoryView incidentId={selected.id} story={story} />
          )}

          {/* Feedback Modal */}
          <FeedbackModal
            isOpen={feedbackOpen}
            incident={selected}
            onClose={() => setFeedbackOpen(false)}
            onFeedbackSubmitted={load}
          />
        </div>
      )}
    </div>
  )
}


