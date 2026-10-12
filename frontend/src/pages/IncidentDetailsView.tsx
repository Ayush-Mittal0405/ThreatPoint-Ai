import { useState } from 'react'
import {
  ChevronLeft, AlertTriangle, Shield, User, Clock,
  Terminal, Globe, Key, FileText, CheckCircle2, Copy,
  ExternalLink, Zap, ChevronRight
} from 'lucide-react'
import { Link } from 'react-router-dom'

export default function IncidentDetailsView() {
  const [activeTab, setActiveTab] = useState<'overview' | 'alerts' | 'timeline' | 'analysis' | 'actions'>('overview')
  const [status, setStatus] = useState('Investigating')
  const [copiedKey, setCopiedKey] = useState<string | null>(null)

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text)
    setCopiedKey(key)
    setTimeout(() => setCopiedKey(null), 2000)
  }

  return (
    <div className="page-container">
      {/* ── Breadcrumb & Top Bar ───────────────────────────────────── */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16, fontSize: 12, color: 'var(--text-muted)' }}>
        <Link to="/alerts-view" style={{ color: 'var(--text-secondary)', textDecoration: 'none', display: 'flex', alignItems: 'center', gap: 4 }}>
          <ChevronLeft size={14} />
          <span>Incidents</span>
        </Link>
        <span>/</span>
        <span style={{ color: '#fff', fontWeight: 600, fontFamily: 'var(--font-mono)' }}>INC-2025-0102</span>
      </div>

      {/* ── Incident Header matching Screen 3 ──────────────────────── */}
      <div className="tp-card" style={{ marginBottom: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 14 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
              <span className="badge-pill badge-critical">CRITICAL</span>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-secondary)' }}>INC-2025-0102</span>
              <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>• Opened 14m ago</span>
            </div>
            <h1 style={{ fontSize: 18, fontWeight: 700, color: '#ffffff', letterSpacing: '-0.3px', margin: 0 }}>
              Suspicious PowerShell Execution with C2 Beaconing
            </h1>
          </div>

          {/* Action buttons and Status Dropdowns */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Status:</span>
              <select
                className="tp-select"
                value={status}
                onChange={e => setStatus(e.target.value)}
              >
                <option value="Active">Active (Open)</option>
                <option value="Investigating">Investigating</option>
                <option value="Contained">Contained</option>
                <option value="Resolved">Resolved</option>
              </select>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Assignee:</span>
              <div className="tp-select" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <div style={{ width: 16, height: 16, borderRadius: '50%', background: '#ec4899', color: '#fff', fontSize: 10, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  AI
                </div>
                <span>ThreatPoint AI</span>
              </div>
            </div>

            <button
              style={{
                background: '#ef4444',
                color: '#fff',
                border: 'none',
                borderRadius: 'var(--radius-md)',
                padding: '6px 14px',
                fontSize: 12,
                fontWeight: 600,
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: 6,
              }}
              onClick={() => alert('Host DESKTOP-GJ53HIT isolated from network!')}
            >
              <Zap size={13} />
              <span>Isolate Host</span>
            </button>
          </div>
        </div>

        {/* Sub-tabs matching Screen 3 */}
        <div style={{ display: 'flex', gap: 16, borderTop: '1px solid var(--border-subtle)', marginTop: 16, paddingTop: 12 }}>
          {(['overview', 'alerts', 'timeline', 'analysis', 'actions'] as const).map(tab => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              style={{
                background: 'transparent',
                border: 'none',
                cursor: 'pointer',
                fontSize: 12,
                fontWeight: activeTab === tab ? 600 : 500,
                color: activeTab === tab ? '#ffffff' : 'var(--text-muted)',
                paddingBottom: 4,
                borderBottom: activeTab === tab ? '2px solid var(--magenta)' : '2px solid transparent',
                textTransform: 'capitalize'
              }}
            >
              {tab === 'alerts' ? 'Alerts (5)' : tab === 'analysis' ? 'AI Analysis' : tab}
            </button>
          ))}
        </div>
      </div>

      {/* ── Two Column Layout matching Screen 3 ────────────────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.1fr 1fr', gap: 16 }}>
        {/* Left Column: Summary & Key Indicators */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {/* Incident Description */}
          <div className="tp-card">
            <h3 style={{ fontSize: 13, fontWeight: 600, color: '#f1f5f9', marginBottom: 10 }}>
              Incident Summary & Attack Vector
            </h3>
            <p style={{ fontSize: 12, lineHeight: 1.6, color: 'var(--text-secondary)' }}>
              An anomalous base64-encoded PowerShell script was executed via <code style={{ color: '#ec4899', background: 'rgba(236,72,153,0.1)', padding: '1px 5px', borderRadius: 3 }}>cmd.exe</code> spawned from an unmanaged process. The script established persistent outbound TCP beaconing on port 443 to external C2 node <code style={{ color: '#38bdf8' }}>185.199.110.5</code> and attempted to register a scheduled task named <code style={{ color: '#eab308' }}>'SystemHealthCheck'</code> for hourly persistence.
            </p>
          </div>

          {/* Key Indicators Table/List */}
          <div className="tp-card">
            <h3 style={{ fontSize: 13, fontWeight: 600, color: '#f1f5f9', marginBottom: 14 }}>
              Key Indicators (IOCs & Entities)
            </h3>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              {/* Process */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 10px', background: 'var(--bg-deep)', borderRadius: 6 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Terminal size={14} color="#f97316" />
                  <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Process:</span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: '#fff' }}>powershell.exe (PID: 4812)</span>
                </div>
                <button
                  onClick={() => handleCopy('powershell.exe -enc SQBFAFgA', 'proc')}
                  style={{ background: 'transparent', border: 'none', color: copiedKey === 'proc' ? '#10b981' : 'var(--text-muted)', cursor: 'pointer' }}
                >
                  {copiedKey === 'proc' ? <CheckCircle2 size={13} /> : <Copy size={13} />}
                </button>
              </div>

              {/* Destination C2 IP */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 10px', background: 'var(--bg-deep)', borderRadius: 6 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Globe size={14} color="#ef4444" />
                  <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>C2 Server:</span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: '#f87171' }}>185.199.110.5:443 (NL)</span>
                </div>
                <button
                  onClick={() => handleCopy('185.199.110.5', 'c2')}
                  style={{ background: 'transparent', border: 'none', color: copiedKey === 'c2' ? '#10b981' : 'var(--text-muted)', cursor: 'pointer' }}
                >
                  {copiedKey === 'c2' ? <CheckCircle2 size={13} /> : <Copy size={13} />}
                </button>
              </div>

              {/* SHA-256 Hash */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 10px', background: 'var(--bg-deep)', borderRadius: 6 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, overflow: 'hidden' }}>
                  <Key size={14} color="#eab308" />
                  <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>SHA-256:</span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: '#cbd5e1', textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap', maxWidth: 220 }}>
                    e3b0c44298fc1c149afbf4c8996fb924...
                  </span>
                </div>
                <button
                  onClick={() => handleCopy('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'hash')}
                  style={{ background: 'transparent', border: 'none', color: copiedKey === 'hash' ? '#10b981' : 'var(--text-muted)', cursor: 'pointer' }}
                >
                  {copiedKey === 'hash' ? <CheckCircle2 size={13} /> : <Copy size={13} />}
                </button>
              </div>

              {/* Endpoint */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 10px', background: 'var(--bg-deep)', borderRadius: 6 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Shield size={14} color="#38bdf8" />
                  <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Target Host:</span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: '#fff' }}>DESKTOP-GJ53HIT (AGT-A9334B63)</span>
                </div>
                <span className="badge-pill" style={{ background: 'rgba(16,185,129,0.15)', color: '#10b981' }}>Online</span>
              </div>

              {/* User Account */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 10px', background: 'var(--bg-deep)', borderRadius: 6 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <User size={14} color="#a855f7" />
                  <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>User Account:</span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: '#fff' }}>NT AUTHORITY\SYSTEM (Elevated)</span>
                </div>
                <span className="badge-pill" style={{ background: 'rgba(239,68,68,0.15)', color: '#ef4444' }}>Privileged</span>
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: Vertical Timeline matching Screen 3 */}
        <div className="tp-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <h3 style={{ fontSize: 13, fontWeight: 600, color: '#f1f5f9' }}>
              Incident Timeline & Kill-Chain Progression
            </h3>
            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>5 Correlated Events</span>
          </div>

          <div style={{ position: 'relative', paddingLeft: 24 }}>
            {/* Timeline track line */}
            <div style={{ position: 'absolute', top: 8, bottom: 8, left: 7, width: 2, background: 'var(--border-dim)' }} />

            {/* Timeline Step 1 */}
            <div style={{ position: 'relative', marginBottom: 20 }}>
              <div style={{ position: 'absolute', left: -24, top: 2, width: 14, height: 14, borderRadius: '50%', background: '#ef4444', border: '3px solid var(--bg-card)' }} />
              <div style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: '#ef4444', marginBottom: 2 }}>
                14:25:12 UTC • Initial Execution
              </div>
              <div style={{ fontSize: 12, fontWeight: 600, color: '#fff' }}>
                Encoded PowerShell Execution Triggered
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>
                Command spawned with <code style={{ color: '#fca5a5' }}>-WindowStyle Hidden -EncodedCommand SQBFAFgA...</code>
              </div>
            </div>

            {/* Timeline Step 2 */}
            <div style={{ position: 'relative', marginBottom: 20 }}>
              <div style={{ position: 'absolute', left: -24, top: 2, width: 14, height: 14, borderRadius: '50%', background: '#f97316', border: '3px solid var(--bg-card)' }} />
              <div style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: '#f97316', marginBottom: 2 }}>
                14:26:01 UTC • Command & Control
              </div>
              <div style={{ fontSize: 12, fontWeight: 600, color: '#fff' }}>
                C2 Network Beacon Established
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>
                Outbound TLS handshake completed to 185.199.110.5:443 with 35s beacon interval.
              </div>
            </div>

            {/* Timeline Step 3 */}
            <div style={{ position: 'relative', marginBottom: 20 }}>
              <div style={{ position: 'absolute', left: -24, top: 2, width: 14, height: 14, borderRadius: '50%', background: '#eab308', border: '3px solid var(--bg-card)' }} />
              <div style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: '#eab308', marginBottom: 2 }}>
                14:28:44 UTC • Persistence
              </div>
              <div style={{ fontSize: 12, fontWeight: 600, color: '#fff' }}>
                Scheduled Task Registered
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>
                Task <code style={{ color: '#fef08a' }}>\SystemHealthCheck</code> registered to execute cmd.exe upon logon.
              </div>
            </div>

            {/* Timeline Step 4 */}
            <div style={{ position: 'relative', marginBottom: 20 }}>
              <div style={{ position: 'absolute', left: -24, top: 2, width: 14, height: 14, borderRadius: '50%', background: '#a855f7', border: '3px solid var(--bg-card)' }} />
              <div style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: '#a855f7', marginBottom: 2 }}>
                14:31:10 UTC • Defense Evasion
              </div>
              <div style={{ fontSize: 12, fontWeight: 600, color: '#fff' }}>
                Event Log Clearing Attempt
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>
                Wevtutil executed to clear Microsoft-Windows-PowerShell/Operational event log channel.
              </div>
            </div>

            {/* Timeline Step 5 */}
            <div style={{ position: 'relative' }}>
              <div style={{ position: 'absolute', left: -24, top: 2, width: 14, height: 14, borderRadius: '50%', background: '#10b981', border: '3px solid var(--bg-card)' }} />
              <div style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: '#10b981', marginBottom: 2 }}>
                14:32:00 UTC • ThreatPoint AI Autonomous Response
              </div>
              <div style={{ fontSize: 12, fontWeight: 600, color: '#fff' }}>
                Automated Incident Correlation & Escalation
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>
                Multi-stage correlations converged; threat confidence scored at 98.4%. Recommended host isolation queued.
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
