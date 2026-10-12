import { useState } from 'react'
import {
  Sparkles, Search, Shield, AlertTriangle, ArrowRight,
  CheckCircle2, Bot, Terminal, Zap, ShieldAlert, FileText, Send,
  Cpu, ExternalLink
} from 'lucide-react'

interface InvestigationItem {
  id: string
  title: string
  host: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  time: string
  status: string
  summary: string
  confidence: number
  techniques: string[]
}

const INVESTIGATIONS: InvestigationItem[] = [
  {
    id: 'INV-8921',
    title: 'C2 Beaconing & Encoded Execution',
    host: 'DESKTOP-GJ53HIT',
    severity: 'critical',
    time: 'Just now',
    status: 'Active',
    summary: 'ThreatPoint AI correlated 5 alerts across process creation, network telemetry, and registry persistence. The attack chain exhibits characteristics consistent with Cobalt Strike / Sliver C2 staging. An encoded PowerShell payload was invoked to spawn an unmanaged memory inject that established beacon intervals of 30-45s against 185.199.110.5.',
    confidence: 85,
    techniques: [
      'T1059.001 Command & Scripting Interpreter',
      'T1071.001 Application Layer Protocol',
      'T1053.005 Scheduled Task',
      'T1027 Obfuscated Files or Information'
    ]
  },
  {
    id: 'INV-8920',
    title: 'Ransomware Canary File Modification',
    host: 'FILE-SRV-02',
    severity: 'high',
    time: '12m ago',
    status: 'Triaged',
    summary: 'Automated tripwire alert triggered in shared backup volume. Unusual burst of 1,200 file renames detected in 4 seconds matching LockBit 3.0 extension schema.',
    confidence: 92,
    techniques: [
      'T1486 Data Encrypted for Impact',
      'T1490 Inhibit System Recovery'
    ]
  },
  {
    id: 'INV-8919',
    title: 'Credential Dumping via LSASS',
    host: 'DC-BACKUP-01',
    severity: 'critical',
    time: '45m ago',
    status: 'Resolved',
    summary: 'Procdump utility executed against lsass.exe process space with debug privileges. Memory dump writing blocked by ThreatPoint AI agent kernel hook.',
    confidence: 96,
    techniques: [
      'T1003.001 LSASS Memory',
      'T1078 Valid Accounts'
    ]
  },
  {
    id: 'INV-8918',
    title: 'Lateral Movement via WinRM / WMI',
    host: 'FIN-WORKSTATION-08',
    severity: 'medium',
    time: '2h ago',
    status: 'Resolved',
    summary: 'Remote process execution invoked via WMI Win32_Process class across internal subnet 10.0.1.0/24 using compromised service account credentials.',
    confidence: 78,
    techniques: [
      'T1047 Windows Management Instrumentation',
      'T1021.002 SMB/Windows Admin Shares'
    ]
  },
  {
    id: 'INV-8917',
    title: 'Suspicious DNS Tunneling Query Burst',
    host: 'CORP-GATEWAY',
    severity: 'high',
    time: '4h ago',
    status: 'Closed',
    summary: 'High entropy subdomain resolution detected (250+ queries per second) querying synthetic base32 encoded domains under ns1.dyn-traffic.net.',
    confidence: 88,
    techniques: [
      'T1071.004 DNS C2 Channel',
      'T1048 Exfiltration Over Alternative Protocol'
    ]
  }
]

export default function InvestigationsView() {
  const [selectedId, setSelectedId] = useState('INV-8921')
  const [prompt, setPrompt] = useState('Investigate beaconing behavior and persistence mechanisms on DESKTOP-GJ53HIT...')
  const [analyzing, setAnalyzing] = useState(false)
  const [search, setSearch] = useState('')
  const [actionFeedback, setActionFeedback] = useState<string | null>(null)

  const selected = INVESTIGATIONS.find(i => i.id === selectedId) || INVESTIGATIONS[0]

  const handleRunAnalysis = () => {
    setAnalyzing(true)
    setTimeout(() => {
      setAnalyzing(false)
      setActionFeedback('ThreatPoint AI refreshed neural hypothesis with +4% confidence.')
      setTimeout(() => setActionFeedback(null), 3000)
    }, 1200)
  }

  const handleAction = (name: string) => {
    setActionFeedback(`Executed: ${name}`)
    setTimeout(() => setActionFeedback(null), 3000)
  }

  const filtered = INVESTIGATIONS.filter(i =>
    i.title.toLowerCase().includes(search.toLowerCase()) ||
    i.id.toLowerCase().includes(search.toLowerCase()) ||
    i.host.toLowerCase().includes(search.toLowerCase())
  )

  return (
    <div className="page-container">
      {/* ── Page Header ────────────────────────────────────────────── */}
      <div className="tp-page-header">
        <div>
          <h1 className="tp-page-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span>ThreatPoint AI Autonomous Investigations</span>
            <span style={{
              background: 'linear-gradient(135deg, #ec4899 0%, #a855f7 100%)',
              color: '#fff',
              fontSize: 10,
              fontWeight: 700,
              padding: '2px 8px',
              borderRadius: 4,
              textTransform: 'uppercase',
              letterSpacing: '0.5px'
            }}>
              Neural Co-Pilot
            </span>
          </h1>
          <p className="tp-page-subtitle">Autonomous hypothesis testing, root cause correlation, and guided remediation</p>
        </div>
      </div>

      {/* ── Main Two Panel Grid matching Screen 4 ──────────────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: '360px 1fr', gap: 18 }}>
        {/* Left Column: Recent Investigations List */}
        <div className="tp-card" style={{ padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: 13, fontWeight: 600, color: '#f1f5f9' }}>Recent Investigations</span>
            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{INVESTIGATIONS.length} cases</span>
          </div>

          {/* Search */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, background: 'var(--bg-deep)', border: '1px solid var(--border-dim)', borderRadius: 6, padding: '6px 10px' }}>
            <Search size={13} color="var(--text-muted)" />
            <input
              type="text"
              placeholder="Filter cases..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              style={{ background: 'transparent', border: 'none', outline: 'none', color: '#fff', fontSize: 12, width: '100%' }}
            />
          </div>

          {/* List items */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, maxHeight: 'calc(100vh - 240px)', overflowY: 'auto' }}>
            {filtered.map(item => {
              const isSelected = item.id === selectedId
              return (
                <div
                  key={item.id}
                  onClick={() => setSelectedId(item.id)}
                  style={{
                    padding: '12px 14px',
                    borderRadius: 6,
                    cursor: 'pointer',
                    background: isSelected ? 'var(--bg-raised)' : 'var(--bg-deep)',
                    border: isSelected ? '1px solid var(--magenta)' : '1px solid var(--border-subtle)',
                    transition: 'all 0.15s ease'
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 600, color: isSelected ? 'var(--magenta)' : '#94a3b8' }}>
                      {item.id}
                    </span>
                    <span className={`badge-pill badge-${item.severity}`} style={{ fontSize: 10, padding: '1px 6px' }}>
                      {item.severity.toUpperCase()}
                    </span>
                  </div>

                  <div style={{ fontSize: 12, fontWeight: 600, color: '#fff', marginBottom: 4, textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }}>
                    {item.title}
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: 'var(--text-muted)' }}>
                    <span>{item.host}</span>
                    <span>{item.time}</span>
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        {/* Right Main Column: AI Assistant & Analysis Result matching Screen 4 */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {/* Query Prompt Input Bar */}
          <div className="tp-card" style={{ padding: '14px 18px', background: 'var(--bg-card)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
              <Bot size={16} color="var(--magenta)" />
              <span style={{ fontSize: 12, fontWeight: 600, color: '#fff' }}>ThreatPoint AI Analyst Prompt</span>
            </div>

            <div style={{ display: 'flex', gap: 10 }}>
              <input
                type="text"
                value={prompt}
                onChange={e => setPrompt(e.target.value)}
                style={{
                  flex: 1,
                  background: 'var(--bg-deep)',
                  border: '1px solid var(--border-dim)',
                  borderRadius: 6,
                  padding: '9px 14px',
                  color: '#fff',
                  fontSize: 12,
                  outline: 'none',
                }}
              />
              <button
                onClick={handleRunAnalysis}
                disabled={analyzing}
                style={{
                  background: 'var(--magenta)',
                  color: '#fff',
                  border: 'none',
                  borderRadius: 6,
                  padding: '0 16px',
                  fontSize: 12,
                  fontWeight: 600,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6,
                  boxShadow: '0 0 10px var(--magenta-glow)',
                  whiteSpace: 'nowrap'
                }}
              >
                <Sparkles size={13} className={analyzing ? 'spin' : ''} />
                <span>{analyzing ? 'Analyzing...' : 'Run AI Analysis'}</span>
              </button>
            </div>

            {actionFeedback && (
              <div style={{ marginTop: 10, fontSize: 11, color: '#10b981', display: 'flex', alignItems: 'center', gap: 6 }}>
                <CheckCircle2 size={13} />
                <span>{actionFeedback}</span>
              </div>
            )}
          </div>

          {/* Analysis Result Card matching Screen 4 */}
          <div className="tp-card" style={{ padding: '20px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14, flexWrap: 'wrap', gap: 8 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <Sparkles size={18} color="var(--magenta)" />
                <h3 style={{ fontSize: 14, fontWeight: 700, color: '#fff', margin: 0 }}>
                  ThreatPoint AI Analysis Result
                </h3>
              </div>

              {/* Confidence badge */}
              <div style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 6,
                background: 'rgba(236,72,153,0.15)',
                border: '1px solid var(--magenta)',
                color: '#fff',
                fontSize: 11,
                fontWeight: 600,
                padding: '3px 10px',
                borderRadius: 99,
              }}>
                <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--magenta)' }} />
                <span>{selected.confidence}% Confidence</span>
              </div>
            </div>

            {/* Root Cause & Reasoning */}
            <div style={{ marginBottom: 18 }}>
              <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 6 }}>
                Root Cause & Threat Behavior Assessment
              </div>
              <p style={{ fontSize: 13, lineHeight: 1.6, color: 'var(--text-secondary)' }}>
                {selected.summary}
              </p>
            </div>

            {/* MITRE ATT&CK Matrix Alignment */}
            <div style={{ marginBottom: 20 }}>
              <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 8 }}>
                Observed MITRE ATT&CK Techniques
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                {selected.techniques.map((tech, idx) => (
                  <span
                    key={idx}
                    style={{
                      background: 'var(--bg-deep)',
                      border: '1px solid var(--border-dim)',
                      borderRadius: 4,
                      padding: '4px 10px',
                      fontSize: 11,
                      fontFamily: 'var(--font-mono)',
                      color: '#cbd5e1',
                    }}
                  >
                    {tech}
                  </span>
                ))}
              </div>
            </div>

            {/* Recommended Containment Actions */}
            <div style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: 16 }}>
              <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 10 }}>
                Automated Containment & Recommended Next Steps
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 10 }}>
                <button
                  onClick={() => handleAction(`Isolated host ${selected.host}`)}
                  style={{
                    background: 'rgba(239,68,68,0.15)',
                    border: '1px solid #ef4444',
                    color: '#f87171',
                    padding: '8px 12px',
                    borderRadius: 6,
                    fontSize: 11,
                    fontWeight: 600,
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: 6
                  }}
                >
                  <Zap size={13} />
                  <span>Isolate Host {selected.host}</span>
                </button>

                <button
                  onClick={() => handleAction('Pushed firewall block rule for C2 IP 185.199.110.5')}
                  style={{
                    background: 'var(--bg-deep)',
                    border: '1px solid var(--border-dim)',
                    color: '#fff',
                    padding: '8px 12px',
                    borderRadius: 6,
                    fontSize: 11,
                    fontWeight: 500,
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: 6
                  }}
                >
                  <Shield size={13} color="#f97316" />
                  <span>Block C2 IP 185.199.110.5</span>
                </button>

                <button
                  onClick={() => handleAction('Terminated powershell.exe process tree')}
                  style={{
                    background: 'var(--bg-deep)',
                    border: '1px solid var(--border-dim)',
                    color: '#fff',
                    padding: '8px 12px',
                    borderRadius: 6,
                    fontSize: 11,
                    fontWeight: 500,
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: 6
                  }}
                >
                  <Terminal size={13} color="#eab308" />
                  <span>Kill Process Tree (PID 4812)</span>
                </button>

                <button
                  onClick={() => handleAction('Exported STIX 2.1 IOC Bundle')}
                  style={{
                    background: 'var(--bg-deep)',
                    border: '1px solid var(--border-dim)',
                    color: '#fff',
                    padding: '8px 12px',
                    borderRadius: 6,
                    fontSize: 11,
                    fontWeight: 500,
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: 6
                  }}
                >
                  <FileText size={13} color="#38bdf8" />
                  <span>Export STIX 2.1 Package</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
