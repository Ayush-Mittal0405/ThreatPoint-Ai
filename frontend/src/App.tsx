import { useState, useEffect, useRef } from 'react'
import { Routes, Route, NavLink, useLocation, Navigate } from 'react-router-dom'
import {
  Shield, AlertTriangle, Activity, Search,
  Target, BarChart2, Radio, Server, MonitorSmartphone,
  Home, Sparkles, Crosshair, Zap, Settings, ChevronLeft, ChevronRight, Plus
} from 'lucide-react'

// ── Screen Views (7 Reference Screens from uploaded image) ───────────────
import DashboardView from './pages/DashboardView'          // Screen 1: Main Dashboard (Overview)
import AlertsView from './pages/AlertsView'                // Screen 2: Alerts Management
import IncidentDetailsView from './pages/IncidentDetailsView' // Screen 3: Incident Details
import InvestigationsView from './pages/InvestigationsView' // Screen 4: Investigations & AI Assistant
import ThreatIntelView from './pages/ThreatIntelView'      // Screen 5: Threat Intelligence
import AssetsView from './pages/AssetsView'                // Screen 6: Assets & Endpoints Fleet
import ReportsView from './pages/ReportsView'              // Screen 7: Reports & Analytics

// ── Left Rail Separate Views ─────────────────────────────────────────────
import HomeView from './pages/HomeView'                    // Left Rail: Home (Enterprise SOC Posture)
import EndpointsPage from './pages/Endpoints'              // Left Rail: Endpoint (Live Agent Telemetry)
import ModelsPage from './pages/Models'                    // Left Rail: Model Evaluation
import HuntingPage from './pages/Hunting'                  // Left Rail: Threat Hunting
import ResponsePage from './pages/Response'                // Left Rail: Response Center
import SettingsView from './pages/SettingsView'            // Left Rail: Settings (Bottom)

import GlobalSearch from './components/GlobalSearch'
import { useToast } from './components/Toast'
import { usePolling } from './hooks/usePolling'
import { api, Alert } from './services/api'

export default function App() {
  const [searchOpen, setSearchOpen] = useState(false)
  const knownAlertIds = useRef<Set<string>>(new Set())
  const toast = useToast()
  const location = useLocation()

  // Shortcut listener for Ctrl+K / Cmd+K
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && (e.key === 'k' || e.key === 'K')) {
        e.preventDefault()
        setSearchOpen(prev => !prev)
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [])

  // Live alert notification polling (every 2s)
  usePolling(async () => {
    try {
      const openAlerts = await api.getAlerts('open')
      if (knownAlertIds.current.size === 0) {
        openAlerts.forEach(a => knownAlertIds.current.add(a.id))
        return
      }

      for (const alert of openAlerts) {
        if (!knownAlertIds.current.has(alert.id)) {
          knownAlertIds.current.add(alert.id)
          if (alert.severity === 'critical') {
            toast.error(`🚨 Critical Alert: ${alert.title}`)
          } else if (alert.severity === 'high') {
            toast.warn(`⚠️ High Alert: ${alert.title}`)
          } else {
            toast.info(`⚡ Alert Detected: ${alert.title}`)
          }
        }
      }
    } catch {
      // Backend polling safe fail
    }
  }, 2_000)

  return (
    <div className="threatpoint-shell">
      {/* ── Top Bar with horizontal navigation matching reference ───────────── */}
      <header className="threatpoint-topbar">
        {/* Brand */}
        <NavLink to="/dashboard" className="brand-badge" title="ThreatPoint Ai">
          <div className="brand-icon-box">
            <Shield size={16} color="#ffffff" />
          </div>
          <span className="brand-title">
            ThreatPoint <span className="accent">Ai</span>
          </span>
        </NavLink>

        {/* Tab Pagination Buttons */}
        <button
          style={{
            background: 'transparent',
            border: 'none',
            color: 'var(--text-muted)',
            cursor: 'pointer',
            padding: 4,
            display: 'flex',
            alignItems: 'center'
          }}
          title="Scroll Left"
        >
          <ChevronLeft size={16} />
        </button>

        {/* Top Horizontal Navigation Tabs (The 7 Screens from the reference image) */}
        <nav className="top-nav-tabs">
          <NavLink
            to="/dashboard"
            className={({ isActive }) => `top-nav-tab${isActive ? ' active' : ''}`}
          >
            Dashboard
          </NavLink>
          <NavLink
            to="/alerts-view"
            className={({ isActive }) => `top-nav-tab${isActive ? ' active' : ''}`}
          >
            Alerts
          </NavLink>
          <NavLink
            to="/incident-details"
            className={({ isActive }) => `top-nav-tab${isActive ? ' active' : ''}`}
          >
            Incident Details
          </NavLink>
          <NavLink
            to="/investigations-view"
            className={({ isActive }) => `top-nav-tab${isActive ? ' active' : ''}`}
          >
            Investigations
          </NavLink>
          <NavLink
            to="/threat-intel"
            className={({ isActive }) => `top-nav-tab${isActive ? ' active' : ''}`}
          >
            Threat Intel
          </NavLink>
          <NavLink
            to="/assets-view"
            className={({ isActive }) => `top-nav-tab${isActive ? ' active' : ''}`}
          >
            Assets
          </NavLink>
          <NavLink
            to="/reports-view"
            className={({ isActive }) => `top-nav-tab${isActive ? ' active' : ''}`}
          >
            Reports
          </NavLink>
        </nav>

        <button
          style={{
            background: 'transparent',
            border: 'none',
            color: 'var(--text-muted)',
            cursor: 'pointer',
            padding: 4,
            display: 'flex',
            alignItems: 'center'
          }}
          title="Scroll Right"
        >
          <ChevronRight size={16} />
        </button>

        <button
          style={{
            background: 'transparent',
            border: 'none',
            color: 'var(--text-muted)',
            cursor: 'pointer',
            padding: 4,
            display: 'flex',
            alignItems: 'center',
            fontSize: 14
          }}
          title="New View"
        >
          <Plus size={16} />
        </button>

        <div style={{ flex: 1 }} />

        {/* Global Search Trigger (Ctrl+K) */}
        <button
          onClick={() => setSearchOpen(true)}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            background: 'var(--bg-surface)',
            border: '1px solid var(--border-dim)',
            borderRadius: 'var(--radius-md)',
            padding: '5px 12px',
            color: 'var(--text-secondary)',
            fontSize: 12,
            cursor: 'pointer',
          }}
        >
          <Search size={13} color="var(--text-muted)" />
          <kbd
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 10,
              background: 'var(--bg-raised)',
              border: '1px solid var(--border-dim)',
              padding: '1px 5px',
              borderRadius: 3,
              color: 'var(--text-muted)',
            }}
          >
            Ctrl+K
          </kbd>
        </button>

        {/* Global Threat Level Pill */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: 6,
          background: 'rgba(239, 68, 68, 0.15)',
          border: '1px solid #ef4444',
          borderRadius: 99,
          padding: '4px 10px',
          color: '#ef4444',
          fontSize: 11,
          fontWeight: 700,
          letterSpacing: '0.5px'
        }}>
          <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#ef4444' }} />
          HIGH
        </div>
      </header>

      {/* ── Left Slide Bar (Mini-Rail) ────────────────────────────────────── */}
      {/* Buttons navigate to separate web pages than the top horizontal tabs */}
      <aside className="threatpoint-rail">
        {/* Top Operations Group */}
        <div className="rail-group">
          {/* 1. Home Button (Enterprise SOC Posture) */}
          <NavLink
            to="/"
            end
            className={({ isActive }) => `rail-btn${isActive ? ' active' : ''}`}
            title="Home • Enterprise SOC Posture"
          >
            <Home size={18} />
          </NavLink>

          {/* 2. Endpoint Button (Live Agent Telemetry & Fleet Inspector) */}
          <NavLink
            to="/endpoints"
            className={({ isActive }) => `rail-btn${isActive ? ' active' : ''}`}
            title="Endpoint • Live Telemetry & Inspector"
          >
            <Server size={18} />
          </NavLink>

          {/* 3. AI Assistant Button (Shows the same UI as Investigation Tab) */}
          <NavLink
            to="/ai-assistant"
            className={({ isActive }) => `rail-btn${isActive ? ' active' : ''}`}
            title="ThreatPoint AI Assistant (Investigations)"
          >
            <Sparkles size={18} />
          </NavLink>

          {/* 4. Model Evaluation Button */}
          <NavLink
            to="/model-eval"
            className={({ isActive }) => `rail-btn${isActive ? ' active' : ''}`}
            title="Model Evaluation • Precision & Hallucination Metrics"
          >
            <BarChart2 size={18} />
          </NavLink>

          {/* 5. Threat Hunting Button */}
          <NavLink
            to="/hunting"
            className={({ isActive }) => `rail-btn${isActive ? ' active' : ''}`}
            title="Autonomous Threat Hunting"
          >
            <Crosshair size={18} />
          </NavLink>

          {/* 6. Response Center Button */}
          <NavLink
            to="/response"
            className={({ isActive }) => `rail-btn${isActive ? ' active' : ''}`}
            title="Response Center • Quarantine & Containment"
          >
            <Zap size={18} />
          </NavLink>
        </div>

        {/* Bottom Group */}
        <div className="rail-group">
          {/* Quick Search */}
          <button
            className="rail-btn"
            onClick={() => setSearchOpen(true)}
            title="Quick Search (Ctrl+K)"
          >
            <Search size={18} />
          </button>

          {/* 7. Settings Button at Bottom */}
          <NavLink
            to="/settings"
            className={({ isActive }) => `rail-btn${isActive ? ' active' : ''}`}
            title="Platform Settings & Certificates"
          >
            <Settings size={18} />
          </NavLink>

          {/* Analyst Avatar */}
          <div className="rail-avatar" title="Lead SOC Analyst (Online)">
            TP
          </div>
        </div>
      </aside>

      {/* ── Main Viewport ─────────────────────────────────────────────────── */}
      <main className="threatpoint-viewport">
        <Routes>
          {/* Left Rail Routes */}
          <Route path="/"                   element={<HomeView />} />
          <Route path="/endpoints"          element={<EndpointsPage />} />
          <Route path="/ai-assistant"       element={<InvestigationsView />} />
          <Route path="/model-eval"         element={<ModelsPage />} />
          <Route path="/hunting"            element={<HuntingPage />} />
          <Route path="/response"           element={<ResponsePage />} />
          <Route path="/settings"           element={<SettingsView />} />

          {/* Top Tabs Routes (The 7 Screens from the reference image) */}
          <Route path="/dashboard"          element={<DashboardView />} />
          <Route path="/alerts-view"        element={<AlertsView />} />
          <Route path="/incident-details"   element={<IncidentDetailsView />} />
          <Route path="/investigations-view" element={<InvestigationsView />} />
          <Route path="/threat-intel"       element={<ThreatIntelView />} />
          <Route path="/assets-view"        element={<AssetsView />} />
          <Route path="/reports-view"       element={<ReportsView />} />

          {/* Legacy & Direct URL Aliases */}
          <Route path="/alerts"             element={<Navigate to="/alerts-view" replace />} />
          <Route path="/incidents"          element={<Navigate to="/incident-details" replace />} />
          <Route path="/models"             element={<Navigate to="/model-eval" replace />} />
          <Route path="/home"               element={<Navigate to="/" replace />} />
          <Route path="*"                   element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </main>

      {/* Global Command Palette */}
      <GlobalSearch isOpen={searchOpen} onClose={() => setSearchOpen(false)} />
    </div>
  )
}
