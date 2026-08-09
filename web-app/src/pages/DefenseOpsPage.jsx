import { useState, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Radio, ShieldAlert, Activity, FileText, Users, Eye, AlertTriangle,
  CheckCircle, XCircle, Wifi, WifiOff, Lock, Unlock, RefreshCw, ChevronDown, ChevronUp
} from 'lucide-react'
import defenceService, { ROLES, ATTACK_SIGNATURES } from '../services/defense.service'
import useStore from '../store/useStore'

// ── colour helpers ──────────────────────────────────────────────────────────
const severityColor = (s) => ({
  critical: 'text-red-400 bg-red-900/20 border-red-500/30',
  high:     'text-orange-400 bg-orange-900/20 border-orange-500/30',
  medium:   'text-yellow-400 bg-yellow-900/20 border-yellow-500/30',
  low:      'text-blue-400 bg-blue-900/20 border-blue-500/30',
  info:     'text-cyan-400 bg-cyan-900/20 border-cyan-500/30',
}[s] ?? 'text-gray-400 bg-gray-900/20 border-gray-500/30')

const statusColor = (s) => ({
  nominal:     'text-green-400',
  degraded:    'text-yellow-400',
  impaired:    'text-orange-400',
  critical:    'text-red-400',
  clean:       'text-green-400',
  suspicious:  'text-yellow-400',
  threat:      'text-orange-400',
  attack:      'text-red-400',
  normal:      'text-green-400',
  anomalous:   'text-orange-400',
  insufficient_data: 'text-gray-400',
}[s] ?? 'text-gray-400')

const statusDot = (s) => ({
  nominal: 'bg-green-400', degraded: 'bg-yellow-400', impaired: 'bg-orange-400', critical: 'bg-red-400',
  clean: 'bg-green-400', suspicious: 'bg-yellow-400', threat: 'bg-orange-400', attack: 'bg-red-500 animate-pulse',
}[s] ?? 'bg-gray-400')

function SectionHeader({ icon: Icon, title, subtitle, badge }) {
  return (
    <div className="flex items-center justify-between mb-4">
      <div className="flex items-center gap-2">
        <Icon className="w-4 h-4 text-cyphra-accent" strokeWidth={1.5} />
        <div>
          <h2 className="text-sm font-semibold text-cyphra-text-primary">{title}</h2>
          {subtitle && <p className="text-[11px] text-cyphra-text-muted">{subtitle}</p>}
        </div>
      </div>
      {badge && <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${severityColor(badge)}`}>{badge.toUpperCase()}</span>}
    </div>
  )
}

// ── 1. Signal Health Panel ──────────────────────────────────────────────────
function SignalHealthPanel({ latest }) {
  const sig = latest?.signal
  const raw = latest?.raw
  if (!sig) return (
    <div className="flex items-center justify-center h-32 text-cyphra-text-muted text-xs">
      <RefreshCw className="w-4 h-4 animate-spin mr-2" /> Awaiting real signal data…
    </div>
  )

  const metrics = [
    { label: 'SNR',          value: `${sig.raw.snr_db} dB`,        ok: sig.raw.snr_db >= 10 },
    { label: 'Latency',      value: `${sig.raw.latency_ms} ms`,     ok: sig.raw.latency_ms <= 250 },
    { label: 'Jitter',       value: `${sig.raw.jitter_ms} ms`,      ok: sig.raw.jitter_ms <= 30 },
    { label: 'Packet Loss',  value: `${sig.raw.packet_loss_pct}%`,  ok: sig.raw.packet_loss_pct <= 2 },
  ]

  return (
    <div>
      <div className="flex items-center gap-2 mb-4">
        <div className={`w-2 h-2 rounded-full ${statusDot(sig.status)}`} />
        <span className={`text-sm font-semibold font-mono uppercase ${statusColor(sig.status)}`}>{sig.status}</span>
        <span className="text-[11px] text-cyphra-text-muted ml-auto">
          {raw?.ssid ? `📶 ${raw.ssid}` : sig.source_id}
          {raw?.channel ? ` · ch${raw.channel}` : ''}
        </span>
        {latest?.real && (
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-green-900/30 text-green-400 border border-green-500/20 font-mono">LIVE</span>
        )}
      </div>
      <div className="grid grid-cols-2 gap-2 mb-3">
        {metrics.map(m => (
          <div key={m.label} className="px-3 py-2 bg-cyphra-bg rounded border border-cyphra-border flex items-center justify-between">
            <span className="text-[11px] text-cyphra-text-muted">{m.label}</span>
            <div className="flex items-center gap-1.5">
              <span className="text-xs font-mono font-semibold text-cyphra-text-primary">{m.value}</span>
              {m.ok
                ? <CheckCircle className="w-3 h-3 text-green-400" strokeWidth={2} />
                : <XCircle    className="w-3 h-3 text-red-400"   strokeWidth={2} />}
            </div>
          </div>
        ))}
      </div>

      {/* Real metadata row */}
      {raw && (
        <div className="mb-3 px-3 py-2 rounded bg-cyphra-bg border border-cyphra-border">
          <div className="grid grid-cols-2 gap-x-4 gap-y-1">
            {raw.signal_pct != null && (
              <div className="flex justify-between text-[11px]">
                <span className="text-cyphra-text-muted">Signal</span>
                <span className="font-mono text-cyphra-text-primary">{raw.signal_pct}%</span>
              </div>
            )}
            {raw.signal_dbm != null && (
              <div className="flex justify-between text-[11px]">
                <span className="text-cyphra-text-muted">RSSI</span>
                <span className="font-mono text-cyphra-text-primary">{raw.signal_dbm} dBm</span>
              </div>
            )}
            {raw.gateway && (
              <div className="flex justify-between text-[11px]">
                <span className="text-cyphra-text-muted">Gateway</span>
                <span className="font-mono text-cyphra-text-primary">{raw.gateway}</span>
              </div>
            )}
            {raw.bssid && raw.bssid !== '?' && (
              <div className="flex justify-between text-[11px]">
                <span className="text-cyphra-text-muted">BSSID</span>
                <span className="font-mono text-cyphra-text-primary text-[10px]">{raw.bssid}</span>
              </div>
            )}
            {raw.ping_samples?.length > 0 && (
              <div className="flex justify-between text-[11px] col-span-2">
                <span className="text-cyphra-text-muted">Ping RTTs</span>
                <span className="font-mono text-cyphra-text-primary">{raw.ping_samples.join('ms, ')}ms</span>
              </div>
            )}
            {raw.bandwidth_mbps != null && (
              <div className="flex justify-between text-[11px]">
                <span className="text-cyphra-text-muted">NIC BW</span>
                <span className="font-mono text-cyphra-text-primary">{raw.bandwidth_mbps} Mbps</span>
              </div>
            )}
            {raw.active_flows != null && (
              <div className="flex justify-between text-[11px]">
                <span className="text-cyphra-text-muted">Active Flows</span>
                <span className="font-mono text-cyphra-text-primary">{raw.active_flows}</span>
              </div>
            )}
          </div>
        </div>
      )}

      {sig.issues.length > 0 && (
        <div className="space-y-1">
          {sig.issues.map((iss, i) => (
            <p key={i} className="text-[11px] text-orange-400 flex items-center gap-1.5">
              <AlertTriangle className="w-3 h-3 shrink-0" /> {iss.msg}
            </p>
          ))}
        </div>
      )}
    </div>
  )
}

// ── 2. EW Threat Detection Panel ──────────────────────────────────────────
function EWThreatPanel({ latest, events }) {
  const thr = latest?.threat
  return (
    <div>
      {thr && (
        <div className={`mb-4 px-3 py-2.5 rounded border flex items-center justify-between ${severityColor(thr.severity)}`}>
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-wide opacity-70 mb-0.5">Current Threat</p>
            <p className="text-sm font-mono font-bold uppercase">{thr.classification}</p>
            <p className="text-[11px] opacity-70 mt-0.5">{thr.recommendation}</p>
          </div>
          <div className="text-right">
            <p className="text-xs font-mono font-bold">{(thr.score * 100).toFixed(1)}%</p>
            <p className="text-[10px] opacity-60">threat score</p>
          </div>
        </div>
      )}
      <p className="text-[11px] text-cyphra-text-muted font-semibold mb-2">Recent Events</p>
      <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
        {events.length === 0 && <p className="text-[11px] text-cyphra-text-muted">No threats detected yet.</p>}
        {events.map(evt => (
          <motion.div
            key={evt.id}
            initial={{ opacity: 0, x: -8 }}
            animate={{ opacity: 1, x: 0 }}
            className={`px-3 py-2 rounded border text-[11px] ${severityColor(evt.severity)}`}
          >
            <div className="flex items-center justify-between mb-0.5">
              <span className="font-semibold uppercase">{evt.classification}</span>
              <span className="font-mono opacity-60">{new Date(evt.timestamp).toLocaleTimeString()}</span>
            </div>
            {evt.signatures.length > 0 && (
              <p className="opacity-70">{evt.signatures.map(s => s.name).join(' · ')}</p>
            )}
            {evt.triggered.length > 0 && (
              <p className="opacity-50 mt-0.5">Indicators: {evt.triggered.join(', ')}</p>
            )}
          </motion.div>
        ))}
      </div>
    </div>
  )
}

// ── 3. Pattern Anomaly Panel ───────────────────────────────────────────────
function PatternAnomalyPanel({ history }) {
  // Use real flow completion timestamps from ML service when available.
  // Polling timestamps (every 6s exactly) would always flag as "beaconing"
  // because the CV of {6001ms, 5999ms, 6003ms} ≈ 0.0002 < 0.08 threshold.
  // Real flow timestamps are irregular (flows complete at random times).
  const latestRaw = history[history.length - 1]?.raw

  const events = history.map((h, i) => {
    // Prefer real flow timestamps if the backend gave us any
    const flowTs = latestRaw?.flow_timestamps
    const ts = (flowTs && flowTs[i] != null)
      ? flowTs[i]
      : (h.signal?.timestamp || Date.now())

    return {
      latency_ms:         h.signal?.raw?.latency_ms       || 0,
      // ✅ Real: average bytes per packet from ML service flow feed
      payload_size_bytes: h.raw?.bytes_per_pkt            || 256,
      timestamp:          ts,
    }
  })

  const result = history.length >= 3
    ? defenceService.detectPatternAnomalies(events)
    : null

  return (
    <div>
      {!result ? (
        <div className="text-[11px] text-cyphra-text-muted">Need ≥3 readings to analyse patterns…</div>
      ) : (
        <>
          <div className="flex items-center gap-2 mb-3">
            <div className={`w-2 h-2 rounded-full ${statusDot(result.verdict)}`} />
            <span className={`text-sm font-semibold font-mono uppercase ${statusColor(result.verdict)}`}>{result.verdict}</span>
            <span className="text-[11px] text-cyphra-text-muted ml-auto">{result.analysed} events analysed</span>
          </div>
          {result.anomalies.length === 0 ? (
            <p className="text-[11px] text-green-400 flex items-center gap-1.5">
              <CheckCircle className="w-3 h-3" /> No statistical anomalies detected in comm patterns
            </p>
          ) : (
            <div className="space-y-2">
              {result.anomalies.map((a, i) => (
                <div key={i} className="px-3 py-2 rounded border border-orange-500/30 bg-orange-900/10">
                  <p className="text-[11px] font-semibold text-orange-400">{a.type.replace(/_/g, ' ')}</p>
                  {a.type === 'LATENCY_SPIKE' && (
                    <p className="text-[10px] text-orange-300 opacity-70">
                      Mean: {a.detail.mean}ms · Std: {a.detail.std}ms · Outliers at indices: {a.detail.outliers.join(', ')}
                    </p>
                  )}
                  {a.type === 'BEACONING' && (
                    <p className="text-[10px] text-orange-300 opacity-70">
                      IAT CoV: {a.detail.cv} — highly regular timing detected (beaconing threshold &lt;0.08)
                    </p>
                  )}
                </div>
              ))}
            </div>
          )}
          <div className="mt-3 grid grid-cols-3 gap-2">
            {[['JAMMING-001','Const. Jamming'],['SPOOF-002','ID Spoofing'],['INTRUDE-003','Beaconing']].map(([id, label]) => {
              const active = result.anomalies.some(a => a.type === 'BEACONING' && id === 'INTRUDE-003')
              return (
                <div key={id} className={`px-2 py-1.5 rounded border text-center ${active ? 'border-orange-500/40 bg-orange-900/10' : 'border-cyphra-border'}`}>
                  <p className={`text-[10px] font-semibold ${active ? 'text-orange-400' : 'text-cyphra-text-muted'}`}>{label}</p>
                  <p className={`text-[9px] mt-0.5 ${active ? 'text-orange-300' : 'text-cyphra-text-muted'}`}>{active ? 'FLAGGED' : 'clear'}</p>
                </div>
              )
            })}
          </div>
        </>
      )}
    </div>
  )
}

// ── 4. Audit Log Panel ─────────────────────────────────────────────────────
function AuditLogPanel() {
  const [logs, setLogs] = useState([])
  const [integrity, setIntegrity] = useState(null)
  const [canView] = useState(defenceService.hasPermission('canViewLogs'))
  const [expanded, setExpanded] = useState(false)

  const refresh = useCallback(async () => {
    if (!canView) return
    try {
      const entries = defenceService.getAuditLog(50)
      setLogs(entries)
      const integ = await defenceService.verifyAuditIntegrity()
      setIntegrity(integ)
    } catch (e) {
      console.warn('Audit log read failed:', e.message)
    }
  }, [canView])

  useEffect(() => { refresh() }, [refresh])
  useEffect(() => {
    const id = setInterval(refresh, 5000)
    return () => clearInterval(id)
  }, [refresh])

  if (!canView) {
    return (
      <div className="flex flex-col items-center justify-center gap-2 py-6 text-cyphra-text-muted">
        <Lock className="w-6 h-6" />
        <p className="text-xs">Audit log access requires Analyst or higher role</p>
      </div>
    )
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-3">
        {integrity && (
          <div className={`flex items-center gap-1.5 text-[11px] ${integrity.intact ? 'text-green-400' : 'text-red-400'}`}>
            {integrity.intact ? <Lock className="w-3 h-3" /> : <Unlock className="w-3 h-3" />}
            Chain {integrity.intact ? 'INTACT' : 'TAMPERED'} · {integrity.entries} entries
          </div>
        )}
        <button onClick={refresh} className="text-[11px] text-cyphra-accent hover:underline ml-auto">
          Refresh
        </button>
      </div>
      <div className="max-h-56 overflow-y-auto space-y-1 pr-1">
        {logs.map(log => (
          <div key={log.seq} className={`px-2.5 py-1.5 rounded border text-[10px] font-mono ${severityColor(log.severity)}`}>
            <div className="flex justify-between mb-0.5">
              <span className="font-bold">[{log.seq}] {log.category}</span>
              <span className="opacity-50">{new Date(log.timestamp).toLocaleTimeString()}</span>
            </div>
            <p className="opacity-80">{log.message}</p>
            {expanded && <p className="opacity-30 mt-0.5 break-all">{log.hash.slice(0, 24)}…</p>}
          </div>
        ))}
        {logs.length === 0 && <p className="text-[11px] text-cyphra-text-muted">No audit events yet.</p>}
      </div>
      <button
        onClick={() => setExpanded(e => !e)}
        className="mt-2 text-[11px] text-cyphra-text-muted flex items-center gap-1 hover:text-cyphra-text-secondary"
      >
        {expanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
        {expanded ? 'Hide' : 'Show'} hash chains
      </button>
    </div>
  )
}

// ── 5. RBAC Panel ──────────────────────────────────────────────────────────
function RBACPanel() {
  const [role, setRole] = useState(defenceService.getRole())
  const roleKeys = Object.keys(ROLES)

  const handleChange = (key) => {
    defenceService.setRole(key)
    setRole(defenceService.getRole())
  }

  return (
    <div>
      <p className="text-[11px] text-cyphra-text-muted mb-3">
        Simulates role-based access control. Authentication context sets this automatically in production.
      </p>
      <div className="space-y-2">
        {roleKeys.map(key => {
          const r = ROLES[key]
          const isActive = role.key === key
          return (
            <button
              key={key}
              onClick={() => handleChange(key)}
              className={`w-full px-3 py-2.5 rounded border text-left transition-colors ${
                isActive
                  ? 'border-cyphra-accent/40 bg-cyphra-accent/10 text-cyphra-accent'
                  : 'border-cyphra-border text-cyphra-text-muted hover:border-cyphra-border/80'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold">{r.label}</span>
                <span className={`text-[10px] px-1.5 py-0.5 rounded ${isActive ? 'bg-cyphra-accent/20' : 'bg-cyphra-bg'}`}>
                  Level {r.level}
                </span>
              </div>
              <div className="mt-1 flex gap-2 flex-wrap">
                {r.canViewLogs    && <span className="text-[9px] text-green-400">● View Logs</span>}
                {r.canManageRoles && <span className="text-[9px] text-blue-400">● Manage Roles</span>}
                {r.canTriggerAlert && <span className="text-[9px] text-yellow-400">● Trigger Alerts</span>}
              </div>
            </button>
          )
        })}
      </div>
    </div>
  )
}

// ── Main Page ───────────────────────────────────────────────────────────────
export default function DefenseOpsPage() {
  const [latest, setLatest] = useState(null)
  const [history, setHistory] = useState([])
  const [events, setEvents] = useState([])
  const [activeTab, setActiveTab] = useState('signal')

  useEffect(() => {
    const stop = defenceService.startDefenceMonitoring((reading) => {
      setLatest(reading)
      setHistory(prev => [...prev.slice(-29), reading])
      setEvents(defenceService.getDetectedEvents(20))
    }, 4000)
    return stop
  }, [])

  const tabs = [
    { id: 'signal',   label: 'Signal',   icon: Wifi      },
    { id: 'ew',       label: 'EW Threat',icon: Radio     },
    { id: 'pattern',  label: 'Patterns', icon: Activity  },
    { id: 'audit',    label: 'Audit Log',icon: FileText  },
    { id: 'rbac',     label: 'Access',   icon: Users     },
  ]

  const threatBadge = latest?.threat?.classification !== 'clean' ? latest?.threat?.severity : undefined

  return (
    <div className="h-full overflow-y-auto p-5 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-base font-semibold text-cyphra-text-primary flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-cyphra-accent" strokeWidth={1.5} />
            Defence Operations Centre
          </h1>
          <p className="text-[11px] text-cyphra-text-muted mt-0.5">
            Jamming · Spoofing · Intrusion Detection · Signal Integrity · Secure Audit · RBAC
          </p>
        </div>
        <div className="flex items-center gap-2 px-2.5 py-1.5 rounded border border-green-500/20 bg-green-900/10">
          <div className="w-1.5 h-1.5 bg-green-400 rounded-full animate-pulse" />
          <span className="text-[11px] font-medium text-green-400">MONITORING ACTIVE</span>
        </div>
      </div>

      {/* Attack signature reference strip */}
      <div className="flex gap-2 overflow-x-auto pb-1">
        {ATTACK_SIGNATURES.slice(0, 6).map(sig => (
          <div key={sig.id} className={`shrink-0 px-2.5 py-1.5 rounded border text-[10px] ${severityColor(sig.severity)}`}>
            <p className="font-bold">{sig.id}</p>
            <p className="opacity-70 mt-0.5">{sig.name}</p>
          </div>
        ))}
      </div>

      {/* Tab bar */}
      <div className="flex gap-1 border-b border-cyphra-border pb-0">
        {tabs.map(tab => {
          const Icon = tab.icon
          const isActive = activeTab === tab.id
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-1.5 px-3 py-2 text-[11px] font-medium border-b-2 transition-colors -mb-px ${
                isActive
                  ? 'border-cyphra-accent text-cyphra-accent'
                  : 'border-transparent text-cyphra-text-muted hover:text-cyphra-text-secondary'
              }`}
            >
              <Icon className="w-3 h-3" strokeWidth={1.5} />
              {tab.label}
              {tab.id === 'ew' && events.length > 0 && (
                <span className="ml-1 text-[9px] bg-red-500 text-white rounded-full px-1.5 py-0.5 font-bold">
                  {events.length}
                </span>
              )}
            </button>
          )
        })}
      </div>

      {/* Tab content */}
      <AnimatePresence mode="wait">
        <motion.div
          key={activeTab}
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -6 }}
          transition={{ duration: 0.15 }}
          className="px-4 py-4 bg-cyphra-surface rounded border border-cyphra-border"
        >
          {activeTab === 'signal' && (
            <>
              <SectionHeader icon={Wifi} title="Signal Availability & Integrity" subtitle="Live telemetry from comm nodes" badge={latest?.signal?.status} />
              <SignalHealthPanel latest={latest} />
            </>
          )}
          {activeTab === 'ew' && (
            <>
              <SectionHeader icon={Radio} title="Electronic Warfare Threat Detection" subtitle="Jamming · Spoofing · Intrusion" badge={threatBadge} />
              <EWThreatPanel latest={latest} events={events} />
            </>
          )}
          {activeTab === 'pattern' && (
            <>
              <SectionHeader icon={Activity} title="Communication Pattern Anomaly Analysis" subtitle="Statistical analysis of comm metadata" />
              <PatternAnomalyPanel history={history} />
            </>
          )}
          {activeTab === 'audit' && (
            <>
              <SectionHeader icon={FileText} title="Secure Audit Log" subtitle="SHA-256 chained tamper-evident records" />
              <AuditLogPanel />
            </>
          )}
          {activeTab === 'rbac' && (
            <>
              <SectionHeader icon={Users} title="Role-Based Access Control" subtitle="Defence-grade security permissions" />
              <RBACPanel />
            </>
          )}
        </motion.div>
      </AnimatePresence>
    </div>
  )
}
