import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import { Shield, Activity, TrendingUp, AlertTriangle, CheckCircle, Zap, Eye, Database, Lock, Ban, ShieldOff, ShieldCheck } from 'lucide-react'
import useStore from '../store/useStore'
import threatService from '../services/threat.service'

export default function SecurityDashboard() {
  const navigate = useNavigate()
  const { threatLevel, setThreatLevel, missionPreset, setMissionPreset } = useStore()

  const [realtimeThreat, setRealtimeThreat] = useState(null)
  const [threatHistory, setThreatHistory] = useState([])
  const [stats, setStats] = useState(null)
  const [monitoring, setMonitoring] = useState(false)
  const [liveCapture, setLiveCapture] = useState(null)  // real NIC stats
  const [responseStatus, setResponseStatus] = useState(null) // auto-response engine state
  const [lastThreatTs, setLastThreatTs] = useState(null) // timestamp of last real threat

  useEffect(() => {
    const backendUrl = localStorage.getItem('serverUrl') || `http://${window.location.hostname}:3001`

    setMonitoring(true)
    const stopMonitoring = threatService.startMonitoring((result) => {
      setRealtimeThreat(result)
      setLastThreatTs(Date.now())
      setThreatHistory(prev => [...prev.slice(-19), result])
      setThreatLevel(result.threatLevel)
    })

    const updateStats = () => {
      const threatStats = threatService.getThreatStats()
      setStats(threatStats)
    }
    updateStats()
    const statsInterval = setInterval(updateStats, 5000)

    // Poll real NIC capture stats every 3s
    const fetchCaptureStats = async () => {
      try {
        const r = await fetch(`${backendUrl}/api/ml/monitor/stats`, { signal: AbortSignal.timeout(4000) })
        if (r.ok) setLiveCapture(await r.json())
      } catch { /* ML service not yet up */ }
    }
    fetchCaptureStats()
    const captureInterval = setInterval(fetchCaptureStats, 3000)

    // Poll auto-response engine status every 5s
    const fetchResponseStatus = async () => {
      try {
        const r = await fetch(`${backendUrl}/api/ml/response/status`, { signal: AbortSignal.timeout(4000) })
        if (r.ok) setResponseStatus(await r.json())
      } catch { /* ML service not yet up */ }
    }
    fetchResponseStatus()
    const responseInterval = setInterval(fetchResponseStatus, 5000)

    return () => {
      stopMonitoring()
      clearInterval(statsInterval)
      clearInterval(captureInterval)
      clearInterval(responseInterval)
      setMonitoring(false)
    }
  }, [])

  // Auto-clear stale threat after 30s of silence
  useEffect(() => {
    if (!lastThreatTs) return
    const t = setTimeout(() => {
      setRealtimeThreat(null)
      setThreatLevel('safe')
    }, 30000)
    return () => clearTimeout(t)
  }, [lastThreatTs])

  const handleUnblock = async (ip) => {
    try {
      const backendUrl = localStorage.getItem('serverUrl') || `http://${window.location.hostname}:3001`
      const r = await fetch(`${backendUrl}/api/ml/response/unblock`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
      })
      if (r.ok) {
        setResponseStatus(prev => prev ? {
          ...prev,
          blocked_ips: prev.blocked_ips.filter(b => b.ip !== ip),
          blocked_count: Math.max(0, (prev.blocked_count || 1) - 1)
        } : prev)
      }
    } catch { /* ignore */ }
  }

  const missionPresets = [
    {
      id: 'silent',
      name: 'Silent Patrol',
      description: 'High obfuscation, minimal bandwidth',
      icon: Eye,
      features: ['80% padding', '1800s rekeying', '4-hop mixnet']
    },
    {
      id: 'balanced',
      name: 'Balanced',
      description: 'Optimal performance and security',
      icon: Shield,
      features: ['30% padding', '3600s rekeying', '2-hop mixnet']
    },
    {
      id: 'secure',
      name: 'Secure Base',
      description: 'Maximum speed, minimal overhead',
      icon: Zap,
      features: ['10% padding', '7200s rekeying', 'Direct routing']
    },
    {
      id: 'compromised',
      name: 'Compromised Network',
      description: 'Emergency mode, maximum protection',
      icon: AlertTriangle,
      features: ['95% padding', '60s rekeying', '5-hop mixnet']
    },
  ]

  const getThreatColor = (score) => {
    if (score < 0.25) return 'text-cyphra-success'
    if (score < 0.50) return 'text-cyphra-warning'
    if (score < 0.75) return 'text-orange-400'
    return 'text-cyphra-danger'
  }

  const getThreatDot = (score) => {
    if (score < 0.25) return 'bg-cyphra-success'
    if (score < 0.50) return 'bg-cyphra-warning'
    if (score < 0.75) return 'bg-orange-400'
    return 'bg-cyphra-danger'
  }

  const formatThreatLevel = (level) => {
    return level.charAt(0).toUpperCase() + level.slice(1)
  }

  return (
    <div className="h-full overflow-y-auto bg-cyphra-bg">
      {/* Header */}
      <div className="border-b border-cyphra-border px-8 py-5">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-lg font-semibold text-cyphra-text-primary">Security Operations Center</h1>
            <p className="text-xs text-cyphra-text-muted mt-0.5">Real-time AI-powered threat monitoring</p>
          </div>
          <div className={`flex items-center gap-2 px-3 py-1.5 rounded text-xs font-medium ${
            monitoring ? 'bg-cyphra-success-muted text-cyphra-success' : 'bg-cyphra-surface text-cyphra-text-muted'
          }`}>
            <div className={`w-1.5 h-1.5 rounded-full ${monitoring ? 'bg-cyphra-success animate-pulse' : 'bg-cyphra-text-muted'}`} />
            <span>
              {monitoring
                ? liveCapture?.capture_iface
                  ? `Live Capture · ${liveCapture.capture_iface}`
                  : 'Monitoring Active'
                : 'Offline'}
            </span>
          </div>
        </div>
      </div>

      <div className="p-8 space-y-6">
        {/* Metric Cards */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} className="card">
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs text-cyphra-text-muted">Current Threat</span>
              <Activity className={`w-4 h-4 ${realtimeThreat ? getThreatColor(realtimeThreat.threatScore) : 'text-cyphra-text-muted'}`} strokeWidth={1.5} />
            </div>
            <p className={`text-xl font-semibold font-mono ${realtimeThreat ? getThreatColor(realtimeThreat.threatScore) : 'text-cyphra-text-primary'}`}>
              {realtimeThreat ? `${(realtimeThreat.threatScore * 100).toFixed(1)}%` : 'N/A'}
            </p>
            <p className="text-[11px] text-cyphra-text-muted mt-1">
              {realtimeThreat ? formatThreatLevel(realtimeThreat.threatLevel) : 'Initializing...'}
            </p>
          </motion.div>

          <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.06 }} className="card">
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs text-cyphra-text-muted">Average Threat</span>
              <TrendingUp className="w-4 h-4 text-cyphra-text-muted" strokeWidth={1.5} />
            </div>
            <p className="text-xl font-semibold font-mono text-cyphra-text-primary">
              {stats ? `${(stats.avgThreatScore * 100).toFixed(1)}%` : '0%'}
            </p>
            <p className="text-[11px] text-cyphra-text-muted mt-1">
              {stats && stats.trendDirection === 'increasing' && 'Trend: Increasing'}
              {stats && stats.trendDirection === 'decreasing' && 'Trend: Decreasing'}
              {stats && stats.trendDirection === 'stable' && 'Trend: Stable'}
            </p>
          </motion.div>

          <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.12 }} className="card">
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs text-cyphra-text-muted">Threats Detected</span>
              <AlertTriangle className="w-4 h-4 text-cyphra-text-muted" strokeWidth={1.5} />
            </div>
            <p className="text-xl font-semibold font-mono text-cyphra-text-primary">
              {stats ? stats.threatsDetected : 0}
            </p>
            <p className="text-[11px] text-cyphra-text-muted mt-1">Last 100 samples</p>
          </motion.div>

          <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.18 }} className="card">
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs text-cyphra-text-muted">Live Bandwidth</span>
              <Activity className="w-4 h-4 text-cyphra-text-muted" strokeWidth={1.5} />
            </div>
            <p className="text-xl font-semibold font-mono text-cyphra-text-primary">
              {liveCapture ? `${liveCapture.bandwidth_mbps ?? '0.000'} Mbps` : '— Mbps'}
            </p>
            <p className="text-[11px] text-cyphra-text-muted mt-1">
              {liveCapture
                ? `${liveCapture.packets_captured?.toLocaleString() ?? 0} pkts · ${liveCapture.packet_rate_pps ?? 0} pps`
                : 'Awaiting capture...'}
            </p>
          </motion.div>
        </div>

        {/* Threat Details */}
        {realtimeThreat && realtimeThreat.threatScore > 0.25 && (
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            className="card"
          >
            <div className="flex items-start gap-4">
              <div className={`mt-0.5 w-2.5 h-2.5 rounded-full flex-shrink-0 ${getThreatDot(realtimeThreat.threatScore)}`} />
              <div className="flex-1 min-w-0">
                <p className={`text-sm font-medium ${getThreatColor(realtimeThreat.threatScore)} mb-1`}>
                  {formatThreatLevel(realtimeThreat.threatLevel)} Threat
                </p>
                <p className="text-xs text-cyphra-text-secondary mb-4">{realtimeThreat.recommendation}</p>
                <div className="grid grid-cols-3 gap-3">
                  <div className="px-3 py-2.5 bg-cyphra-bg rounded border border-cyphra-border">
                    <p className="text-[11px] text-cyphra-text-muted mb-1">Packet Anomaly</p>
                    <p className="text-xs font-mono font-medium text-cyphra-text-primary">
                      {realtimeThreat.details.packetAnomaly ? 'Detected' : 'Normal'}
                    </p>
                  </div>
                  <div className="px-3 py-2.5 bg-cyphra-bg rounded border border-cyphra-border">
                    <p className="text-[11px] text-cyphra-text-muted mb-1">Timing Anomaly</p>
                    <p className="text-xs font-mono font-medium text-cyphra-text-primary">
                      {realtimeThreat.details.timingAnomaly ? 'Detected' : 'Normal'}
                    </p>
                  </div>
                  <div className="px-3 py-2.5 bg-cyphra-bg rounded border border-cyphra-border">
                    <p className="text-[11px] text-cyphra-text-muted mb-1">Pattern</p>
                    <p className="text-xs font-mono font-medium text-cyphra-text-primary">
                      {realtimeThreat.details.patternDetected ? 'Detected' : 'Clear'}
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </motion.div>
        )}

        <div className="grid lg:grid-cols-3 gap-6">
          {/* Threat Timeline */}
          <div className="lg:col-span-2 card">
            <h3 className="text-sm font-semibold text-cyphra-text-primary mb-4">Threat Timeline</h3>
            <div className="space-y-1.5">
              {threatHistory.length === 0 && (
                <p className="text-xs text-cyphra-text-muted py-4 text-center">Collecting data...</p>
              )}
              {threatHistory.slice(-10).reverse().map((threat, index) => (
                <motion.div
                  key={index}
                  initial={{ opacity: 0, x: -8 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: index * 0.03 }}
                  className="flex items-center gap-3 px-3 py-2.5 bg-cyphra-bg rounded border border-cyphra-border"
                >
                  <div className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${getThreatDot(threat.threatScore)}`} />
                  <div className="flex-1 flex items-center justify-between min-w-0">
                    <div className="flex items-center gap-3">
                      <span className="text-xs font-medium text-cyphra-text-primary">
                        {formatThreatLevel(threat.threatLevel)}
                      </span>
                      <span className="text-[11px] font-mono text-cyphra-text-muted">
                        {(threat.threatScore * 100).toFixed(1)}%
                      </span>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className="text-[11px] text-cyphra-text-muted">{threat.category}</span>
                      <span className="text-[11px] font-mono text-cyphra-text-muted">
                        {new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                      </span>
                    </div>
                  </div>
                </motion.div>
              ))}
            </div>
          </div>

          {/* AI Model Status */}
          <div className="card">
            <h3 className="text-sm font-semibold text-cyphra-text-primary mb-4">AI Model Status</h3>
            <div className="space-y-3">
              <div className="px-3 py-2.5 rounded border border-cyphra-success/20 bg-cyphra-success-muted">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-medium text-cyphra-success">Model Loaded</span>
                  <CheckCircle className="w-3.5 h-3.5 text-cyphra-success" strokeWidth={1.5} />
                </div>
                <p className="text-[11px] text-cyphra-text-muted mt-0.5">Ready for inference</p>
              </div>

              <div className="px-3 py-2.5 bg-cyphra-bg rounded border border-cyphra-border">
                <p className="text-[11px] text-cyphra-text-muted mb-2">Accuracy</p>
                <div className="flex items-center gap-2">
                  <div className="flex-1 bg-cyphra-border rounded-full h-1.5 overflow-hidden">
                    <div className="bg-cyphra-accent h-full rounded-full" style={{ width: '99.3%' }} />
                  </div>
                  <span className="text-xs font-mono font-medium text-cyphra-accent">99.3%</span>
                </div>
              </div>

              <div className="px-3 py-2.5 bg-cyphra-bg rounded border border-cyphra-border">
                <p className="text-[11px] text-cyphra-text-muted mb-1">Training Data</p>
                <p className="text-xs font-mono font-medium text-cyphra-text-primary">3.1M samples</p>
                <p className="text-[11px] text-cyphra-text-muted mt-0.5">4 datasets combined</p>
              </div>

              <div className="px-3 py-2.5 bg-cyphra-bg rounded border border-cyphra-border">
                <p className="text-[11px] text-cyphra-text-muted mb-1">Inference Speed</p>
                <p className="text-xs font-mono font-medium text-cyphra-text-primary">&lt; 10ms</p>
                <p className="text-[11px] text-cyphra-text-muted mt-0.5">Per flow analysis</p>
              </div>
            </div>
          </div>
        </div>

        {/* Mission Presets */}
        <div className="card">
          <h3 className="text-sm font-semibold text-cyphra-text-primary mb-4">Mission Presets</h3>
          <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-3">
            {missionPresets.map((preset) => {
              const Icon = preset.icon
              const isActive = missionPreset === preset.id
              return (
                <button
                  key={preset.id}
                  onClick={() => setMissionPreset(preset.id)}
                  className={`text-left p-4 rounded border transition-colors ${
                    isActive
                      ? 'border-cyphra-accent bg-cyphra-accent-muted'
                      : 'border-cyphra-border bg-cyphra-bg hover:border-cyphra-border-light'
                  }`}
                >
                  <Icon className={`w-5 h-5 mb-3 ${isActive ? 'text-cyphra-accent' : 'text-cyphra-text-muted'}`} strokeWidth={1.5} />
                  <p className={`text-xs font-medium mb-0.5 ${isActive ? 'text-cyphra-accent' : 'text-cyphra-text-primary'}`}>{preset.name}</p>
                  <p className="text-[11px] text-cyphra-text-muted mb-3">{preset.description}</p>
                  <div className="space-y-1">
                    {preset.features.map((feature, i) => (
                      <div key={i} className="flex items-center gap-2 text-[11px] text-cyphra-text-muted">
                        <div className={`w-1 h-1 rounded-full ${isActive ? 'bg-cyphra-accent' : 'bg-cyphra-text-muted'}`} />
                        <span className="font-mono">{feature}</span>
                      </div>
                    ))}
                  </div>
                </button>
              )
            })}
          </div>
        </div>

        {/* Auto-Response: Blocked IPs */}
        {responseStatus && (
          <div className="card">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2.5">
                <Ban className="w-4 h-4 text-cyphra-danger" strokeWidth={1.5} />
                <h3 className="text-sm font-semibold text-cyphra-text-primary">Auto-Response Engine</h3>
              </div>
              <div className="flex items-center gap-3">
                <span className={`text-[11px] font-mono px-2 py-0.5 rounded ${
                  responseStatus.enabled ? 'bg-green-900/40 text-green-400' : 'bg-red-900/40 text-red-400'
                }`}>
                  {responseStatus.enabled ? 'ACTIVE' : 'DISABLED'}
                </span>
                <span className="text-[11px] text-cyphra-text-muted">
                  {responseStatus.blocked_count || 0} IP{responseStatus.blocked_count !== 1 ? 's' : ''} blocked
                </span>
              </div>
            </div>

            {responseStatus.blocked_ips && responseStatus.blocked_ips.length > 0 ? (
              <div className="space-y-2">
                {responseStatus.blocked_ips.slice(-10).reverse().map((entry, i) => (
                  <div key={i} className="flex items-center justify-between p-2.5 rounded bg-red-950/30 border border-red-900/40">
                    <div className="flex items-center gap-3">
                      <div className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                        entry.tier === 1 ? 'bg-red-900/60 text-red-300' :
                        entry.tier === 2 ? 'bg-orange-900/60 text-orange-300' :
                                          'bg-yellow-900/60 text-yellow-300'
                      }`}>
                        T{entry.tier}
                      </div>
                      <div>
                        <span className="text-xs font-mono text-cyphra-text-primary">{entry.ip}</span>
                        <span className="text-[11px] text-cyphra-text-muted ml-2">{entry.attack_type}</span>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className="text-[11px] font-mono text-red-400">{(entry.score * 100).toFixed(0)}%</span>
                      <button
                        onClick={() => handleUnblock(entry.ip)}
                        className="text-[11px] px-2 py-0.5 rounded border border-cyphra-border text-cyphra-text-muted hover:border-cyphra-accent hover:text-cyphra-accent transition-colors"
                      >
                        Unblock
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="flex items-center gap-2 text-[11px] text-cyphra-success">
                <ShieldCheck className="w-3.5 h-3.5" />
                <span>No IPs currently blocked — network clean</span>
              </div>
            )}

            {/* Last 5 actions */}
            {responseStatus.action_log && responseStatus.action_log.length > 0 && (
              <div className="mt-4 pt-4 border-t border-cyphra-border">
                <p className="text-[11px] text-cyphra-text-muted mb-2 uppercase tracking-wider">Recent Actions</p>
                <div className="space-y-1">
                  {responseStatus.action_log.slice(-5).reverse().map((log, i) => (
                    <div key={i} className="flex items-center gap-2 text-[11px]">
                      <span className={`font-mono ${
                        log.action.startsWith('T1') ? 'text-red-400' :
                        log.action.startsWith('T2') ? 'text-orange-400' :
                        log.action.includes('UNBLOCK') ? 'text-green-400' :
                        'text-cyphra-text-muted'
                      }`}>{log.action}</span>
                      <span className="text-cyphra-text-muted">{log.ip}</span>
                      <span className="text-cyphra-text-muted ml-auto">{log.ts_iso?.slice(11)}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* System Health */}
        <div className="grid sm:grid-cols-3 gap-4">
          <div className="card">
            <div className="flex items-center gap-2.5 mb-2.5">
              <Shield className="w-4 h-4 text-cyphra-success" strokeWidth={1.5} />
              <span className="text-xs font-medium text-cyphra-text-primary">Encryption</span>
            </div>
            <p className="text-xs text-cyphra-text-secondary mb-1.5">PQC Hybrid Active</p>
            <div className="flex items-center gap-1.5 text-[11px] text-cyphra-success">
              <div className="status-dot-active" />
              <span>All traffic encrypted</span>
            </div>
          </div>

          <div className="card">
            <div className="flex items-center gap-2.5 mb-2.5">
              <Eye className="w-4 h-4 text-cyphra-accent" strokeWidth={1.5} />
              <span className="text-xs font-medium text-cyphra-text-primary">Metadata Protection</span>
            </div>
            <p className="text-xs text-cyphra-text-secondary mb-1.5">AI Shaping Active</p>
            <div className="flex items-center gap-1.5 text-[11px] text-cyphra-accent">
              <div className="status-dot bg-cyphra-accent" />
              <span>Traffic obfuscated</span>
            </div>
          </div>

          <div className="card">
            <div className="flex items-center gap-2.5 mb-2.5">
              <Database className="w-4 h-4 text-cyphra-teal" strokeWidth={1.5} />
              <span className="text-xs font-medium text-cyphra-text-primary">Secure Storage</span>
            </div>
            <p className="text-xs text-cyphra-text-secondary mb-1.5">VedDB Operational</p>
            <div className="flex items-center gap-1.5 text-[11px] text-cyphra-teal">
              <div className="status-dot bg-cyphra-teal" />
              <span>Zero-knowledge storage</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

