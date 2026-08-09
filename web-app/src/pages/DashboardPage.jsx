import { useNavigate } from 'react-router-dom'
import { useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import { MessageSquare, Activity, Users, Shield, Lock, Zap, Eye, CheckCircle, AlertTriangle, ArrowRight } from 'lucide-react'
import useStore from '../store/useStore'
import threatService from '../services/threat.service'

export default function DashboardPage() {
  const navigate = useNavigate()
  const { currentUser, messages, contacts, threatLevel, missionPreset } = useStore()
  const [realtimeThreat, setRealtimeThreat] = useState(null)

  useEffect(() => {
    const stopMonitoring = threatService.startMonitoring((result) => {
      setRealtimeThreat(result)
    })
    return () => stopMonitoring()
  }, [])

  const threatColor = threatLevel === 'critical' ? 'text-cyphra-danger' : threatLevel === 'high' ? 'text-orange-400' : threatLevel === 'medium' ? 'text-cyphra-warning' : 'text-cyphra-success'

  const stats = [
    { label: 'Messages', value: messages.length, icon: MessageSquare },
    { label: 'Contacts', value: contacts.length, icon: Users },
    { label: 'Threat Level', value: threatLevel.toUpperCase(), icon: Activity, color: threatColor },
    { label: 'Preset', value: missionPreset.charAt(0).toUpperCase() + missionPreset.slice(1), icon: Shield },
  ]

  const securityItems = [
    { name: 'E2E Encryption', status: 'Active', icon: Lock },
    { name: 'Metadata Protection', status: 'Enabled', icon: Eye },
    { name: 'Self-Destruct', status: 'Ready', icon: Zap },
    { name: 'AI Detection', status: 'Monitoring', icon: Activity },
  ]

  const activityLog = [
    { message: 'Secure session initiated', time: 'Just now', type: 'success' },
    { message: 'PQC key pair generated', time: '2m ago', type: 'info' },
    { message: 'VedDB connection established', time: '2m ago', type: 'info' },
    { message: `Threat level: ${threatLevel}`, time: 'Live', type: threatLevel === 'low' ? 'info' : 'warning' },
  ]

  return (
    <div className="h-full overflow-y-auto bg-cyphra-bg">
      {/* Header */}
      <div className="border-b border-cyphra-border px-8 py-5">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-lg font-semibold text-cyphra-text-primary">Mission Control</h1>
            <p className="text-xs text-cyphra-text-muted mt-0.5">
              Welcome back, <span className="text-cyphra-accent font-medium">{currentUser?.username}</span>
            </p>
          </div>
          <div className="flex gap-2">
            <button onClick={() => navigate('/messenger')} className="btn-primary text-xs">
              <MessageSquare className="w-3.5 h-3.5" strokeWidth={1.5} />
              Messenger
            </button>
            <button onClick={() => navigate('/security')} className="btn-secondary text-xs">
              <Activity className="w-3.5 h-3.5" strokeWidth={1.5} />
              Security
            </button>
          </div>
        </div>
      </div>

      <div className="p-8 space-y-6">
        {/* Stats Row */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {stats.map((stat, i) => {
            const Icon = stat.icon
            return (
              <motion.div
                key={stat.label}
                initial={{ opacity: 0, y: 12 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.08 }}
                className="card"
              >
                <div className="flex items-center justify-between mb-3">
                  <span className="text-xs text-cyphra-text-muted">{stat.label}</span>
                  <Icon className="w-4 h-4 text-cyphra-text-muted" strokeWidth={1.5} />
                </div>
                <p className={`text-xl font-semibold ${stat.color || 'text-cyphra-text-primary'} font-mono`}>
                  {stat.value}
                </p>
              </motion.div>
            )
          })}
        </div>

        {/* Threat Alert */}
        {realtimeThreat && realtimeThreat.threatScore > 0.5 && (
          <motion.div
            initial={{ opacity: 0, y: -8 }}
            animate={{ opacity: 1, y: 0 }}
            className="flex items-start gap-4 p-5 rounded border border-cyphra-danger/20 bg-cyphra-danger-muted"
          >
            <AlertTriangle className="w-5 h-5 text-cyphra-danger flex-shrink-0 mt-0.5" strokeWidth={1.5} />
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-cyphra-danger mb-1">Threat Detected</p>
              <p className="text-xs text-cyphra-text-secondary mb-3">{realtimeThreat.recommendation}</p>
              <button onClick={() => navigate('/security')} className="text-xs text-cyphra-danger hover:underline flex items-center gap-1">
                View details <ArrowRight className="w-3 h-3" />
              </button>
            </div>
          </motion.div>
        )}

        <div className="grid lg:grid-cols-3 gap-6">
          {/* Security Status */}
          <div className="lg:col-span-2 card">
            <div className="flex items-center justify-between mb-5">
              <h3 className="text-sm font-semibold text-cyphra-text-primary">Security Status</h3>
              <span className="badge-success text-[11px]">Operational</span>
            </div>
            <div className="grid sm:grid-cols-2 gap-3">
              {securityItems.map((item) => {
                const Icon = item.icon
                return (
                  <div key={item.name} className="flex items-center justify-between px-4 py-3 bg-cyphra-bg rounded border border-cyphra-border">
                    <div className="flex items-center gap-3">
                      <div className="status-dot-active" />
                      <span className="text-xs text-cyphra-text-secondary">{item.name}</span>
                    </div>
                    <span className="text-[11px] font-mono text-cyphra-accent">{item.status}</span>
                  </div>
                )
              })}
            </div>
          </div>

          {/* Recent Activity */}
          <div className="card">
            <h3 className="text-sm font-semibold text-cyphra-text-primary mb-4">Activity</h3>
            <div className="space-y-2">
              {activityLog.map((item, i) => (
                <motion.div
                  key={i}
                  initial={{ opacity: 0, x: -8 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: i * 0.08 }}
                  className="flex items-start gap-3 px-3 py-2.5 bg-cyphra-bg rounded"
                >
                  <div className={`mt-1.5 ${
                    item.type === 'success' ? 'status-dot-active' :
                    item.type === 'warning' ? 'status-dot-warning' :
                    'status-dot bg-cyphra-accent'
                  }`} />
                  <div className="flex-1 min-w-0">
                    <p className="text-xs text-cyphra-text-secondary truncate">{item.message}</p>
                    <p className="text-[11px] text-cyphra-text-muted mt-0.5">{item.time}</p>
                  </div>
                </motion.div>
              ))}
            </div>
          </div>
        </div>

        {/* Quick Actions */}
        <div className="card">
          <h3 className="text-sm font-semibold text-cyphra-text-primary mb-4">Quick Actions</h3>
          <div className="grid sm:grid-cols-3 gap-3">
            <button
              onClick={() => navigate('/messenger')}
              className="text-left p-4 bg-cyphra-bg rounded border border-cyphra-border hover:border-cyphra-border-light transition-colors"
            >
              <MessageSquare className="w-5 h-5 text-cyphra-accent mb-3" strokeWidth={1.5} />
              <p className="text-xs font-medium text-cyphra-text-primary mb-0.5">Send Secure Message</p>
              <p className="text-[11px] text-cyphra-text-muted">End-to-end encrypted</p>
            </button>
            <button
              onClick={() => navigate('/security')}
              className="text-left p-4 bg-cyphra-bg rounded border border-cyphra-border hover:border-cyphra-border-light transition-colors"
            >
              <Activity className="w-5 h-5 text-cyphra-success mb-3" strokeWidth={1.5} />
              <p className="text-xs font-medium text-cyphra-text-primary mb-0.5">Monitor Threats</p>
              <p className="text-[11px] text-cyphra-text-muted">Real-time AI detection</p>
            </button>
            <button
              onClick={() => navigate('/defense')}
              className="text-left p-4 bg-cyphra-bg rounded border border-cyphra-border hover:border-cyphra-border-light transition-colors"
            >
              <Shield className="w-5 h-5 text-cyphra-cyan mb-3" strokeWidth={1.5} />
              <p className="text-xs font-medium text-cyphra-text-primary mb-0.5">Defence Ops</p>
              <p className="text-[11px] text-cyphra-text-muted">Signal & EW analysis</p>
            </button>
          </div>
        </div>

        {/* System Info Footer */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            { label: 'Encryption', value: 'AES-256-GCM + Kyber' },
            { label: 'Authentication', value: 'GhostKey' },
            { label: 'Storage', value: 'VedDB Encrypted' },
            { label: 'AI Accuracy', value: '98.83%' },
          ].map((item) => (
            <div key={item.label} className="px-4 py-3 bg-cyphra-surface border border-cyphra-border rounded">
              <p className="text-[11px] text-cyphra-text-muted mb-1">{item.label}</p>
              <p className="text-xs font-mono font-medium text-cyphra-accent">{item.value}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

