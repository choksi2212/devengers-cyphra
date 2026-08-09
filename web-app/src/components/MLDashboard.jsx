import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Shield, Activity, Cpu, Zap, AlertTriangle, CheckCircle, TrendingUp, Database, Server, Clock } from 'lucide-react'
import mlSimulationService from '../services/ml-intelligence.service'

export default function MLDashboard() {
  const [modelInfo, setModelInfo] = useState(mlSimulationService.getModelInfo())
  const [networkStats, setNetworkStats] = useState(mlSimulationService.getNetworkStats())
  const [trainingLog, setTrainingLog] = useState(mlSimulationService.getTrainingLog())
  const [showDetails, setShowDetails] = useState(false)

  // Real dataset sample lookup from training log (real values from 01_combine_datasets.py)
  const datasetSamples = {
    'ISCXVPN2016':    '271,028',
    'UNSW-NB15':      '257,673',
    'CICIDS2017':     '2,830,743',
    'CSE-CICIDS2018': '16,233,002',
  }

  useEffect(() => {
    const interval = setInterval(() => {
      setNetworkStats(mlSimulationService.getNetworkStats())
    }, 2000)
    return () => clearInterval(interval)
  }, [])

  const getThreatColor = (level) => {
    switch (level) {
      case 'critical': return 'text-cyphra-danger border-cyphra-danger/30 bg-cyphra-danger-muted'
      case 'high': return 'text-orange-400 border-orange-400/30 bg-orange-400/10'
      case 'medium': return 'text-cyphra-warning border-cyphra-warning/30 bg-cyphra-warning-muted'
      case 'low': return 'text-cyphra-accent border-cyphra-accent/30 bg-cyphra-accent-muted'
      default: return 'text-cyphra-success border-cyphra-success/30 bg-cyphra-success-muted'
    }
  }

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Cpu className="w-5 h-5 text-cyphra-accent" strokeWidth={1.5} />
          <div>
            <h2 className="text-sm font-semibold text-cyphra-text-primary">AI/ML Threat Detection</h2>
            <p className="text-[11px] text-cyphra-text-muted">Real-time network traffic analysis</p>
          </div>
        </div>
        <div className="flex items-center gap-2 px-2.5 py-1.5 rounded border border-cyphra-success/20 bg-cyphra-success-muted">
          <div className="w-1.5 h-1.5 bg-cyphra-success rounded-full animate-pulse" />
          <span className="text-[11px] font-medium text-cyphra-success">ACTIVE</span>
        </div>
      </div>

      {/* Model Info */}
      <div className="grid grid-cols-3 gap-3">
        <div className="px-3.5 py-3 bg-cyphra-bg rounded border border-cyphra-border">
          <div className="flex items-center gap-1.5 mb-2">
            <Shield className="w-3.5 h-3.5 text-cyphra-accent" strokeWidth={1.5} />
            <span className="text-[11px] text-cyphra-text-muted">Model</span>
          </div>
          <p className="text-xs font-medium text-cyphra-text-primary">{modelInfo.name}</p>
          <p className="text-[11px] text-cyphra-text-muted mt-0.5">{modelInfo.architecture}</p>
        </div>

        <div className="px-3.5 py-3 bg-cyphra-bg rounded border border-cyphra-border">
          <div className="flex items-center gap-1.5 mb-2">
            <Database className="w-3.5 h-3.5 text-cyphra-accent" strokeWidth={1.5} />
            <span className="text-[11px] text-cyphra-text-muted">Training Data</span>
          </div>
          <p className="text-xs font-mono font-medium text-cyphra-text-primary">{modelInfo.totalSamples}</p>
          <p className="text-[11px] text-cyphra-text-muted mt-0.5">samples across 4 datasets</p>
        </div>

        <div className="px-3.5 py-3 bg-cyphra-bg rounded border border-cyphra-border">
          <div className="flex items-center gap-1.5 mb-2">
            <TrendingUp className="w-3.5 h-3.5 text-cyphra-success" strokeWidth={1.5} />
            <span className="text-[11px] text-cyphra-text-muted">Accuracy</span>
          </div>
          <p className="text-xs font-mono font-medium text-cyphra-success">{modelInfo.accuracy}%</p>
          <p className="text-[11px] text-cyphra-text-muted mt-0.5">F1: {modelInfo.f1Score}%</p>
        </div>
      </div>

      {/* Threat Level */}
      <div className={`px-4 py-3.5 rounded border ${getThreatColor(networkStats.threatLevel)}`}>
        <div className="flex items-center justify-between">
          <div>
            <p className="text-[11px] opacity-70 mb-1">Current Threat Level</p>
            <p className="text-lg font-semibold font-mono uppercase">{networkStats.threatLevel}</p>
            <p className="text-[11px] opacity-60 mt-1">
              Score: {(networkStats.threatScore * 100).toFixed(2)}%
            </p>
          </div>
          {networkStats.threatLevel === 'low' || networkStats.threatLevel === 'safe' ? (
            <CheckCircle className="w-8 h-8 opacity-40" strokeWidth={1} />
          ) : (
            <AlertTriangle className="w-8 h-8 opacity-40" strokeWidth={1} />
          )}
        </div>
      </div>

      {/* Real-time Metrics */}
      <div className="grid grid-cols-4 gap-3">
        <div className="px-3.5 py-3 bg-cyphra-bg rounded border border-cyphra-border">
          <div className="flex items-center gap-1.5 mb-2">
            <Activity className="w-3.5 h-3.5 text-cyphra-text-muted" strokeWidth={1.5} />
            <span className="text-[11px] text-cyphra-text-muted">Packets</span>
          </div>
          <p className="text-sm font-mono font-semibold text-cyphra-text-primary">{networkStats.packetsAnalyzed.toLocaleString()}</p>
        </div>

        <div className="px-3.5 py-3 bg-cyphra-bg rounded border border-cyphra-border">
          <div className="flex items-center gap-1.5 mb-2">
            <Shield className="w-3.5 h-3.5 text-cyphra-danger" strokeWidth={1.5} />
            <span className="text-[11px] text-cyphra-text-muted">Threats</span>
          </div>
          <p className="text-sm font-mono font-semibold text-cyphra-danger">{networkStats.threatsDetected}</p>
        </div>

        <div className="px-3.5 py-3 bg-cyphra-bg rounded border border-cyphra-border">
          <div className="flex items-center gap-1.5 mb-2">
            <Zap className="w-3.5 h-3.5 text-cyphra-warning" strokeWidth={1.5} />
            <span className="text-[11px] text-cyphra-text-muted">Latency</span>
          </div>
          <p className="text-sm font-mono font-semibold text-cyphra-text-primary">{networkStats.avgLatency.toFixed(1)}<span className="text-[11px] text-cyphra-text-muted ml-0.5">ms</span></p>
        </div>

        <div className="px-3.5 py-3 bg-cyphra-bg rounded border border-cyphra-border">
          <div className="flex items-center gap-1.5 mb-2">
            <Server className="w-3.5 h-3.5 text-cyphra-text-muted" strokeWidth={1.5} />
            <span className="text-[11px] text-cyphra-text-muted">Connections</span>
          </div>
          <p className="text-sm font-mono font-semibold text-cyphra-text-primary">{networkStats.activeConnections}</p>
        </div>
      </div>

      {/* Performance Metrics */}
      <div className="px-4 py-3.5 bg-cyphra-bg rounded border border-cyphra-border">
        <h3 className="text-xs font-semibold text-cyphra-text-primary mb-3 flex items-center gap-2">
          <TrendingUp className="w-3.5 h-3.5 text-cyphra-accent" strokeWidth={1.5} />
          Model Performance
        </h3>
        <div className="grid grid-cols-4 gap-4">
          <div>
            <p className="text-[11px] text-cyphra-text-muted mb-0.5">Precision</p>
            <p className="text-sm font-mono font-semibold text-cyphra-text-primary">{modelInfo.precision}%</p>
          </div>
          <div>
            <p className="text-[11px] text-cyphra-text-muted mb-0.5">Recall</p>
            <p className="text-sm font-mono font-semibold text-cyphra-text-primary">{modelInfo.recall}%</p>
          </div>
          <div>
            <p className="text-[11px] text-cyphra-text-muted mb-0.5">Detection Rate</p>
            <p className="text-sm font-mono font-semibold text-cyphra-success">{networkStats.detectionRate}%</p>
          </div>
          <div>
            <p className="text-[11px] text-cyphra-text-muted mb-0.5">Inference Time</p>
            <p className="text-sm font-mono font-semibold text-cyphra-text-primary">{networkStats.avgInferenceTime}<span className="text-[11px] text-cyphra-text-muted ml-0.5">ms</span></p>
          </div>
        </div>
      </div>

      {/* Datasets Info */}
      <div className="px-4 py-3.5 bg-cyphra-bg rounded border border-cyphra-border">
        <h3 className="text-xs font-semibold text-cyphra-text-primary mb-3">Training Datasets</h3>
        <div className="space-y-2">
          {modelInfo.trainedOn.map((dataset, idx) => (
            <div key={idx} className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className="w-1 h-1 bg-cyphra-accent rounded-full" />
                <span className="text-xs text-cyphra-text-primary">{dataset}</span>
              </div>
              <span className="text-[11px] text-cyphra-text-muted font-mono">
                {datasetSamples[dataset] || '—'}
              </span>
            </div>
          ))}
        </div>
        <div className="mt-3 pt-3 border-t border-cyphra-border space-y-1.5">
          <div className="flex items-center justify-between text-xs">
            <span className="text-cyphra-text-muted">Features</span>
            <span className="font-mono text-cyphra-text-primary">{modelInfo.features}</span>
          </div>
          <div className="flex items-center justify-between text-xs">
            <span className="text-cyphra-text-muted">Training Time</span>
            <span className="font-mono text-cyphra-text-primary">{modelInfo.trainingTime}</span>
          </div>
          <div className="flex items-center justify-between text-xs">
            <span className="text-cyphra-text-muted">Last Updated</span>
            <span className="font-mono text-cyphra-text-primary">{modelInfo.lastUpdated}</span>
          </div>
        </div>
      </div>

      {/* Advanced Details Toggle */}
      <button
        onClick={() => setShowDetails(!showDetails)}
        className="w-full px-4 py-2.5 rounded border border-cyphra-accent/20 bg-cyphra-accent-muted text-cyphra-accent text-xs font-medium hover:bg-cyphra-accent/15 transition-colors"
      >
        {showDetails ? 'Hide' : 'Show'} Advanced Training Details
      </button>

      {/* Advanced Details */}
      <AnimatePresence>
        {showDetails && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="px-4 py-3.5 bg-cyphra-bg rounded border border-cyphra-border overflow-hidden"
          >
            <h3 className="text-xs font-semibold text-cyphra-text-primary mb-3">Training Configuration</h3>
            <div className="grid grid-cols-2 gap-3 text-xs">
              <div>
                <span className="text-cyphra-text-muted">Epochs:</span>
                <span className="text-cyphra-text-primary font-mono font-medium ml-1.5">{trainingLog.epochs}</span>
              </div>
              <div>
                <span className="text-cyphra-text-muted">Batch Size:</span>
                <span className="text-cyphra-text-primary font-mono font-medium ml-1.5">{trainingLog.batchSize}</span>
              </div>
              <div>
                <span className="text-cyphra-text-muted">Learning Rate:</span>
                <span className="text-cyphra-text-primary font-mono font-medium ml-1.5">{trainingLog.learningRate}</span>
              </div>
              <div>
                <span className="text-cyphra-text-muted">Optimizer:</span>
                <span className="text-cyphra-text-primary font-mono font-medium ml-1.5">{trainingLog.optimizer}</span>
              </div>
              <div>
                <span className="text-cyphra-text-muted">Loss Function:</span>
                <span className="text-cyphra-text-primary font-mono font-medium ml-1.5">{trainingLog.lossFunction}</span>
              </div>
              <div>
                <span className="text-cyphra-text-muted">Best Epoch:</span>
                <span className="text-cyphra-text-primary font-mono font-medium ml-1.5">{trainingLog.bestEpoch}</span>
              </div>
            </div>

            <h4 className="text-xs font-semibold text-cyphra-text-primary mt-5 mb-3">Confusion Matrix</h4>
            <div className="grid grid-cols-2 gap-2.5">
              <div className="px-3 py-2.5 rounded border border-cyphra-success/20 bg-cyphra-success-muted">
                <p className="text-[11px] text-cyphra-success mb-0.5">True Positive</p>
                <p className="text-sm font-mono font-semibold text-cyphra-text-primary">{trainingLog.confusionMatrix.truePositive.toLocaleString()}</p>
              </div>
              <div className="px-3 py-2.5 rounded border border-cyphra-success/20 bg-cyphra-success-muted">
                <p className="text-[11px] text-cyphra-success mb-0.5">True Negative</p>
                <p className="text-sm font-mono font-semibold text-cyphra-text-primary">{trainingLog.confusionMatrix.trueNegative.toLocaleString()}</p>
              </div>
              <div className="px-3 py-2.5 rounded border border-cyphra-danger/20 bg-cyphra-danger-muted">
                <p className="text-[11px] text-cyphra-danger mb-0.5">False Positive</p>
                <p className="text-sm font-mono font-semibold text-cyphra-text-primary">{trainingLog.confusionMatrix.falsePositive.toLocaleString()}</p>
              </div>
              <div className="px-3 py-2.5 rounded border border-cyphra-danger/20 bg-cyphra-danger-muted">
                <p className="text-[11px] text-cyphra-danger mb-0.5">False Negative</p>
                <p className="text-sm font-mono font-semibold text-cyphra-text-primary">{trainingLog.confusionMatrix.falseNegative.toLocaleString()}</p>
              </div>
            </div>

            <div className="mt-3 grid grid-cols-2 gap-3 text-xs">
              <div>
                <span className="text-cyphra-text-muted">ROC-AUC:</span>
                <span className="text-cyphra-text-primary font-mono font-medium ml-1.5">{trainingLog.rocAuc}</span>
              </div>
              <div>
                <span className="text-cyphra-text-muted">PR-AUC:</span>
                <span className="text-cyphra-text-primary font-mono font-medium ml-1.5">{trainingLog.prAuc}</span>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* System Status */}
      <div className="flex items-center justify-between text-[11px] text-cyphra-text-muted">
        <div className="flex items-center gap-1.5">
          <Clock className="w-3 h-3" strokeWidth={1.5} />
          <span className="font-mono">Uptime: {networkStats.uptime}</span>
        </div>
        <div className="flex items-center gap-1.5">
          <div className="w-1.5 h-1.5 bg-cyphra-success rounded-full animate-pulse" />
          <span>All systems operational</span>
        </div>
      </div>
    </div>
  )
}

