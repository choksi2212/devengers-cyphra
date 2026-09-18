import { useEffect, useState } from 'react'
import { SocShell, SocLoading, SocError, SocEmpty, SocNavBar, StatTile } from '../components/SocShell'
import * as soc from '../services/soc.service'

export default function SocMetricsPage() {
  const [state, setState] = useState({ loading: true, data: null, error: null })

  useEffect(() => {
    soc.metrics().then(d => setState({ loading: false, data: d }))
      .catch(e => setState({ loading: false, data: null, error: e }))
  }, [])

  return (
    <SocShell title="Metrics" subtitle="MTTD / MTTR / verdict counts" current="metrics">
      <SocNavBar current="metrics" />
      {state.loading ? <SocLoading /> :
       state.error ? <SocError error={state.error} /> :
       (
        <div>
          <div className="grid grid-cols-4 gap-3 mb-6">
            <StatTile label="Alert volume"   value={state.data.alert_volume} />
            <StatTile label="Incidents"      value={state.data.incident_count} />
            <StatTile label="MTTD (s)"       value={state.data.mttd_seconds.toFixed(3)} />
            <StatTile label="MTTR (s)"       value={state.data.mttr_seconds.toFixed(3)} />
            <StatTile label="False-positive" value={(state.data.false_positive_rate * 100).toFixed(1) + '%'} />
            <StatTile label="True-positive"  value={(state.data.true_positive_rate * 100).toFixed(1) + '%'} accent="success" />
            <StatTile label="Escalation"     value={(state.data.escalation_rate * 100).toFixed(1) + '%'} />
            <StatTile label="Verdicts"       value={Object.values(state.data.verdict_counts || {}).reduce((a, b) => a + b, 0)} />
          </div>
          {state.data.verdict_counts && Object.keys(state.data.verdict_counts).length > 0 && (
            <div className="bg-cyphra-surface border border-cyphra-border rounded-lg p-4">
              <h3 className="text-xs uppercase tracking-wider text-cyphra-text-muted mb-2">Verdict counts</h3>
              <ul className="space-y-1">
                {Object.entries(state.data.verdict_counts).map(([label, count]) => (
                  <li key={label} className="text-xs flex justify-between">
                    <span className="text-cyphra-text-secondary">{label}</span>
                    <span className="text-cyphra-text-primary font-mono">{count}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
       )}
    </SocShell>
  )
}
