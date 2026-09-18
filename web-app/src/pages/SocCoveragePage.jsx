import { useEffect, useState } from 'react'
import { SocShell, SocLoading, SocError, SocEmpty, SocNavBar, StatTile } from '../components/SocShell'
import * as soc from '../services/soc.service'

export default function SocCoveragePage() {
  const [state, setState] = useState({ loading: true, data: null, error: null })

  useEffect(() => {
    soc.coverage().then(d => setState({ loading: false, data: d }))
      .catch(e => setState({ loading: false, data: null, error: e }))
  }, [])

  return (
    <SocShell
      title="Coverage"
      subtitle="Which SOC functions have emulation scenarios backing them."
      current="coverage"
    >
      <SocNavBar current="coverage" />
      {state.loading ? <SocLoading /> :
       state.error ? <SocError error={state.error} /> :
       (
        <div>
          <div className="grid grid-cols-3 gap-3 mb-6">
            <StatTile label="Functions" value={state.data.rows.length} />
            <StatTile
              label="Missing"
              value={state.data.missing.length}
              accent={state.data.missing.length === 0 ? 'success' : 'danger'}
            />
            <StatTile label="Fragile (1 scenario)" value={state.data.fragile.length} accent="warning" />
          </div>
          {state.data.missing.length > 0 && (
            <div className="bg-cyphra-danger-muted border border-cyphra-danger/30 rounded-lg p-4 mb-4">
              <p className="text-xs uppercase tracking-wider text-cyphra-danger mb-2">Missing functions</p>
              <ul className="text-xs text-cyphra-text-secondary space-y-1">
                {state.data.missing.map(fn => (
                  <li key={fn} className="font-mono">- {fn}</li>
                ))}
              </ul>
            </div>
          )}
          <div className="bg-cyphra-surface border border-cyphra-border rounded-lg overflow-hidden">
            <table className="w-full text-xs">
              <thead className="bg-cyphra-surface-alt text-cyphra-text-muted uppercase tracking-wider">
                <tr>
                  <th className="px-4 py-2 text-left">Function</th>
                  <th className="px-4 py-2 text-left">Scenarios</th>
                  <th className="px-4 py-2 text-right">Count</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-cyphra-border">
                {state.data.rows.map(row => (
                  <tr key={row.function} className="text-cyphra-text-secondary">
                    <td className="px-4 py-2 font-mono text-cyphra-text-primary">{row.function}</td>
                    <td className="px-4 py-2">{row.scenarios.join(', ') || '—'}</td>
                    <td className="px-4 py-2 text-right font-mono">{row.count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
       )}
    </SocShell>
  )
}
