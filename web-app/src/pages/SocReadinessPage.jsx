import { useEffect, useState } from 'react'
import { SocShell, SocLoading, SocError, SocEmpty, SocNavBar } from '../components/SocShell'
import * as soc from '../services/soc.service'

export default function SocReadinessPage() {
  const [state, setState] = useState({ loading: true, data: null, error: null })

  useEffect(() => {
    soc.readiness().then(d => setState({ loading: false, data: d }))
      .catch(e => setState({ loading: false, data: null, error: e }))
  }, [])

  return (
    <SocShell
      title="Readiness"
      subtitle="Every credential slot the platform reads, and whether it's set."
      current="readiness"
    >
      <SocNavBar current="readiness" />
      {state.loading ? <SocLoading /> :
       state.error ? <SocError error={state.error} onRetry={() => window.location.reload()} /> :
       (
        <div className="bg-cyphra-surface border border-cyphra-border rounded-lg overflow-hidden">
          <table className="w-full text-xs">
            <thead className="bg-cyphra-surface-alt text-cyphra-text-muted uppercase tracking-wider">
              <tr>
                <th className="px-4 py-2 text-left">Slot</th>
                <th className="px-4 py-2 text-left">Env var</th>
                <th className="px-4 py-2 text-left">Purpose</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-cyphra-border">
              {state.data.configured.map(name => (
                <tr key={name} className="text-cyphra-text-secondary">
                  <td className="px-4 py-2 font-mono">{name}</td>
                  <td className="px-4 py-2 text-cyphra-success">configured</td>
                  <td className="px-4 py-2 text-cyphra-text-muted">—</td>
                </tr>
              ))}
              {state.data.unset.length === 0 ? null : state.data.unset.map(slot => (
                <tr key={slot.name} className="text-cyphra-text-secondary">
                  <td className="px-4 py-2 font-mono">{slot.name}</td>
                  <td className="px-4 py-2 font-mono text-cyphra-warning">${slot.env_var}</td>
                  <td className="px-4 py-2 text-cyphra-text-muted">{slot.purpose}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
       )}
    </SocShell>
  )
}
