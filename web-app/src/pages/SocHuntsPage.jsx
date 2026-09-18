import { useEffect, useState } from 'react'
import { SocShell, SocLoading, SocError, SocEmpty, SocNavBar } from '../components/SocShell'
import * as soc from '../services/soc.service'

export default function SocHuntsPage() {
  const [run, setRun] = useState(false)
  const [state, setState] = useState({ loading: true, data: null, error: null })

  useEffect(() => {
    setState({ loading: true, data: null, error: null })
    soc.hunts(run).then(d => setState({ loading: false, data: d }))
      .catch(e => setState({ loading: false, data: null, error: e }))
  }, [run])

  return (
    <SocShell
      title="Hunts"
      subtitle="Hypothesis-driven queries run against the lake."
      current="hunts"
      actions={
        <button
          onClick={() => setRun(v => !v)}
          className={`px-3 py-1.5 rounded text-xs font-medium border transition-colors ${
            run
              ? 'bg-cyphra-accent/15 border-cyphra-accent/40 text-cyphra-accent'
              : 'bg-cyphra-surface border-cyphra-border text-cyphra-text-secondary hover:text-cyphra-text-primary'
          }`}
        >
          {run ? 'Also running' : 'Run on click'}
        </button>
      }
    >
      <SocNavBar current="hunts" />
      {state.loading ? <SocLoading /> :
       state.error ? <SocError error={state.error} /> :
       state.data.registered.length === 0 ? <SocEmpty message="No hunts registered." /> :
       (
        <div className="bg-cyphra-surface border border-cyphra-border rounded-lg overflow-hidden">
          <table className="w-full text-xs">
            <thead className="bg-cyphra-surface-alt text-cyphra-text-muted uppercase tracking-wider">
              <tr>
                <th className="px-4 py-2 text-left">Name</th>
                <th className="px-4 py-2 text-left">Window</th>
                <th className="px-4 py-2 text-right">Predicates</th>
                {run && <th className="px-4 py-2 text-right">Hits</th>}
              </tr>
            </thead>
            <tbody className="divide-y divide-cyphra-border">
              {state.data.registered.map(h => {
                const runResult = state.data.runs.find(r => r.name === h.name)
                return (
                  <tr key={h.name} className="text-cyphra-text-secondary">
                    <td className="px-4 py-2 font-mono text-cyphra-text-primary">{h.name}</td>
                    <td className="px-4 py-2">{h.window}</td>
                    <td className="px-4 py-2 text-right font-mono">{h.predicate_count}</td>
                    {run && (
                      <td className="px-4 py-2 text-right font-mono">
                        {runResult ? runResult.hit_count : '—'}
                      </td>
                    )}
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
       )}
    </SocShell>
  )
}
