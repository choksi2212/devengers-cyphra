import { useEffect, useState } from 'react'
import { SocShell, SocLoading, SocError, SocEmpty, SocNavBar } from '../components/SocShell'
import * as soc from '../services/soc.service'

export default function SocCasesPage() {
  const [includeAll, setIncludeAll] = useState(false)
  const [state, setState] = useState({ loading: true, data: null, error: null })

  useEffect(() => {
    setState({ loading: true, data: null, error: null })
    soc.cases(includeAll).then(d => setState({ loading: false, data: d }))
      .catch(e => setState({ loading: false, data: null, error: e }))
  }, [includeAll])

  return (
    <SocShell
      title="Cases"
      subtitle="Open investigations tracked by the case store."
      current="cases"
      actions={
        <button
          onClick={() => setIncludeAll(v => !v)}
          className={`px-3 py-1.5 rounded text-xs font-medium border transition-colors ${
            includeAll
              ? 'bg-cyphra-accent/15 border-cyphra-accent/40 text-cyphra-accent'
              : 'bg-cyphra-surface border-cyphra-border text-cyphra-text-secondary hover:text-cyphra-text-primary'
          }`}
        >
          {includeAll ? 'Showing all' : 'Showing open'}
        </button>
      }
    >
      <SocNavBar current="cases" />
      {state.loading ? <SocLoading /> :
       state.error ? <SocError error={state.error} /> :
       state.data.cases.length === 0 ? <SocEmpty message="No cases yet." /> :
       (
        <div className="bg-cyphra-surface border border-cyphra-border rounded-lg overflow-hidden">
          <table className="w-full text-xs">
            <thead className="bg-cyphra-surface-alt text-cyphra-text-muted uppercase tracking-wider">
              <tr>
                <th className="px-4 py-2 text-left">UID</th>
                <th className="px-4 py-2 text-left">Status</th>
                <th className="px-4 py-2 text-left">Severity</th>
                <th className="px-4 py-2 text-left">Title</th>
                <th className="px-4 py-2 text-left">Attacks</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-cyphra-border">
              {state.data.cases.map(c => (
                <tr key={c.uid} className="text-cyphra-text-secondary">
                  <td className="px-4 py-2 font-mono text-cyphra-text-primary">{c.uid}</td>
                  <td className="px-4 py-2">{c.status}</td>
                  <td className="px-4 py-2">{c.severity_id}</td>
                  <td className="px-4 py-2 text-cyphra-text-primary">{c.title}</td>
                  <td className="px-4 py-2 font-mono text-cyphra-text-muted">
                    {(c.attack_ids || []).join(', ') || '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
       )}
    </SocShell>
  )
}
