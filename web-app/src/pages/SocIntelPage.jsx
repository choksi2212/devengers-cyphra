import { useEffect, useState } from 'react'
import { SocShell, SocLoading, SocError, SocEmpty, SocNavBar, StatTile } from '../components/SocShell'
import * as soc from '../services/soc.service'

export default function SocIntelPage() {
  const [state, setState] = useState({ loading: true, data: null, error: null })

  useEffect(() => {
    soc.intel().then(d => setState({ loading: false, data: d }))
      .catch(e => setState({ loading: false, data: null, error: e }))
  }, [])

  return (
    <SocShell
      title="Intel"
      subtitle="Indicators loaded from OTX / VirusTotal / MISP."
      current="intel"
    >
      <SocNavBar current="intel" />
      {state.loading ? <SocLoading /> :
       state.error ? <SocError error={state.error} /> :
       (
        <div>
          <div className="grid grid-cols-3 gap-3 mb-6">
            <StatTile label="Indicators loaded" value={state.data.indicators_loaded} />
            <StatTile
              label="Sources active"
              value={Object.keys(state.data.by_source).length}
              accent="success"
            />
            <StatTile
              label="Empty sources"
              value={['otx', 'virustotal', 'misp'].filter(s => !state.data.by_source[s]).length}
              accent="warning"
            />
          </div>
          {Object.keys(state.data.by_source).length === 0 ? (
            <SocEmpty message="No intel sources have loaded indicators yet." />
          ) : (
            <div className="bg-cyphra-surface border border-cyphra-border rounded-lg p-4">
              <h3 className="text-xs uppercase tracking-wider text-cyphra-text-muted mb-3">By source</h3>
              <ul className="space-y-2">
                {Object.entries(state.data.by_source).map(([source, count]) => (
                  <li key={source} className="text-xs flex justify-between items-center">
                    <span className="text-cyphra-text-secondary font-mono">{source}</span>
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
