import { useState } from 'react'
import { SocShell, SocLoading, SocError, SocNavBar, StatTile } from '../components/SocShell'
import * as soc from '../services/soc.service'

/**
 * /soc/regression — run the regression harness from the UI.
 *
 * A regression run can take ~30s and emits a JSON verdict with the
 * baseline drift, missing-function list, and pass/fail. The button
 * triggers a POST; the result card stays until the next run.
 */
export default function SocRegressionPage() {
  const [state, setState] = useState({ running: false, data: null, error: null })

  const run = (reset = false) => {
    setState({ running: true, data: null, error: null })
    soc.regression(reset)
      .then(d => setState({ running: false, data: d, error: null }))
      .catch(e => setState({ running: false, data: null, error: e }))
  }

  return (
    <SocShell
      title="Regression"
      subtitle="Run the regression harness and check the baseline drift."
      current="regression"
      actions={
        <>
          <button
            onClick={() => run(false)}
            disabled={state.running}
            className="px-3 py-1.5 rounded text-xs font-medium bg-cyphra-accent text-white hover:bg-cyphra-accent-hover disabled:opacity-50 transition-colors"
          >
            {state.running ? 'Running...' : 'Run'}
          </button>
          <button
            onClick={() => run(true)}
            disabled={state.running}
            className="px-3 py-1.5 rounded text-xs font-medium border border-cyphra-border text-cyphra-text-secondary hover:text-cyphra-text-primary disabled:opacity-50 transition-colors"
          >
            Run + reset baseline
          </button>
        </>
      }
    >
      <SocNavBar current="regression" />
      {state.running ? <SocLoading label="Running regression..." /> :
       state.error ? <SocError error={state.error} /> :
       state.data ? (
        <div>
          <div className="grid grid-cols-4 gap-3 mb-6">
            <StatTile
              label="Passed"
              value={String(state.data.passed)}
              accent={state.data.passed ? 'success' : 'danger'}
            />
            <StatTile label="Events" value={state.data.events} />
            <StatTile label="Incidents" value={state.data.incidents} />
            <StatTile label="Escalations" value={state.data.escalations} />
            <StatTile
              label="Drift within tolerance"
              value={state.data.drift_within_tolerance === null ? 'n/a' : String(state.data.drift_within_tolerance)}
              accent={state.data.drift_within_tolerance ? 'success' : 'danger'}
            />
            <StatTile
              label="Missing functions"
              value={state.data.missing_functions.length}
              accent={state.data.missing_functions.length === 0 ? 'success' : 'danger'}
            />
            <StatTile
              label="Baseline reset"
              value={state.data.baseline_reset ? 'yes' : 'no'}
            />
          </div>
          {state.data.missing_functions.length > 0 && (
            <div className="bg-cyphra-danger-muted border border-cyphra-danger/30 rounded-lg p-4">
              <p className="text-xs uppercase tracking-wider text-cyphra-danger mb-2">Missing functions</p>
              <ul className="text-xs text-cyphra-text-secondary space-y-1">
                {state.data.missing_functions.map(fn => (
                  <li key={fn} className="font-mono">- {fn}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
       ) : (
        <div className="bg-cyphra-surface border border-cyphra-border rounded-lg p-8 text-center">
          <p className="text-sm text-cyphra-text-muted">Click Run to start the regression harness.</p>
        </div>
       )}
    </SocShell>
  )
}
