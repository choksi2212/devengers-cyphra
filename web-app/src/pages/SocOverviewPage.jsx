import { useEffect, useState } from 'react'
import { SocShell, SocLoading, SocError, SocNavBar, StatTile } from '../components/SocShell'
import * as soc from '../services/soc.service'

/**
 * /soc — the operator's landing page.
 *
 * Three sections: credentials (readiness summary), live KPIs
 * (metrics), and coverage (what the SOC actually exercises).
 * Each section loads independently — a slow endpoint only blocks
 * its own card, not the whole page.
 */
export default function SocOverviewPage() {
  const [readiness, setReadiness] = useState({ loading: true, data: null, error: null })
  const [metrics, setMetrics] = useState({ loading: true, data: null, error: null })
  const [coverage, setCoverage] = useState({ loading: true, data: null, error: null })

  useEffect(() => {
    soc.readiness().then(d => setReadiness({ loading: false, data: d }))
      .catch(e => setReadiness({ loading: false, data: null, error: e }))
    soc.metrics().then(d => setMetrics({ loading: false, data: d }))
      .catch(e => setMetrics({ loading: false, data: null, error: e }))
    soc.coverage().then(d => setCoverage({ loading: false, data: d }))
      .catch(e => setCoverage({ loading: false, data: null, error: e }))
  }, [])

  const readinessConfigured = readiness.data
    ? readiness.data.configured.length
    : null
  const readinessTotal = readiness.data?.total ?? null

  return (
    <SocShell
      title="SOC Overview"
      subtitle="Live readiness, KPIs, and coverage from socctl."
      current="overview"
    >
      <SocNavBar current="overview" />

      {/* Readiness */}
      <section className="mb-8">
        <h2 className="text-sm font-medium text-cyphra-text-secondary mb-3">Readiness</h2>
        {readiness.loading ? <SocLoading label="Loading credentials..." /> :
         readiness.error ? <SocError error={readiness.error} /> :
         (
          <div className="grid grid-cols-3 gap-3">
            <StatTile label="Total credentials" value={readinessTotal} />
            <StatTile label="Configured" value={readinessConfigured} accent="success" />
            <StatTile
              label="Awaiting"
              value={readinessTotal - readinessConfigured}
              accent={readinessTotal - readinessConfigured === 0 ? 'success' : 'warning'}
            />
          </div>
         )}
      </section>

      {/* Metrics */}
      <section className="mb-8">
        <h2 className="text-sm font-medium text-cyphra-text-secondary mb-3">Metrics</h2>
        {metrics.loading ? <SocLoading label="Loading metrics..." /> :
         metrics.error ? <SocError error={metrics.error} /> :
         (
          <div className="grid grid-cols-4 gap-3">
            <StatTile label="Alert volume"   value={metrics.data.alert_volume} />
            <StatTile label="Incidents"      value={metrics.data.incident_count} />
            <StatTile label="MTTD (s)"       value={metrics.data.mttd_seconds.toFixed(3)} accent="text" />
            <StatTile label="MTTR (s)"       value={metrics.data.mttr_seconds.toFixed(3)} accent="text" />
            <StatTile label="False-positive" value={(metrics.data.false_positive_rate * 100).toFixed(1) + '%'} />
            <StatTile label="True-positive"  value={(metrics.data.true_positive_rate * 100).toFixed(1) + '%'} accent="success" />
            <StatTile label="Escalation"     value={(metrics.data.escalation_rate * 100).toFixed(1) + '%'} />
            <StatTile label="Verdicts"       value={Object.values(metrics.data.verdict_counts || {}).reduce((a, b) => a + b, 0)} />
          </div>
         )}
      </section>

      {/* Coverage */}
      <section className="mb-8">
        <h2 className="text-sm font-medium text-cyphra-text-secondary mb-3">Coverage</h2>
        {coverage.loading ? <SocLoading label="Loading coverage..." /> :
         coverage.error ? <SocError error={coverage.error} /> :
         (
          <div className="grid grid-cols-3 gap-3">
            <StatTile label="Functions" value={coverage.data.rows.length} />
            <StatTile
              label="Missing"
              value={coverage.data.missing.length}
              accent={coverage.data.missing.length === 0 ? 'success' : 'danger'}
            />
            <StatTile label="Fragile (1 scenario)" value={coverage.data.fragile.length} accent="warning" />
          </div>
         )}
      </section>
    </SocShell>
  )
}
