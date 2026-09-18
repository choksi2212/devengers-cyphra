import { Link } from 'react-router-dom'

/**
 * SocShell — the shared frame for every /soc/* page.
 *
 * Renders the page heading, an optional action bar on the right, and a
 * loading / error / empty state below. Children render the actual content.
 */
export function SocShell({ title, subtitle, actions = null, children }) {
  return (
    <div className="h-full overflow-y-auto bg-cyphra-bg">
      <div className="max-w-6xl mx-auto px-6 py-6">
        <div className="flex items-start justify-between gap-4 mb-6">
          <div>
            <h1 className="text-xl font-semibold text-cyphra-text-primary">{title}</h1>
            {subtitle && (
              <p className="text-xs text-cyphra-text-muted mt-1">{subtitle}</p>
            )}
          </div>
          {actions && <div className="flex items-center gap-2">{actions}</div>}
        </div>
        {children}
      </div>
    </div>
  )
}

/**
 * Loading state used by every SOC page.
 */
export function SocLoading({ label = 'Loading...' }) {
  return (
    <div className="flex items-center justify-center py-12">
      <div className="flex flex-col items-center gap-2">
        <div className="w-6 h-6 border-2 border-cyphra-accent border-t-transparent rounded-full animate-spin" />
        <p className="text-xs text-cyphra-text-muted">{label}</p>
      </div>
    </div>
  )
}

/**
 * Error state — surfaces the raw error message from socctl / the backend.
 */
export function SocError({ error, onRetry }) {
  return (
    <div className="bg-cyphra-danger-muted border border-cyphra-danger/30 rounded-lg p-4">
      <p className="text-sm font-medium text-cyphra-danger mb-1">Failed to load</p>
      <pre className="text-xs text-cyphra-text-secondary whitespace-pre-wrap font-mono">
        {String(error?.message || error)}
      </pre>
      {onRetry && (
        <button
          onClick={onRetry}
          className="mt-3 px-3 py-1.5 rounded text-xs font-medium bg-cyphra-danger/20 text-cyphra-danger hover:bg-cyphra-danger/30 transition-colors"
        >
          Retry
        </button>
      )}
    </div>
  )
}

/**
 * Empty state — used when an endpoint returns nothing to show.
 */
export function SocEmpty({ message = 'No data yet.' }) {
  return (
    <div className="bg-cyphra-surface border border-cyphra-border rounded-lg p-8 text-center">
      <p className="text-sm text-cyphra-text-muted">{message}</p>
    </div>
  )
}

/**
 * StatTile — a small KPI card. Used on the overview and metrics pages.
 */
export function StatTile({ label, value, accent = 'accent' }) {
  const colorMap = {
    accent: 'text-cyphra-accent',
    success: 'text-cyphra-success',
    warning: 'text-cyphra-warning',
    danger: 'text-cyphra-danger',
    text: 'text-cyphra-text-primary',
  }
  return (
    <div className="bg-cyphra-surface border border-cyphra-border rounded-lg p-4">
      <p className="text-[10px] uppercase tracking-wider text-cyphra-text-muted">{label}</p>
      <p className={`mt-1 text-2xl font-semibold ${colorMap[accent] || colorMap.text}`}>
        {value}
      </p>
    </div>
  )
}

/**
 * SocNavBar — secondary nav bar shown above each SOC page's content.
 * Each entry points to one /soc/* page; the active one is highlighted.
 */
export function SocNavBar({ current }) {
  const items = [
    { path: '/soc',             label: 'Overview',   match: 'overview' },
    { path: '/soc/readiness',   label: 'Readiness',  match: 'readiness' },
    { path: '/soc/cases',       label: 'Cases',      match: 'cases' },
    { path: '/soc/crises',      label: 'Crises',     match: 'crises' },
    { path: '/soc/triage',      label: 'Triage',     match: 'triage' },
    { path: '/soc/response',    label: 'Response',   match: 'response' },
    { path: '/soc/metrics',     label: 'Metrics',    match: 'metrics' },
    { path: '/soc/coverage',    label: 'Coverage',   match: 'coverage' },
    { path: '/soc/hunts',       label: 'Hunts',      match: 'hunts' },
    { path: '/soc/intel',       label: 'Intel',      match: 'intel' },
    { path: '/soc/compliance',  label: 'Compliance', match: 'compliance' },
    { path: '/soc/audit',       label: 'Audit',      match: 'audit' },
    { path: '/soc/regression',  label: 'Regression', match: 'regression' },
  ]
  return (
    <nav className="flex items-center gap-1 mb-6 border-b border-cyphra-border overflow-x-auto">
      {items.map((item) => (
        <Link
          key={item.path}
          to={item.path}
          className={`px-3 py-2 text-xs font-medium border-b-2 transition-colors duration-150 whitespace-nowrap ${
            current === item.match
              ? 'border-cyphra-accent text-cyphra-accent'
              : 'border-transparent text-cyphra-text-muted hover:text-cyphra-text-secondary'
          }`}
        >
          {item.label}
        </Link>
      ))}
    </nav>
  )
}
