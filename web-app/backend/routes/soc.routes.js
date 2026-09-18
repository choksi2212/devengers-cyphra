/**
 * SOC Routes — operator dashboard endpoints.
 *
 * Every endpoint is a thin pass-through to the socctl CLI; the work
 * happens in `services/soc.service.js`. The response shape matches
 * what the frontend components expect (so changes on one side must
 * match the other).
 *
 *   GET /api/soc/readiness              → { total, configured, unset, config_path }
 *   GET /api/soc/metrics                → { alert_volume, mttd_seconds, ... }
 *   GET /api/soc/coverage               → { rows, missing, fragile }
 *   GET /api/soc/cases?all=1            → { cases: [...] }
 *   GET /api/soc/crises?all=1           → { crises: [...] }
 *   GET /api/soc/hunts?run=1            → { registered, runs }
 *   GET /api/soc/intel                  → { indicators_loaded, by_source }
 *   POST /api/soc/regression?reset=1    → { passed, events, ... }
 */

import * as soc from '../services/soc.service.js'

/**
 * Wrap an async handler so a thrown error becomes a 502 JSON.
 */
function route(handler) {
  return async (req, res) => {
    try {
      const payload = await handler(req)
      res.json(payload)
    } catch (err) {
      console.error('[soc route]', err.message)
      res.status(502).json({
        error: err.message,
        exitCode: err.exitCode ?? null,
      })
    }
  }
}

export function setupSocRoutes(app) {
  app.get('/api/soc/readiness',   route(() => soc.readiness()))
  app.get('/api/soc/metrics',     route(() => soc.metrics()))
  app.get('/api/soc/coverage',    route(() => soc.coverage()))
  app.get('/api/soc/cases',       route((req) => soc.cases(req.query.all === '1')))
  app.get('/api/soc/crises',      route((req) => soc.crises(req.query.all === '1')))
  app.get('/api/soc/hunts',       route((req) => soc.hunts(req.query.run === '1')))
  app.get('/api/soc/intel',       route(() => soc.intel()))
  app.post(
    '/api/soc/regression',
    route((req) => soc.regression(req.query.reset === '1'))
  )
}
