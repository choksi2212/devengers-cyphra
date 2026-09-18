/**
 * SOC Service (Frontend)
 * ─────────────────────────────────────────────────────────────────────────────
 * Thin client over the backend's /api/soc/* routes. Every method returns
 * the parsed JSON the backend produced from `python -m socctl <cmd> --json`.
 *
 * The backend (backend/services/soc.service.js) shells out to socctl and
 * returns 502 with the raw stderr if the call fails — so the frontend
 * surfaces that error message verbatim instead of inventing one.
 */

const BASE = '/api/soc'

async function getJson(path) {
  const res = await fetch(`${BASE}${path}`)
  if (!res.ok) {
    let detail = ''
    try {
      const body = await res.json()
      detail = body.error || ''
    } catch (_) {}
    throw new Error(
      detail || `SOC endpoint failed: ${res.status} ${res.statusText}`
    )
  }
  return res.json()
}

async function postJson(path) {
  const res = await fetch(`${BASE}${path}`, { method: 'POST' })
  if (!res.ok) {
    let detail = ''
    try {
      const body = await res.json()
      detail = body.error || ''
    } catch (_) {}
    throw new Error(
      detail || `SOC endpoint failed: ${res.status} ${res.statusText}`
    )
  }
  return res.json()
}

export async function readiness() {
  return getJson('/readiness')
}

export async function metrics() {
  return getJson('/metrics')
}

export async function coverage() {
  return getJson('/coverage')
}

export async function cases(all = false) {
  return getJson(`/cases${all ? '?all=1' : ''}`)
}

export async function crises(all = false) {
  return getJson(`/crises${all ? '?all=1' : ''}`)
}

export async function hunts(run = false) {
  return getJson(`/hunts${run ? '?run=1' : ''}`)
}

export async function intel() {
  return getJson('/intel')
}

export async function regression(reset = false) {
  return postJson(`/regression${reset ? '?reset=1' : ''}`)
}
