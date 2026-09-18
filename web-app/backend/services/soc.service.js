/**
 * SOC service — thin wrapper around the `socctl` CLI.
 *
 * Every endpoint shells out to `python -m socctl <subcommand> --json`
 * with cwd set to the SOC root and parses the JSON output. Errors
 * from socctl (non-zero exit, malformed JSON) are surfaced to the
 * caller as a 502 with the raw stderr attached — the operator
 * dashboard shows that exact text in its error toast.
 *
 * The python path and SOC root come from environment variables so
 * the same code works in dev (Windows, git-bash) and in a Linux
 * container. The defaults match the verified environment.
 */

import { execFile } from 'child_process'
import { promisify } from 'util'

const execFileAsync = promisify(execFile)

const SOC_PYTHON = process.env.SOC_PYTHON || 'C:\\Program Files\\Python311\\python.exe'
const SOC_ROOT = process.env.SOC_ROOT || 'N:\\craftathon\\cyphra-soc'
const PYTHONIOENCODING = 'utf-8'

/**
 * Run a socctl subcommand with --json and parse the result.
 *
 * @param {string} subcommand e.g. "readiness", "metrics", "cases"
 * @param {string[]} extraArgs additional args (--all, --reset, --run, etc.)
 * @returns {Promise<object>} the parsed JSON payload
 */
export async function runSocctl(subcommand, extraArgs = []) {
  const args = ['-m', 'socctl', subcommand, '--json', ...extraArgs]
  let stdout
  let stderr
  try {
    const result = await execFileAsync(SOC_PYTHON, args, {
      cwd: SOC_ROOT,
      env: { ...process.env, PYTHONIOENCODING, PYTHONUNBUFFERED: '1' },
      maxBuffer: 32 * 1024 * 1024,
      timeout: 60_000,
    })
    stdout = result.stdout
    stderr = result.stderr
  } catch (err) {
    // socctl prints useful errors to stderr and exits non-zero.
    // Surface that to the caller; the frontend toast renders it.
    const message = err.stderr || err.message || 'socctl failed'
    const error = new Error(message.trim())
    error.exitCode = err.code || null
    throw error
  }
  const text = stdout.trim()
  if (!text) {
    throw new Error(`socctl ${subcommand} produced empty output (stderr: ${stderr || ''})`)
  }
  try {
    return JSON.parse(text)
  } catch (err) {
    throw new Error(
      `socctl ${subcommand} returned non-JSON: ${text.slice(0, 200)}...`
    )
  }
}

/**
 * Read the readiness report. Returns `{ total, configured, unset, config_path }`.
 */
export const readiness = () => runSocctl('readiness')

/**
 * Read the metrics snapshot. Returns MTTD/MTTR/FPR/etc.
 */
export const metrics = () => runSocctl('metrics')

/**
 * Read the coverage matrix.
 */
export const coverage = () => runSocctl('coverage')

/**
 * List cases.
 * @param {boolean} all include closed and archived
 */
export const cases = (all = false) => runSocctl('cases', all ? ['--all'] : [])

/**
 * List crises.
 * @param {boolean} all include contained and closed
 */
export const crises = (all = false) => runSocctl('crises', all ? ['--all'] : [])

/**
 * List hunts, optionally running each against an empty stream.
 * @param {boolean} run also execute each hunt
 */
export const hunts = (run = false) => runSocctl('hunts', run ? ['--run'] : [])

/**
 * Read intel-store stats.
 */
export const intel = () => runSocctl('intel')

/**
 * Run the regression harness.
 * @param {boolean} reset reset the persisted baseline
 */
export const regression = (reset = false) =>
  runSocctl('regression', reset ? ['--reset'] : [])
