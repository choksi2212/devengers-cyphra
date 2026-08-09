/**
 * VedDB Service — Backend Service
 * ─────────────────────────────────────────────────────────────
 * Uses veddb-client.exe (the official Rust CLI) as a subprocess to
 * communicate with veddb-server.exe.
 *
 * This is the only reliable approach because veddb-server.exe uses a
 * custom binary/framed Rust Tokio protocol, NOT a simple JSON-over-TCP
 * format. The official Rust client is the only compatible implementation.
 *
 * Falls back to an in-memory store if the VedDB server is not running.
 */

import { execFile } from 'child_process'
import { promisify } from 'util'
import path from 'path'
import { config } from '../config.js'

const execFileAsync = promisify(execFile)

// veddb-client.exe sits in the "WEB VERSION" folder (one level above backend/)
// process.cwd() is "WEB VERSION/backend" when server is started from that dir
const VEDDB_CLI = path.resolve(process.cwd(), '..', 'veddb-client.exe')

// ── In-memory fallback store ──────────────────────────────────────────────
const _memStore = new Map()

// ── CLI runner ────────────────────────────────────────────────────────────

// Strip ANSI color codes + veddb-client INFO/ERROR log lines from stdout.
// The CLI writes connection logs to stdout (not stderr), so we must remove them
// before parsing the actual key:value response line.
function cleanOutput(raw) {
  // Remove ANSI escape codes
  const noAnsi = raw.replace(/\x1b\[[0-9;]*m/g, '')
  // Remove log lines: lines starting with a timestamp like "2026-..."
  const lines = noAnsi.split('\n').filter(l => {
    const t = l.trim()
    return t && !t.match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/)
  })
  return lines.join('\n').trim()
}

async function cli(...args) {
  const server = `${config.veddb.host}:${config.veddb.port}`
  const { stdout } = await execFileAsync(
    VEDDB_CLI,
    ['--server', server, ...args],
    { timeout: config.veddb.requestTimeout || 8000 }
  )
  return cleanOutput(stdout)
}

// ── VedDB Client (CLI-backed) ─────────────────────────────────────────────

class VedDBClient {
  constructor() {
    this._usingFallback = false
    this._connected = false
  }

  async ping() {
    if (this._usingFallback) return true
    try {
      // SET always prints "Set 'key' to 'value'" on success — reliable connectivity probe
      const out = await cli('example', '__cyphra_ping__', '__pong__')
      return out.includes('Set') || out.includes('__cyphra_ping__')
    } catch {
      return false
    }
  }

  async setString(key, value) {
    if (this._usingFallback) { _memStore.set(key, value); return }
    await cli('example', key, value)
  }

  async getString(key) {
    if (this._usingFallback) return _memStore.get(key) ?? null
    try {
      const out = await cli('example', key)
      // Output format: "key: value" on success, "Error getting 'key': ..." on miss
      if (!out || out.startsWith('Error getting')) return null
      // Strip the "key: " prefix — everything after the first ": "
      const colonIdx = out.indexOf(': ')
      if (colonIdx === -1) return null
      return out.slice(colonIdx + 2).trim()
    } catch {
      return null
    }
  }

  async delete(key) {
    if (this._usingFallback) { _memStore.delete(key); return }
    // No explicit delete in the CLI example subcommand – use empty-string set as tombstone
    // and handle null on read; VedDB keys need to be managed via the example subcommand
    try { await cli('example', key, '\x00DEL\x00') } catch { /* best effort */ }
  }

  async listKeys() {
    if (this._usingFallback) return Array.from(_memStore.keys())
    // CLI doesn't expose KEYS, return empty (metadata not needed for auth flow)
    return []
  }

  getPoolStats() {
    return {
      poolSize: 1,
      host: config.veddb.host,
      port: config.veddb.port,
      mode: this._usingFallback ? 'in-memory-fallback' : 'veddb-cli',
      connected: this._connected
    }
  }

  async close() { this._connected = false }
}

// ── VedDB Service ─────────────────────────────────────────────────────────

export class VedDBService {
  constructor() {
    this.client = null
    this.connected = false
  }

  async init() {
    const { host, port } = config.veddb
    const client = new VedDBClient()

    const alive = await client.ping().catch(() => false)

    if (alive) {
      client._connected = true
      client._usingFallback = false
      this.connected = true
      console.log(`✓ VedDB connected at ${host}:${port} (CLI mode)`)
    } else {
      client._usingFallback = true
      client._connected = true
      this.connected = true
      console.warn(`⚠️  VedDB server not reachable at ${host}:${port} — using in-memory fallback`)
      console.warn(`    Start veddb-server.exe to persist data across sessions.`)
    }

    this.client = client
    return true
  }

  isConnected() { return this.connected }

  async set(key, value) {
    this._requireConnected()
    await this.client.setString(key, JSON.stringify(value))
    return { success: true }
  }

  async get(key) {
    this._requireConnected()
    const raw = await this.client.getString(key)
    if (raw === null) return null
    if (raw === '\x00DEL\x00') return null  // tombstone from delete
    try { return JSON.parse(raw) } catch { return raw }
  }

  async delete(key) {
    this._requireConnected()
    await this.client.delete(key)
    return { success: true }
  }

  async listKeys() {
    this._requireConnected()
    return this.client.listKeys()
  }

  async ping() {
    this._requireConnected()
    const ok = await this.client.ping()
    return { success: ok, timestamp: Date.now() }
  }

  getStats() {
    return this.client?.getPoolStats() ?? null
  }

  async close() {
    if (this.client) {
      await this.client.close()
      this.connected = false
    }
  }

  _requireConnected() {
    if (!this.connected) throw new Error('VedDB not initialized — call init() first')
  }
}
