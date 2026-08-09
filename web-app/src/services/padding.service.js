/**
 * CYPHRA Traffic Padding Service — Real Dummy Traffic Generation
 * ─────────────────────────────────────────────────────────────
 * Generates encrypted dummy messages at a configurable rate.
 * An eavesdropper cannot distinguish real messages from padding —
 * they all appear as identical encrypted WebSocket frames.
 *
 * This prevents traffic analysis (timing attacks that reveal
 * WHEN you communicate, even without reading content).
 */

import veddbService from './veddb.service.js'
import { bytesToHex } from './wasm-bridge.service.js'

class PaddingService {
  constructor() {
    this._timer = null
    this._rate = 0.3        // 30% default (Balanced)
    this._intervalMs = 2000 // Check every 2 seconds
    this._packetsSent = 0
    this._active = false
  }

  /**
   * Start generating dummy traffic
   * @param {number} rate — Probability of sending dummy per interval (0.0 to 1.0)
   * @param {number} intervalMs — How often to check/send (default 2000ms)
   */
  start(rate = 0.3, intervalMs = 2000) {
    this.stop() // Clear any existing timer

    this._rate = Math.max(0, Math.min(1, rate))
    this._intervalMs = intervalMs
    this._active = true

    if (this._rate === 0) {
      console.log('[Padding] Rate is 0% — disabled')
      return
    }

    this._timer = setInterval(() => {
      this._maybeEmitDummy()
    }, this._intervalMs)

    console.log(`[Padding] Started — rate: ${(this._rate * 100).toFixed(0)}%, interval: ${this._intervalMs}ms`)
  }

  /**
   * Stop generating dummy traffic
   */
  stop() {
    if (this._timer) {
      clearInterval(this._timer)
      this._timer = null
    }
    this._active = false
  }

  /**
   * Probabilistically send a dummy encrypted frame
   */
  _maybeEmitDummy() {
    // Roll dice — should we send padding this tick?
    if (Math.random() > this._rate) return

    // Generate random encrypted-looking payload (same size as real messages)
    const dummySize = 128 + Math.floor(Math.random() * 256) // 128-384 bytes
    const dummyBytes = new Uint8Array(dummySize)
    crypto.getRandomValues(dummyBytes)

    const dummyMsg = {
      type: 'padding',
      data: bytesToHex(dummyBytes),
      ts: Date.now(),
      // These fields make it look identical to a real message on the wire
      nonce: bytesToHex(crypto.getRandomValues(new Uint8Array(12))),
    }

    // Send via WebSocket (server ignores 'padding' type — but traffic is real on the wire)
    if (veddbService.ws && veddbService.ws.readyState === WebSocket.OPEN) {
      veddbService.ws.send(JSON.stringify(dummyMsg))
      this._packetsSent++
    }
  }

  /**
   * Get padding status (for UI display)
   */
  getStatus() {
    return {
      active: this._active,
      rate: this._rate,
      ratePercent: Math.round(this._rate * 100),
      intervalMs: this._intervalMs,
      packetsSent: this._packetsSent,
    }
  }

  /**
   * Set rate without restarting
   */
  setRate(rate) {
    this._rate = Math.max(0, Math.min(1, rate))
    if (this._rate === 0 && this._timer) {
      this.stop()
    }
  }
}

export default new PaddingService()
