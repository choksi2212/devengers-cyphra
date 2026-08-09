/**
 * CYPHRA Mixnet Service — Real Multi-Hop Onion Routing
 * ─────────────────────────────────────────────────────────────
 * Messages pass through N independent relay nodes before reaching
 * the recipient. Each relay decrypts one layer and forwards to the
 * next hop. No single relay knows both sender AND recipient.
 *
 * Relay topology:
 *   Sender → Relay 1 (:6001) → Relay 2 (:6002) → ... → Backend (:3001)
 *
 * Each relay has a unique AES-256-GCM key. The sender wraps the message
 * in N layers of encryption (onion). Each relay peels one layer.
 */

import { aesGcmEncrypt, aesGcmDecrypt, hexToBytes, bytesToHex } from './wasm-bridge.service.js'

// ── Relay Configuration ──────────────────────────────────────────────────────
// Each relay has a pre-shared 256-bit key (in production these would be
// exchanged via X3DH or Kyber — here they're derived deterministically
// from the relay index for reproducibility)
const RELAY_PORTS = [6001, 6002, 6003, 6004, 6005]

// Derive relay keys deterministically (same on sender + relay side)
function deriveRelayKey(relayIndex) {
  const seed = new Uint8Array(32)
  const view = new DataView(seed.buffer)
  // Deterministic derivation: SHA-256("cyphra:relay:{index}") would be ideal
  // For simplicity: fill with index-based pattern
  for (let i = 0; i < 32; i++) {
    seed[i] = ((relayIndex + 1) * 37 + i * 13) & 0xFF
  }
  return seed
}

const RELAY_KEYS = RELAY_PORTS.map((_, i) => deriveRelayKey(i))

class MixnetService {
  constructor() {
    this._hops = 2  // default: balanced (2 hops)
    this._enabled = true
    this._baseUrl = ''
  }

  /**
   * Set the number of mix hops (1 = direct, 2-5 = relay chain)
   */
  setHops(count) {
    this._hops = Math.max(1, Math.min(5, count))
    console.log(`[Mixnet] Path length set to ${this._hops} hops`)
  }

  getHops() {
    return this._hops
  }

  /**
   * Set the base URL for relay access
   */
  setBaseUrl(url) {
    this._baseUrl = url || `http://${window.location.hostname}`
  }

  /**
   * Send a message through the mixnet (onion-encrypted multi-hop)
   * @param {object} message — the message payload to deliver
   * @param {string} recipientId — final recipient's user ID
   * @returns {object} — { delivered, hops, latencyMs }
   */
  async sendThroughMix(message, recipientId) {
    const startTime = performance.now()

    if (this._hops <= 1) {
      // Direct path — no mix routing (Secure Base preset)
      return { delivered: true, hops: 1, mode: 'direct', latencyMs: 0 }
    }

    const baseUrl = this._baseUrl || `http://${window.location.hostname}`
    const hopCount = Math.min(this._hops, RELAY_PORTS.length)
    const relays = RELAY_PORTS.slice(0, hopCount)

    try {
      // Build the onion: wrap message in N layers (innermost = last relay)
      let payload = JSON.stringify({
        nextHop: `${baseUrl}:3001/api/mix/deliver`,
        payload: { recipientId, message, timestamp: Date.now() }
      })

      // Wrap layers from inside out
      for (let i = hopCount - 1; i >= 0; i--) {
        const key = RELAY_KEYS[i]
        const plainBytes = new TextEncoder().encode(payload)
        const encrypted = await aesGcmEncrypt(key, plainBytes)
        // encrypted = { ciphertext: hex, nonce: hex }

        const nextHop = i < hopCount - 1
          ? `${baseUrl}:${relays[i + 1]}/relay`
          : `${baseUrl}:3001/api/mix/deliver`

        payload = JSON.stringify({
          nextHop,
          ciphertext: encrypted.ciphertext,
          nonce: encrypted.nonce,
        })
      }

      // Send to first relay
      const firstRelayUrl = `${baseUrl}:${relays[0]}/relay`
      const response = await fetch(firstRelayUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: payload,
        signal: AbortSignal.timeout(15000),
      })

      const latencyMs = Math.round(performance.now() - startTime)

      if (response.ok) {
        console.log(`[Mixnet] Message routed through ${hopCount} relays (${latencyMs}ms)`)
        return { delivered: true, hops: hopCount, mode: 'onion', latencyMs }
      } else {
        console.warn(`[Mixnet] Relay returned ${response.status} — falling back to direct`)
        return { delivered: false, hops: hopCount, mode: 'fallback', latencyMs }
      }
    } catch (e) {
      console.warn(`[Mixnet] Relay chain failed (${e.message}) — using direct delivery`)
      return { delivered: false, hops: hopCount, mode: 'fallback', latencyMs: Math.round(performance.now() - startTime) }
    }
  }

  /**
   * Get current mixnet status (for UI display)
   */
  getStatus() {
    return {
      enabled: this._enabled,
      hops: this._hops,
      relayPorts: RELAY_PORTS.slice(0, this._hops),
      mode: this._hops <= 1 ? 'direct' : 'onion',
    }
  }
}

export default new MixnetService()
export { RELAY_KEYS, RELAY_PORTS, deriveRelayKey }
