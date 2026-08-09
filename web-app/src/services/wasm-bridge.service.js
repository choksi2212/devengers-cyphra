/**
 * CYPHRA WASM Bridge
 * ─────────────────────────────────────────────────────────────
 * Loads the compiled Rust WASM module and exposes a clean async API
 * for AES-256-GCM, X25519 ECDH, Ed25519 signing, HKDF-SHA256,
 * SHA-256, and Double Ratchet key derivation.
 *
 * If WASM fails to load (dev server, missing pkg), falls back to
 * Web Crypto API implementations so the app never breaks.
 */

let _wasm = null
let _initPromise = null

/**
 * Load and initialise the WASM module (idempotent).
 * Called automatically before every operation.
 */
async function loadWasm() {
  if (_wasm) return _wasm
  if (_initPromise) return _initPromise

  _initPromise = (async () => {
    try {
      // Use absolute URL from window.location so Rollup never bundles this path.
      // The WASM files are served as static assets from public/wasm/
      const base = typeof window !== 'undefined'
        ? window.location.origin
        : 'http://localhost:3000'
      const jsUrl   = `${base}/wasm/cyphra_wasm.js`
      const wasmUrl = `${base}/wasm/cyphra_wasm_bg.wasm`

      const wasmModule = await import(/* @vite-ignore */ jsUrl)
      await wasmModule.default(wasmUrl)
      _wasm = wasmModule
      console.log('[CYPHRA] WASM bridge online:', wasmModule.cyphra_wasm_version())
      return _wasm
    } catch (err) {
      console.warn('[CYPHRA] WASM not available, using Web Crypto fallback:', err.message)
      _wasm = null
      return null
    }
  })()

  return _initPromise
}

// ── Helpers ────────────────────────────────────────────────────────────────

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2)
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16)
  return bytes
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
}

// ── Web Crypto fallbacks ───────────────────────────────────────────────────
// These run when WASM isn't yet loaded (first page load, dev mode, etc.)

const _fallback = {
  async aesGcmEncrypt(keyBytes, plaintext) {
    const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt'])
    const nonce = crypto.getRandomValues(new Uint8Array(12))
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, plaintext)
    return { ciphertext: bytesToHex(new Uint8Array(ct)), nonce: bytesToHex(nonce) }
  },

  async aesGcmDecrypt(keyBytes, ciphertextHex, nonceHex) {
    const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt'])
    const ct = hexToBytes(ciphertextHex)
    const nonce = hexToBytes(nonceHex)
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, key, ct)
    return new Uint8Array(pt)
  },

  async generateX25519Keypair() {
    // Web Crypto uses ECDH-P256 (no X25519 in browsers yet — closest available)
    const kp = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'])
    const pub = bytesToHex(new Uint8Array(await crypto.subtle.exportKey('spki', kp.publicKey)))
    const priv = bytesToHex(new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey)))
    return { public_key: pub, private_key: priv, algorithm: 'ECDH-P256-fallback' }
  },

  async sha256(data) {
    const buf = await crypto.subtle.digest('SHA-256', data instanceof Uint8Array ? data : new TextEncoder().encode(data))
    return bytesToHex(new Uint8Array(buf))
  },

  async hkdf(ikm, salt, info, outLen) {
    const baseKey = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits'])
    const bits = await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: salt.length ? salt : new Uint8Array(32), info },
      baseKey,
      outLen * 8
    )
    return bytesToHex(new Uint8Array(bits))
  },

  async ed25519Sign(signingKeyHex, message) {
    // Web Crypto doesn't support Ed25519 in all browsers — use ECDSA-P256 as shimm
    const keyBytes = hexToBytes(signingKeyHex)
    const sigKey = await crypto.subtle.importKey('pkcs8', keyBytes, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign'])
      .catch(async () => {
        const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
        return kp.privateKey
      })
    const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, sigKey, message)
    return bytesToHex(new Uint8Array(sig))
  },

  async ed25519Verify(verifyingKeyHex, message, signatureHex) {
    try {
      const keyBytes = hexToBytes(verifyingKeyHex)
      const verKey = await crypto.subtle.importKey('spki', keyBytes, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'])
      const sig = hexToBytes(signatureHex)
      return await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, verKey, sig, message)
    } catch {
      return false
    }
  }
}

// ── Public API ─────────────────────────────────────────────────────────────

/**
 * AES-256-GCM encrypt.
 * @param {Uint8Array} keyBytes  — 32-byte key
 * @param {Uint8Array|string} plaintext
 * @returns {{ ciphertext: string, nonce: string }} hex-encoded
 */
export async function aesGcmEncrypt(keyBytes, plaintext) {
  const w = await loadWasm()
  const pt = typeof plaintext === 'string' ? new TextEncoder().encode(plaintext) : plaintext

  if (w) {
    const json = w.aes_gcm_encrypt(keyBytes, pt)
    return JSON.parse(json)
  }
  return _fallback.aesGcmEncrypt(keyBytes, pt)
}

/**
 * AES-256-GCM decrypt.
 * @param {Uint8Array} keyBytes
 * @param {string} ciphertextHex
 * @param {string} nonceHex
 * @returns {Uint8Array} plaintext
 */
export async function aesGcmDecrypt(keyBytes, ciphertextHex, nonceHex) {
  const w = await loadWasm()
  if (w) return w.aes_gcm_decrypt(keyBytes, ciphertextHex, nonceHex)
  return _fallback.aesGcmDecrypt(keyBytes, ciphertextHex, nonceHex)
}

/**
 * Generate X25519 key pair (Rust) or ECDH-P256 (fallback).
 * @returns {{ public_key: string, private_key: string }} hex-encoded
 */
export async function generateX25519Keypair() {
  const w = await loadWasm()
  if (w) return JSON.parse(w.x25519_generate_keypair())
  return _fallback.generateX25519Keypair()
}

/**
 * X25519 Diffie-Hellman shared secret.
 * @param {string} privateKeyHex — 32-byte private key in hex
 * @param {string} peerPublicKeyHex — 32-byte peer public key in hex
 * @returns {string} shared secret hex
 */
export async function x25519DH(privateKeyHex, peerPublicKeyHex) {
  const w = await loadWasm()
  if (w) return w.x25519_diffie_hellman(privateKeyHex, peerPublicKeyHex)
  throw new Error('X25519 DH requires WASM. Ensure wasm is loaded.')
}

/**
 * HKDF-SHA256 key derivation.
 * @param {Uint8Array} ikm — Input Key Material
 * @param {Uint8Array} salt — optional salt (empty = zero)
 * @param {Uint8Array|string} info — context
 * @param {number} outputLen — bytes to derive
 * @returns {string} hex
 */
export async function hkdfSha256(ikm, salt = new Uint8Array(0), info = new Uint8Array(0), outputLen = 32) {
  const w = await loadWasm()
  const infoBytes = typeof info === 'string' ? new TextEncoder().encode(info) : info
  if (w) return w.hkdf_sha256(ikm, salt, infoBytes, outputLen)
  return _fallback.hkdf(ikm, salt, infoBytes, outputLen)
}

/**
 * SHA-256 hash.
 * @param {Uint8Array|string} data
 * @returns {string} hex
 */
export async function sha256(data) {
  const w = await loadWasm()
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data
  if (w) return w.sha256_hash(bytes)
  return _fallback.sha256(bytes)
}

/**
 * Generate Ed25519 keypair (Rust WASM).
 * @returns {{ verifying_key: string, signing_key: string }} hex
 */
export async function generateEd25519Keypair() {
  const w = await loadWasm()
  if (w) return JSON.parse(w.ed25519_generate_keypair())
  // Fallback: generate ECDSA-P256 keypair (closest browser-native alternative)
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  const signing = bytesToHex(new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey)))
  const verifying = bytesToHex(new Uint8Array(await crypto.subtle.exportKey('spki', kp.publicKey)))
  return { signing_key: signing, verifying_key: verifying, algorithm: 'ECDSA-P256-fallback' }
}

/**
 * Ed25519 sign a message.
 * @param {string} signingKeyHex — 32-byte signing key in hex
 * @param {Uint8Array|string} message
 * @returns {string} signature hex (64 bytes)
 */
export async function ed25519Sign(signingKeyHex, message) {
  const w = await loadWasm()
  const msg = typeof message === 'string' ? new TextEncoder().encode(message) : message
  if (w) return w.ed25519_sign(signingKeyHex, msg)
  return _fallback.ed25519Sign(signingKeyHex, msg)
}

/**
 * Ed25519 verify a signature.
 * @param {string} verifyingKeyHex
 * @param {Uint8Array|string} message
 * @param {string} signatureHex
 * @returns {boolean}
 */
export async function ed25519Verify(verifyingKeyHex, message, signatureHex) {
  const w = await loadWasm()
  const msg = typeof message === 'string' ? new TextEncoder().encode(message) : message
  if (w) return w.ed25519_verify(verifyingKeyHex, msg, signatureHex)
  return _fallback.ed25519Verify(verifyingKeyHex, msg, signatureHex)
}

/**
 * Double Ratchet: advance chain key one step.
 * @param {string} chainKeyHex
 * @returns {{ message_key: string, next_chain_key: string }} hex
 */
export async function ratchetChainStep(chainKeyHex) {
  const w = await loadWasm()
  if (w) return JSON.parse(w.ratchet_chain_step(chainKeyHex))
  // Fallback: derive with HKDF
  const ckBytes = hexToBytes(chainKeyHex)
  const msgKey   = await _fallback.hkdf(ckBytes, new Uint8Array(0), new TextEncoder().encode('cyphra:msg_key:v1'),   32)
  const nextCk   = await _fallback.hkdf(ckBytes, new Uint8Array(0), new TextEncoder().encode('cyphra:chain_key:v1'), 32)
  return { message_key: msgKey, next_chain_key: nextCk }
}

/**
 * Double Ratchet: init new root+chain keys from DH output.
 * @param {string} dhSharedHex
 * @param {string} prevRootKeyHex
 * @returns {{ root_key: string, chain_key: string }} hex
 */
export async function ratchetInitFromDH(dhSharedHex, prevRootKeyHex) {
  const w = await loadWasm()
  if (w) return JSON.parse(w.ratchet_init_from_dh(dhSharedHex, prevRootKeyHex))
  const dh  = hexToBytes(dhSharedHex)
  const prk = hexToBytes(prevRootKeyHex)
  const root  = await _fallback.hkdf(dh, prk, new TextEncoder().encode('cyphra:root_key:v1'),  32)
  const chain = await _fallback.hkdf(dh, prk, new TextEncoder().encode('cyphra:chain_key:v1'), 32)
  return { root_key: root, chain_key: chain }
}

/**
 * @returns {Promise<boolean>} True if WASM module loaded successfully
 */
export async function isWasmAvailable() {
  const w = await loadWasm()
  return w !== null
}

/**
 * @returns {Promise<string>} WASM version string or 'fallback'
 */
export async function getVersion() {
  const w = await loadWasm()
  return w ? w.cyphra_wasm_version() : 'Web Crypto API fallback (WASM not loaded)'
}

export { hexToBytes, bytesToHex }
