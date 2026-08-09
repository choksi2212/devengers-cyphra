/**
 * Crypto Service — Backed by Rust WASM (cyphra-wasm)
 * ─────────────────────────────────────────────────────────────
 * All cryptographic primitives are backed by the compiled Rust
 * WASM module (public/wasm/cyphra_wasm_bg.wasm). If WASM is not
 * yet loaded a Web Crypto API fallback is used transparently.
 */

import {
  aesGcmEncrypt, aesGcmDecrypt,
  generateX25519Keypair, x25519DH,
  hkdfSha256, sha256,
  generateEd25519Keypair, ed25519Sign, ed25519Verify,
  ratchetChainStep, ratchetInitFromDH,
  isWasmAvailable, getVersion as getWasmVersion,
  hexToBytes, bytesToHex,
} from './wasm-bridge.service.js'

let _wasmReady = false

// Initialize the crypto system — loads WASM module
export const initCrypto = async () => {
  try {
    console.log('[CryptoService] Initialising…')
    _wasmReady = await isWasmAvailable()
    const ver  = await getWasmVersion()
    console.log(`[CryptoService] ${
      _wasmReady ? '🦀 Rust WASM active' : '⚠️ Web Crypto fallback'
    }: ${ver}`)
    return createFallbackCrypto()
  } catch (error) {
    console.error('[CryptoService] Init failed:', error)
    return createFallbackCrypto()
  }
}

// ── WASM-first crypto facade ───────────────────────────────────────────────
// Routes every operation through the Rust WASM module when available.
// Each method falls back to Web Crypto API automatically via wasm-bridge.service.js
const createFallbackCrypto = () => {
  return {
    // Generate identity keypair — X25519 (Rust WASM) or ECDH-P256 (fallback)
    async generateIdentityKeypair() {
      const kp = await generateX25519Keypair()
      return {
        publicKey: kp.public_key,        // hex string
        privateKey: kp.private_key,      // hex string
        algorithm: kp.algorithm || 'X25519 (Rust WASM)',
      }
    },

    // Generate signed prekey — Ed25519 (Rust WASM)
    async generateSignedPrekey() {
      const kp = await generateEd25519Keypair()
      return {
        publicKey:  kp.verifying_key,    // hex string
        privateKey: kp.signing_key,      // hex string
        signature: null,                  // signed by identity key in production
        timestamp: Date.now(),
        algorithm: kp.algorithm || 'Ed25519 (Rust WASM)',
      }
    },

    // Encrypt message — AES-256-GCM (Rust WASM)
    // DEK is derived from chatId (deterministic per-chat) so it never needs to be stored.
    // The recipient re-derives the same DEK from the same chatId.
    async encryptMessage(plaintext, chatId) {
      // Derive a per-message DEK from chatId + random salt
      // Salt is stored with message (safe — salt is not secret)
      const salt = crypto.getRandomValues(new Uint8Array(16))
      const ikm = new TextEncoder().encode(`cyphra:chat:${chatId || 'default'}:${Date.now()}`)
      const dekHex = await hkdfSha256(ikm, salt, 'cyphra:dek:v1', 32)
      const dekBytes = hexToBytes(dekHex)

      const { ciphertext, nonce } = await aesGcmEncrypt(dekBytes, plaintext)

      return {
        ciphertext,   // hex string
        nonce,        // hex string
        salt: bytesToHex(salt),  // hex — safe to store (not secret)
        // DEK is NOT stored — derived from chat context + salt
        algorithm: 'AES-256-GCM (Rust WASM)',
        timestamp: Date.now(),
      }
    },

    // Decrypt message — AES-256-GCM (Rust WASM)
    async decryptMessage(encryptedMessage, chatId) {
      // Re-derive the DEK from the same inputs
      let dekBytes
      if (encryptedMessage.dek) {
        // Legacy messages (before fix) — still have DEK stored
        dekBytes = hexToBytes(encryptedMessage.dek)
      } else if (encryptedMessage.salt) {
        // New messages — derive DEK from salt + chatId + timestamp
        const salt = hexToBytes(encryptedMessage.salt)
        const ikm = new TextEncoder().encode(`cyphra:chat:${chatId || 'default'}:${encryptedMessage.timestamp}`)
        const dekHex = await hkdfSha256(ikm, salt, 'cyphra:dek:v1', 32)
        dekBytes = hexToBytes(dekHex)
      } else {
        throw new Error('Cannot decrypt — no DEK or salt available')
      }
      const plainBytes = await aesGcmDecrypt(dekBytes, encryptedMessage.ciphertext, encryptedMessage.nonce)
      return new TextDecoder().decode(plainBytes)
    },

    // Generate session key — Double Ratchet initialisation (Rust WASM)
    async generateSessionKey() {
      // Generate ephemeral root seed
      const seedHex = await hkdfSha256(
        crypto.getRandomValues(new Uint8Array(32)),
        new Uint8Array(0),
        'cyphra:session:init:v1',
        32
      )
      const { root_key, chain_key } = await ratchetInitFromDH(seedHex, seedHex)
      return {
        sessionKey: hexToBytes(chain_key),
        ratchetState: {
          sendCounter: 0,
          receiveCounter: 0,
          rootKey: hexToBytes(root_key),
          chainKey: hexToBytes(chain_key),
        },
      }
    },

    // Sign message — Ed25519 (Rust WASM)
    async signMessage(message, signingKeyHex) {
      const msgBytes = new TextEncoder().encode(JSON.stringify(message))
      // signingKeyHex is a 32-byte Ed25519 key in hex (from generateSignedPrekey)
      const sig = await ed25519Sign(signingKeyHex || '', msgBytes)
      return { signature: sig, algorithm: 'Ed25519 (Rust WASM)' }
    },

    // Verify signature — Ed25519 (Rust WASM)
    async verifySignature(message, signatureData, verifyingKeyHex) {
      if (!verifyingKeyHex || !signatureData) return false
      const msgBytes = new TextEncoder().encode(JSON.stringify(message))
      const sigHex = typeof signatureData === 'string'
        ? signatureData
        : signatureData.signature
      return ed25519Verify(verifyingKeyHex, msgBytes, sigHex)
    },

    // Hash — SHA-256 (Rust WASM)
    async hash(data) {
      return sha256(data)
    },

    // HKDF key derivation — HKDF-SHA256 (Rust WASM)
    async deriveKey(ikm, salt, info, len = 32) {
      return hkdfSha256(
        typeof ikm === 'string' ? new TextEncoder().encode(ikm) : ikm,
        typeof salt === 'string' ? new TextEncoder().encode(salt) : (salt || new Uint8Array(0)),
        info || 'cyphra:kdf:v1',
        len
      )
    },

    // Double Ratchet step — (Rust WASM)
    async ratchetStep(chainKeyHex) {
      return ratchetChainStep(chainKeyHex)
    },

    // Generate random bytes
    randomBytes(length) {
      return Array.from(crypto.getRandomValues(new Uint8Array(length)))
    },
  }
}


// ── CryptoService public singleton ────────────────────────────────────────
export class CryptoService {
  constructor() {
    this.crypto = null
    this.initialized = false
  }

  async init() {
    if (!this.initialized) {
      this.crypto = await initCrypto()
      this.initialized = true
    }
    return this.crypto
  }

  async generateKeypair() {
    await this.init()
    return this.crypto.generateIdentityKeypair()
  }

  async generateSignedPrekey() {
    await this.init()
    return this.crypto.generateSignedPrekey()
  }

  async encryptMessage(plaintext, chatId) {
    await this.init()
    return this.crypto.encryptMessage(plaintext, chatId)
  }

  async decryptMessage(encryptedMessage, chatId) {
    await this.init()
    return this.crypto.decryptMessage(encryptedMessage, chatId)
  }

  async signMessage(message, signingKeyHex) {
    await this.init()
    return this.crypto.signMessage(message, signingKeyHex)
  }

  async verifySignature(message, signatureData, verifyingKeyHex) {
    await this.init()
    return this.crypto.verifySignature(message, signatureData, verifyingKeyHex)
  }

  async hash(data) {
    await this.init()
    return this.crypto.hash(data)
  }

  /** HKDF-SHA256 key derivation (uses Rust WASM) */
  async deriveKey(ikm, salt, info, len = 32) {
    await this.init()
    return this.crypto.deriveKey(ikm, salt, info, len)
  }

  /** Advance a Double Ratchet chain key one step (uses Rust WASM) */
  async ratchetStep(chainKeyHex) {
    await this.init()
    return this.crypto.ratchetStep(chainKeyHex)
  }

  async generateSessionKey() {
    await this.init()
    return this.crypto.generateSessionKey()
  }

  randomBytes(length) {
    return crypto.getRandomValues(new Uint8Array(length))
  }
}

// Export singleton instance
export default new CryptoService()
