/**
 * crypto.js — Cyphra PWA Cryptographic Layer
 * Mirrors the Android CyphraApiClient SHA-256 logic exactly.
 * Uses Web Crypto API (native browser, no libraries needed).
 */

const CryptoUtils = (() => {

  /** SHA-256 → hex string (same as Android's MessageDigest) */
  async function sha256Hex(message) {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    return Array.from(new Uint8Array(hashBuffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  /**
   * Derive userId from email — exact same as Android:
   *   userId = SHA-256(email.trim().lowercase())
   */
  async function deriveUserId(email) {
    return sha256Hex(email.trim().toLowerCase());
  }

  /**
   * Hash password — same as Android:
   *   passwordHash = SHA-256(password + salt)
   * When no salt provided (login), uses empty salt to match
   * what was stored at registration.
   */
  async function hashPassword(password, salt = '') {
    return sha256Hex(password + salt);
  }

  /**
   * Generate random hex ID for messages
   */
  function generateId() {
    const arr = new Uint8Array(9);
    crypto.getRandomValues(arr);
    return 'msg_' + Date.now() + '_' + Array.from(arr)
      .map(b => b.toString(16).padStart(2, '0')).join('');
  }

  return { sha256Hex, deriveUserId, hashPassword, generateId };
})();
