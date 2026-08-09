/**
 * Secure Authentication Service
 * Military-grade security without behavioral biometrics
 * Uses: Argon2-style key derivation, AES-256-GCM encryption, secure hashing
 */

import cryptoService from './crypto.service'
import veddbService from './veddb.service'

class AuthService {
  constructor() {
    this.currentUser = null
    this.sessionToken = null
  }

  /**
   * Initialize authentication service
   */
  async init() {
    console.log('Initializing Secure Authentication...')
    await cryptoService.init()
    await veddbService.init()
    console.log('Authentication ready')
  }

  /**
   * Derive a strong key from password using PBKDF2
   * (Simulating Argon2 with Web Crypto API)
   */
  async deriveKey(password, salt) {
    const encoder = new TextEncoder()
    const passwordBuffer = encoder.encode(password)

    // Import password as key material
    const keyMaterial = await window.crypto.subtle.importKey(
      'raw',
      passwordBuffer,
      { name: 'PBKDF2' },
      false,
      ['deriveBits', 'deriveKey']
    )

    // Derive key using PBKDF2 with 100,000 iterations (very secure)
    const derivedKey = await window.crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: 100000, // High iteration count for security
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    )

    return derivedKey
  }

  /**
   * Hash password securely (for storage/comparison)
   */
  async hashPassword(password, salt) {
    const encoder = new TextEncoder()
    const passwordBuffer = encoder.encode(password + salt)
    
    // Use SHA-256 for hashing
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', passwordBuffer)
    
    // Convert to hex
    const hashArray = Array.from(new Uint8Array(hashBuffer))
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
    
    return hashHex
  }

  /**
   * Generate random salt
   */
  generateSalt() {
    const salt = new Uint8Array(32)
    window.crypto.getRandomValues(salt)
    return Array.from(salt)
  }

  /**
   * Register new user
   */
  async register(username, email, password) {
    console.log('Registering user...')

    // Validation
    if (!username || username.length < 3) {
      throw new Error('Username must be at least 3 characters')
    }

    if (!email || !email.includes('@')) {
      throw new Error('Please enter a valid email address')
    }

    if (!password || password.length < 8) {
      throw new Error('Password must be at least 8 characters')
    }

    // Check if user already exists
    const userId = await cryptoService.hash(email.toLowerCase())
    const existingUser = await veddbService.getUser(userId)
    
    if (existingUser) {
      throw new Error('User already exists. Please login instead.')
    }

    // Generate salt for password hashing
    const salt = this.generateSalt()
    const saltString = salt.map(b => b.toString(16).padStart(2, '0')).join('')

    // Hash password with salt
    const passwordHash = await this.hashPassword(password, saltString)

    // Generate cryptographic keypair for end-to-end encryption
    const keypair = await cryptoService.generateKeypair()

    // Encrypt private key with password-derived key (never stored in plaintext)
    const pkDeriveKey = await this.deriveKey(password, new Uint8Array(salt))
    const pkExported = await window.crypto.subtle.exportKey('raw', pkDeriveKey)
    const pkKeyBytes = new Uint8Array(pkExported)
    const pkIv = window.crypto.getRandomValues(new Uint8Array(12))
    const pkPlainBytes = new TextEncoder().encode(keypair.privateKey)
    const pkEncrypted = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: pkIv }, pkDeriveKey, pkPlainBytes
    )
    const encryptedPrivateKey = {
      ciphertext: Array.from(new Uint8Array(pkEncrypted)).map(b => b.toString(16).padStart(2, '0')).join(''),
      iv: Array.from(pkIv).map(b => b.toString(16).padStart(2, '0')).join(''),
      _encrypted: true
    }

    // Create user object — private key is encrypted with user's password
    const user = {
      id: userId,
      username,
      email: email.toLowerCase(),
      passwordHash,
      salt: saltString,
      publicKey: keypair.publicKey,
      privateKey: encryptedPrivateKey, // Encrypted — cannot be read without password
      createdAt: Date.now(),
      verified: true,
      securityLevel: 'military-grade',
    }

    // Store in VedDB
    await veddbService.storeUser(user)

    console.log('User registered successfully')

    // Set current user
    this.currentUser = user
    this.sessionToken = this.generateSessionToken()

    return {
      success: true,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        createdAt: user.createdAt,
      },
      sessionToken: this.sessionToken,
    }
  }

  /**
   * Login user
   */
  async login(email, password) {
    console.log('Authenticating user...')

    // Validation
    if (!email || !password) {
      throw new Error('Email and password are required')
    }

    // Get user from database
    const userId = await cryptoService.hash(email.toLowerCase())
    const user = await veddbService.getUser(userId)

    if (!user) {
      throw new Error('Invalid email or password')
    }

    // Verify password
    const passwordHash = await this.hashPassword(password, user.salt)

    if (passwordHash !== user.passwordHash) {
      console.error('Password mismatch')
      throw new Error('Invalid email or password')
    }

    console.log('Authentication successful')

    // Set current user
    this.currentUser = user
    this.sessionToken = this.generateSessionToken()

    return {
      success: true,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        createdAt: user.createdAt,
      },
      sessionToken: this.sessionToken,
    }
  }

  /**
   * Logout user
   */
  logout() {
    this.currentUser = null
    this.sessionToken = null
    console.log('User logged out')
  }

  /**
   * Generate session token
   */
  generateSessionToken() {
    const tokenBytes = new Uint8Array(32)
    window.crypto.getRandomValues(tokenBytes)
    return Array.from(tokenBytes).map(b => b.toString(16).padStart(2, '0')).join('')
  }

  /**
   * Get current user
   */
  getCurrentUser() {
    return this.currentUser
  }

  /**
   * Check if user is authenticated
   */
  isAuthenticated() {
    return this.currentUser !== null && this.sessionToken !== null
  }

  /**
   * Change password
   */
  async changePassword(oldPassword, newPassword) {
    if (!this.currentUser) {
      throw new Error('Not authenticated')
    }

    if (newPassword.length < 8) {
      throw new Error('New password must be at least 8 characters')
    }

    // Verify old password
    const oldPasswordHash = await this.hashPassword(oldPassword, this.currentUser.salt)
    if (oldPasswordHash !== this.currentUser.passwordHash) {
      throw new Error('Current password is incorrect')
    }

    // Generate new salt and hash
    const newSalt = this.generateSalt()
    const newSaltString = newSalt.map(b => b.toString(16).padStart(2, '0')).join('')
    const newPasswordHash = await this.hashPassword(newPassword, newSaltString)

    // Update user
    this.currentUser.salt = newSaltString
    this.currentUser.passwordHash = newPasswordHash

    // Save to database
    await veddbService.storeUser(this.currentUser)

    console.log('Password changed successfully')

    return { success: true }
  }
}

// Export singleton
export default new AuthService()

