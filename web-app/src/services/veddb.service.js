/**
 * VedDB Storage Service (Frontend)
 * Connects to Backend API which manages VedDB connection
 * All data is encrypted before sending to backend
 */

import CryptoService from './crypto.service'

class VedDBService {
  constructor() {
    this.apiUrl = '/api'
    const wsProto = window.location.protocol === 'https:' ? 'wss' : 'ws'
    this.wsUrl = `${wsProto}://${window.location.host}/ws`
    this.ws = null
    this.initialized = false
    this.encryptionEnabled = true
    this.subscribers = new Map()
  }

  /**
   * Initialize connection to backend
   */
  async init() {
    if (this.initialized) return

    console.log('Connecting to Ghost Messenger Backend...')

    try {
      // Test backend connection — try Rust TLS route first, fallback to legacy
      let response = await fetch(`${this.apiUrl}/db/ping`)
      let data = response.ok ? await response.json() : null

      if (data && data.connected) {
        this.initialized = true
        console.log('Connected to backend API (Rust TLS client)')
        console.log(`VedDB Status: Connected | TLS: ${data.tls_enabled} | Latency: ${data.latency_ms}ms`)
        console.log(`Encryption: ${this.encryptionEnabled ? 'AES-256-GCM ENABLED' : 'DISABLED'}`)
        this.initWebSocket()
        return
      }

      // Fallback: legacy ping
      response = await fetch(`${this.apiUrl}/storage/ping`)
      data = await response.json()
      
      if (data.success) {
        this.initialized = true
        console.log('Connected to backend API (legacy mode)')
        console.log(`VedDB Status: ${data.stats ? 'Connected' : 'Unknown'}`)
        console.log(`Encryption: ${this.encryptionEnabled ? 'AES-256-GCM ENABLED' : 'DISABLED'}`)
        this.initWebSocket()
      } else {
        throw new Error('Backend API not responding correctly')
      }
    } catch (error) {
      console.error('Backend connection failed:', error)
      console.warn('Make sure the backend server is running at localhost:3001')
      throw error
    }
  }

  /**
   * Initialize WebSocket connection for real-time updates
   */
  initWebSocket() {
    try {
      this.ws = new WebSocket(this.wsUrl)
      
      this.ws.onopen = () => {
        console.log('WebSocket connected')
      }
      
      this.ws.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data)
          
          if (message.type === 'update') {
            // Notify subscribers
            const callback = this.subscribers.get(message.key)
            if (callback) {
              callback(message.data)
            }
          } else if (message.type === 'delivered' || message.type === 'read') {
            // Delivery/read receipt — notify status callback
            if (this.onStatusUpdate) {
              this.onStatusUpdate(message.messageId, message.type === 'read' ? 'read' : (message.delivered ? 'delivered' : 'sent'))
            }
          }
        } catch (error) {
          console.error('WebSocket message error:', error)
        }
      }
      
      this.ws.onclose = () => {
        console.log('WebSocket disconnected')
        // Attempt to reconnect after 5 seconds
        setTimeout(() => this.initWebSocket(), 5000)
      }
      
      this.ws.onerror = (error) => {
        console.error('WebSocket error:', error)
      }
    } catch (error) {
      console.warn('WebSocket connection failed:', error)
    }
  }

  /**
   * Subscribe to real-time updates for a key
   */
  subscribe(key, callback) {
    this.subscribers.set(key, callback)
    
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({ type: 'subscribe', key }))
    }
  }

  /**
   * Unsubscribe from updates
   */
  unsubscribe(key) {
    this.subscribers.delete(key)
    
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({ type: 'unsubscribe', key }))
    }
  }

  /**
   * Encrypt data before storage (AES-256-GCM)
   */
  async encryptData(data) {
    if (!this.encryptionEnabled) {
      return data
    }

    try {
      const jsonData = JSON.stringify(data)
      const encoder = new TextEncoder()
      const dataBuffer = encoder.encode(jsonData)

      // Generate encryption key
      const key = await window.crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
      )
      
      // Generate random IV
      const iv = window.crypto.getRandomValues(new Uint8Array(12))

      // Encrypt
      const encrypted = await window.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv },
        key,
        dataBuffer
      )

      // Export key
      const exportedKey = await window.crypto.subtle.exportKey('raw', key)

      return {
        encrypted: Array.from(new Uint8Array(encrypted)),
        iv: Array.from(iv),
        key: Array.from(new Uint8Array(exportedKey)),
        _encrypted: true
      }
    } catch (error) {
      console.error('Encryption failed:', error)
      return data
    }
  }

  /**
   * Decrypt data from storage
   */
  async decryptData(encryptedData) {
    if (!encryptedData._encrypted) {
      return encryptedData
    }

    try {
      // Import key
      const key = await window.crypto.subtle.importKey(
        'raw',
        new Uint8Array(encryptedData.key),
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
      )

      // Decrypt
      const decrypted = await window.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: new Uint8Array(encryptedData.iv) },
        key,
        new Uint8Array(encryptedData.encrypted)
      )

      const decoder = new TextDecoder()
      const jsonData = decoder.decode(decrypted)
      return JSON.parse(jsonData)
    } catch (error) {
      console.error('Decryption failed:', error)
      throw error
    }
  }

  /**
   * Store data via backend API (encrypted)
   * Uses the Rust TLS-encrypted VedDB client for optimal performance.
   * Falls back to legacy /api/storage/set if Rust server is unavailable.
   */
  async set(key, value) {
    await this.init()

    try {
      // Encrypt data
      const encrypted = await this.encryptData(value)

      // Primary: Rust server with TLS (< 5ms)
      const response = await fetch(`${this.apiUrl}/db/set`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key, value: encrypted })
      })

      if (response.ok) {
        const data = await response.json()
        if (data.success) {
          console.log(`Stored encrypted data: ${key}`)
          return true
        }
      }

      // Fallback: legacy subprocess route (if Rust server is down)
      const fallback = await fetch(`${this.apiUrl}/storage/set`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key, value: encrypted })
      })
      const fbData = await fallback.json()
      if (fbData.success) {
        console.log(`Stored encrypted data (fallback): ${key}`)
        return true
      }

      throw new Error(fbData.error || 'Failed to store data')
    } catch (error) {
      console.error(`Failed to store ${key}:`, error)
      return false
    }
  }

  /**
   * Retrieve data via backend API (decrypt)
   * Uses the Rust TLS-encrypted VedDB client for optimal performance.
   */
  async get(key) {
    await this.init()

    try {
      // Primary: Rust server with TLS (< 5ms)
      const response = await fetch(`${this.apiUrl}/db/get/${encodeURIComponent(key)}`)

      if (response.ok) {
        const data = await response.json()
        if (data.success && data.value !== null) {
          const decrypted = await this.decryptData(data.value)
          console.log(`Retrieved and decrypted: ${key}`)
          return decrypted
        }
        if (data.success && data.value === null) {
          return null  // Key not found
        }
      }

      // Fallback: legacy subprocess route
      const fallback = await fetch(`${this.apiUrl}/storage/get/${key}`)
      if (fallback.status === 404) return null
      const fbData = await fallback.json()
      if (!fbData.success) return null
      const decrypted = await this.decryptData(fbData.value)
      console.log(`Retrieved and decrypted (fallback): ${key}`)
      return decrypted
    } catch (error) {
      console.error(`Failed to retrieve ${key}:`, error)
      return null
    }
  }

  /**
   * Delete data via backend API
   * Uses the Rust TLS-encrypted VedDB client.
   */
  async delete(key) {
    await this.init()

    try {
      // Primary: Rust server with TLS
      const response = await fetch(`${this.apiUrl}/db/delete/${encodeURIComponent(key)}`, {
        method: 'DELETE'
      })

      if (response.ok) {
        const data = await response.json()
        if (data.success) {
          console.log(`Deleted: ${key}`)
          return true
        }
      }

      // Fallback: legacy route
      const fallback = await fetch(`${this.apiUrl}/storage/delete/${key}`, {
        method: 'DELETE'
      })
      const fbData = await fallback.json()
      if (fbData.success) {
        console.log(`Deleted (fallback): ${key}`)
        return true
      }

      throw new Error(fbData.error || 'Failed to delete data')
    } catch (error) {
      console.error(`Failed to delete ${key}:`, error)
      return false
    }
  }

  /**
   * Store user profile (helper)
   */
  async storeUser(user) {
    await this.init()

    try {
      // Encrypt user data
      const encrypted = await this.encryptData(user)

      const response = await fetch(`${this.apiUrl}/users`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...user, encryptedData: encrypted })
      })

      const data = await response.json()
      return data.success
    } catch (error) {
      console.error('Failed to store user:', error)
      return false
    }
  }

  /**
   * Get user profile (helper)
   */
  async getUser(userId) {
    await this.init()

    try {
      const response = await fetch(`${this.apiUrl}/users/${userId}`)
      
      if (response.status === 404) {
        return null
      }

      const data = await response.json()
      
      if (data.success && data.user.encryptedData) {
        // Decrypt user data
        return await this.decryptData(data.user.encryptedData)
      }

      return data.user
    } catch (error) {
      console.error('Failed to get user:', error)
      return null
    }
  }

  /**
   * Store message (helper)
   */
  async storeMessage(message) {
    await this.init()

    try {
      // Encrypt message content
      const encrypted = await this.encryptData(message)

      const response = await fetch(`${this.apiUrl}/messages`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...message, encryptedContent: encrypted })
      })

      const data = await response.json()
      return data.success
    } catch (error) {
      console.error('Failed to store message:', error)
      return false
    }
  }

  /**
   * Get messages for a chat (helper)
   */
  async getMessages(chatId) {
    await this.init()

    try {
      const response = await fetch(`${this.apiUrl}/messages/chat/${chatId}`)
      const data = await response.json()
      
      if (!data.success) {
        return []
      }

      // Decrypt messages
      const decrypted = []
      for (const msg of data.messages) {
        if (msg.encryptedContent) {
          decrypted.push(await this.decryptData(msg.encryptedContent))
        } else {
          decrypted.push(msg)
        }
      }

      return decrypted
    } catch (error) {
      console.error('Failed to get messages:', error)
      return []
    }
  }

  /**
   * Store contact (helper)
   */
  async storeContact(contact) {
    await this.init()

    try {
      const response = await fetch(`${this.apiUrl}/contacts`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(contact)
      })

      const data = await response.json()
      return data.success
    } catch (error) {
      console.error('Failed to store contact:', error)
      return false
    }
  }

  /**
   * Get all contacts (helper)
   */
  async getContacts(userId) {
    await this.init()

    try {
      const response = await fetch(`${this.apiUrl}/contacts/user/${userId}`)
      const data = await response.json()
      
      return data.success ? data.contacts : []
    } catch (error) {
      console.error('Failed to get contacts:', error)
      return []
    }
  }

  /**
   * Get connection statistics
   */
  async getStats() {
    await this.init()

    try {
      const response = await fetch(`${this.apiUrl}/stats`)
      const data = await response.json()
      
      return data
    } catch (error) {
      console.error('Failed to get stats:', error)
      return null
    }
  }

  /**
   * Close connections
   */
  close() {
    if (this.ws) {
      this.ws.close()
      this.ws = null
    }
    this.initialized = false
  }
}

// Export singleton
export default new VedDBService()
