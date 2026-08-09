/**
 * API Routes
 */

const ML_SERVICE_URL = 'http://127.0.0.1:5002'

/** Forward a request to the ML FastAPI service */
async function proxyML(path, method = 'GET', body = null) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } }
  if (body) opts.body = JSON.stringify(body)
  const resp = await fetch(`${ML_SERVICE_URL}${path}`, opts)
  if (!resp.ok) throw new Error(`ML service error ${resp.status}`)
  return resp.json()
}

export function setupRoutes(app, veddb) {
  
  // ============= Storage Routes =============
  
  /**
   * SET - Store a key-value pair
   * POST /api/storage/set
   * Body: { key, value }
   */
  app.post('/api/storage/set', async (req, res) => {
    try {
      const { key, value } = req.body
      
      if (!key) {
        return res.status(400).json({ error: 'Key is required' })
      }
      
      await veddb.set(key, value)
      
      // Broadcast update to WebSocket clients
      if (app.locals.wsBroadcast) {
        app.locals.wsBroadcast(key, value)
      }
      
      res.json({
        success: true,
        key,
        timestamp: Date.now()
      })
    } catch (error) {
      res.status(500).json({ error: error.message })
    }
  })

  /**
   * GET - Retrieve a value by key
   * GET /api/storage/get/:key
   */
  app.get('/api/storage/get/:key', async (req, res) => {
    try {
      const { key } = req.params
      const value = await veddb.get(key)
      
      if (value === null) {
        return res.status(404).json({ error: 'Key not found' })
      }
      
      res.json({
        success: true,
        key,
        value,
        timestamp: Date.now()
      })
    } catch (error) {
      res.status(500).json({ error: error.message })
    }
  })

  /**
   * DELETE - Delete a key
   * DELETE /api/storage/delete/:key
   */
  app.delete('/api/storage/delete/:key', async (req, res) => {
    try {
      const { key } = req.params
      await veddb.delete(key)
      
      res.json({
        success: true,
        key,
        timestamp: Date.now()
      })
    } catch (error) {
      res.status(500).json({ error: error.message })
    }
  })

  /**
   * LIST - List all keys
   * GET /api/storage/keys
   */
  app.get('/api/storage/keys', async (req, res) => {
    try {
      const keys = await veddb.listKeys()
      
      res.json({
        success: true,
        keys,
        count: keys.length,
        timestamp: Date.now()
      })
    } catch (error) {
      res.status(500).json({ error: error.message })
    }
  })

  /**
   * PING - Test VedDB connection
   * GET /api/storage/ping
   */
  app.get('/api/storage/ping', async (req, res) => {
    try {
      const result = await veddb.ping()
      
      res.json({
        success: true,
        ...result,
        stats: veddb.getStats()
      })
    } catch (error) {
      res.status(500).json({ error: error.message })
    }
  })

  // ============= User Routes =============

  /**
   * Store user
   * POST /api/users
   * Body: { id, username, email, ...userData }
   */
  app.post('/api/users', async (req, res) => {
    try {
      const user = req.body
      
      if (!user.id) {
        return res.status(400).json({ error: 'User ID is required' })
      }
      
      const key = `user:${user.id}`
      await veddb.set(key, user)
      
      res.json({
        success: true,
        userId: user.id,
        timestamp: Date.now()
      })
    } catch (error) {
      res.status(500).json({ error: error.message })
    }
  })

  /**
   * Get user
   * GET /api/users/:userId
   */
  app.get('/api/users/:userId', async (req, res) => {
    try {
      const { userId } = req.params
      const key = `user:${userId}`
      const user = await veddb.get(key)
      
      if (!user) {
        return res.status(404).json({ error: 'User not found' })
      }
      
      res.json({
        success: true,
        user,
        timestamp: Date.now()
      })
    } catch (error) {
      res.status(500).json({ error: error.message })
    }
  })

  // ============= Message Routes =============

  /**
   * Store message
   * POST /api/messages
   * Body: { id, chatId, senderId, content, ...messageData }
   */
  app.post('/api/messages', async (req, res) => {
    try {
      const message = req.body
      
      if (!message.id || !message.chatId) {
        return res.status(400).json({ error: 'Message ID and chatId are required' })
      }
      
      // Store message
      const messageKey = `message:${message.id}`
      await veddb.set(messageKey, message)
      
      // Update chat messages index
      const chatKey = `chat:${message.chatId}:messages`
      const messages = await veddb.get(chatKey) || []
      messages.push(message.id)
      await veddb.set(chatKey, messages)
      
      // Broadcast to WebSocket clients
      if (app.locals.wsBroadcast) {
        app.locals.wsBroadcast(`chat:${message.chatId}`, message)
      }
      
      res.json({
        success: true,
        messageId: message.id,
        timestamp: Date.now()
      })
    } catch (error) {
      res.status(500).json({ error: error.message })
    }
  })

  /**
   * Get messages for a chat
   * GET /api/messages/chat/:chatId
   */
  app.get('/api/messages/chat/:chatId', async (req, res) => {
    try {
      const { chatId } = req.params
      const chatKey = `chat:${chatId}:messages`
      const messageIds = await veddb.get(chatKey) || []
      
      // Fetch all messages
      const messages = []
      for (const id of messageIds) {
        const message = await veddb.get(`message:${id}`)
        if (message) messages.push(message)
      }
      
      res.json({
        success: true,
        chatId,
        messages,
        count: messages.length,
        timestamp: Date.now()
      })
    } catch (error) {
      res.status(500).json({ error: error.message })
    }
  })

  // ============= Contact Routes =============

  /**
   * Store contact
   * POST /api/contacts
   * Body: { id, userId, ...contactData }
   */
  app.post('/api/contacts', async (req, res) => {
    try {
      const contact = req.body
      
      if (!contact.id || !contact.userId) {
        return res.status(400).json({ error: 'Contact ID and userId are required' })
      }
      
      // Store contact
      const contactKey = `contact:${contact.id}`
      await veddb.set(contactKey, contact)
      
      // Update user's contacts list
      const userContactsKey = `user:${contact.userId}:contacts`
      const contacts = await veddb.get(userContactsKey) || []
      if (!contacts.includes(contact.id)) {
        contacts.push(contact.id)
        await veddb.set(userContactsKey, contacts)
      }
      
      res.json({
        success: true,
        contactId: contact.id,
        timestamp: Date.now()
      })
    } catch (error) {
      res.status(500).json({ error: error.message })
    }
  })

  /**
   * Get contacts for a user
   * GET /api/contacts/user/:userId
   */
  app.get('/api/contacts/user/:userId', async (req, res) => {
    try {
      const { userId } = req.params
      const userContactsKey = `user:${userId}:contacts`
      const contactIds = await veddb.get(userContactsKey) || []
      
      // Fetch all contacts
      const contacts = []
      for (const id of contactIds) {
        const contact = await veddb.get(`contact:${id}`)
        if (contact) contacts.push(contact)
      }
      
      res.json({
        success: true,
        userId,
        contacts,
        count: contacts.length,
        timestamp: Date.now()
      })
    } catch (error) {
      res.status(500).json({ error: error.message })
    }
  })

  // ============= Stats Route =============

  /**
   * Get VedDB statistics
   * GET /api/stats
   */
  app.get('/api/stats', async (req, res) => {
    try {
      const keys = await veddb.listKeys()
      const stats = veddb.getStats()
      
      res.json({
        success: true,
        veddb: {
          connected: veddb.isConnected(),
          totalKeys: keys.length,
          poolStats: stats
        },
        server: {
          uptime: process.uptime(),
          memory: process.memoryUsage(),
          pid: process.pid
        },
        timestamp: Date.now()
      })
    } catch (error) {
      res.status(500).json({ error: error.message })
    }
  })
  

  // ============= ML Inference Proxy Routes =============
  // All /api/ml/* calls are forwarded to the Python FastAPI service (port 5001)

  /** GET /api/ml/health — ML service liveness */
  app.get('/api/ml/health', async (req, res) => {
    try {
      const data = await proxyML('/health')
      res.json(data)
    } catch (e) {
      res.status(503).json({ status: 'unavailable', error: e.message })
    }
  })

  /** GET /api/ml/model/info — real trained model metadata */
  app.get('/api/ml/model/info', async (req, res) => {
    try {
      const data = await proxyML('/model/info')
      res.json(data)
    } catch (e) {
      res.status(503).json({ error: 'ML service unavailable', detail: e.message })
    }
  })

  /** POST /api/ml/analyze/flow — classify a network flow */
  app.post('/api/ml/analyze/flow', async (req, res) => {
    try {
      const data = await proxyML('/analyze/flow', 'POST', req.body)
      res.json(data)
    } catch (e) {
      res.status(503).json({ error: 'ML service unavailable', detail: e.message })
    }
  })

  /** POST /api/ml/analyze/message — classify a message for threats */
  app.post('/api/ml/analyze/message', async (req, res) => {
    try {
      const data = await proxyML('/analyze/message', 'POST', req.body)
      res.json(data)
    } catch (e) {
      res.status(503).json({ error: 'ML service unavailable', detail: e.message })
    }
  })

  /** GET /api/ml/monitor/stats — live real packet/bandwidth counters */
  app.get('/api/ml/monitor/stats', async (req, res) => {
    try {
      const data = await proxyML('/monitor/stats')
      res.json(data)
    } catch (e) {
      res.status(503).json({ error: 'ML service unavailable', detail: e.message })
    }
  })

  /** GET /api/ml/realtime/feed — real captured + classified flows */
  app.get('/api/ml/realtime/feed', async (req, res) => {
    try {
      const limit = req.query.limit || 20
      const data = await proxyML(`/realtime/feed?limit=${limit}`)
      res.json(data)
    } catch (e) {
      res.status(503).json({ error: 'ML service unavailable', detail: e.message })
    }
  })

  console.log('✓ Configured routes:')
  console.log('  POST   /api/storage/set')
  console.log('  GET    /api/storage/get/:key')
  console.log('  DELETE /api/storage/delete/:key')
  console.log('  GET    /api/storage/keys')
  console.log('  GET    /api/storage/ping')
  console.log('  POST   /api/users')
  console.log('  GET    /api/users/:userId')
  console.log('  POST   /api/messages')
  console.log('  GET    /api/messages/chat/:chatId')
  console.log('  POST   /api/contacts')
  console.log('  GET    /api/contacts/user/:userId')
  console.log('  GET    /api/stats')
  console.log('  GET    /api/ml/health')
  console.log('  GET    /api/ml/model/info')
  console.log('  POST   /api/ml/analyze/flow')
  console.log('  POST   /api/ml/analyze/message')
  console.log('  GET    /api/ml/monitor/stats')
  console.log('  GET    /api/ml/realtime/feed')
}

