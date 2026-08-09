/**
 * Ghost Messenger Backend API
 * Connects to VedDB server and exposes REST + WebSocket API
 */

import express from 'express'
import cors from 'cors'
import { WebSocketServer } from 'ws'
import { createServer } from 'http'
import { config } from './config.js'
import { VedDBService } from './services/veddb.service.js'
import { setupRoutes } from './routes/index.js'
import { exec } from 'child_process'
import { promisify } from 'util'
const execAsync = promisify(exec)

const app = express()
const server = createServer(app)

// Middleware
app.use(cors(config.cors))
app.use(express.json({ limit: '10mb' }))
app.use(express.urlencoded({ extended: true }))

// Request logging
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`)
  next()
})

// Initialize VedDB connection
const veddb = new VedDBService()

async function initializeServices() {
  try {
    console.log('🚀 Initializing Ghost Messenger Backend...')
    console.log(`📡 Server: http://${config.host}:${config.port}`)
    console.log(`💾 VedDB: ${config.veddb.host}:${config.veddb.port}`)
    
    // Connect to VedDB
    await veddb.init()
    console.log('✓ VedDB connected')
    
    // Setup REST API routes
    setupRoutes(app, veddb)
    console.log('✓ REST API routes configured')
    
    // Setup WebSocket server
    const wss = new WebSocketServer({ server, path: '/ws' })
    setupWebSocket(wss, veddb)
    console.log('✓ WebSocket server configured')
    
    return true
  } catch (error) {
    console.error('❌ Service initialization failed:', error)
    throw error
  }
}

// WebSocket setup
function setupWebSocket(wss, veddb) {
  wss.on('connection', (ws, req) => {
    const clientId = Math.random().toString(36).substring(7)
    console.log(`✓ WebSocket client connected: ${clientId}`)
    
    ws.on('message', async (data) => {
      try {
        const message = JSON.parse(data.toString())
        console.log(`📨 WebSocket message from ${clientId}:`, message.type)
        
        // Handle different message types
        switch (message.type) {
          case 'ping':
            ws.send(JSON.stringify({ type: 'pong', timestamp: Date.now() }))
            break
            
          case 'subscribe':
            // Subscribe to real-time updates for a specific key
            ws.subscribedKeys = ws.subscribedKeys || []
            if (message.key && !ws.subscribedKeys.includes(message.key)) {
              ws.subscribedKeys.push(message.key)
              ws.send(JSON.stringify({
                type: 'subscribed',
                key: message.key
              }))
            }
            break
            
          case 'unsubscribe':
            // Unsubscribe from updates
            if (ws.subscribedKeys) {
              ws.subscribedKeys = ws.subscribedKeys.filter(k => k !== message.key)
              ws.send(JSON.stringify({
                type: 'unsubscribed',
                key: message.key
              }))
            }
            break
            
          case 'message':
            // Broadcast message to recipient
            if (message.recipientId && message.message) {
              console.log(`📤 Broadcasting message to ${message.recipientId}`)
              
              // Find recipient's WebSocket connection
              const recipientKey = `messages:${message.recipientId}`
              let delivered = false
              
              wss.clients.forEach((client) => {
                if (client.readyState === WebSocket.OPEN && 
                    client.subscribedKeys && 
                    client.subscribedKeys.includes(recipientKey)) {
                  // Send message to recipient
                  client.send(JSON.stringify({
                    type: 'update',
                    key: recipientKey,
                    data: message.message
                  }))
                  delivered = true
                  console.log(`✓ Message delivered to ${message.recipientId}`)
                }
              })
              
              // Send delivery confirmation to sender
              ws.send(JSON.stringify({
                type: 'delivered',
                messageId: message.message.id,
                delivered: delivered
              }))
            }
            break
            
          default:
            ws.send(JSON.stringify({
              type: 'error',
              message: 'Unknown message type'
            }))
        }
      } catch (error) {
        console.error('WebSocket message error:', error)
        ws.send(JSON.stringify({
          type: 'error',
          message: error.message
        }))
      }
    })
    
    ws.on('close', () => {
      console.log(`✗ WebSocket client disconnected: ${clientId}`)
    })
    
    ws.on('error', (error) => {
      console.error(`WebSocket error for ${clientId}:`, error)
    })
    
    // Send welcome message
    ws.send(JSON.stringify({
      type: 'connected',
      clientId,
      timestamp: Date.now()
    }))
  })
  
  // Broadcast function for real-time updates
  wss.broadcast = (key, data) => {
    wss.clients.forEach((client) => {
      if (client.readyState === 1 && client.subscribedKeys?.includes(key)) {
        client.send(JSON.stringify({
          type: 'update',
          key,
          data,
          timestamp: Date.now()
        }))
      }
    })
  }
  
  // Store broadcast function for use in routes
  app.locals.wsBroadcast = wss.broadcast
}

// Test endpoint (always available)
app.get('/test', (req, res) => {
  res.json({ message: 'Backend is working!', timestamp: Date.now() })
})

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    veddb: veddb.isConnected(),
    uptime: process.uptime(),
    timestamp: Date.now()
  })
})

// Test API endpoint
app.get('/api/test', (req, res) => {
  res.json({ message: 'API route is working!', timestamp: Date.now() })
})

// Storage routes (temporarily inline until we fix setupRoutes)
app.get('/api/storage/ping', async (req, res) => {
  try {
    await veddb.ping()
    res.json({
      success: true,
      timestamp: Date.now(),
      stats: veddb.getStats()
    })
  } catch (error) {
    res.status(500).json({ error: error.message })
  }
})

app.post('/api/storage/set', async (req, res) => {
  try {
    const { key, value } = req.body
    if (!key) {
      return res.status(400).json({ error: 'Key is required' })
    }
    await veddb.set(key, value)
    res.json({ success: true, key, timestamp: Date.now() })
  } catch (error) {
    res.status(500).json({ error: error.message })
  }
})

app.get('/api/storage/get/:key', async (req, res) => {
  try {
    const { key } = req.params
    const value = await veddb.get(key)
    if (value === null) {
      return res.status(404).json({ error: 'Key not found' })
    }
    res.json({ success: true, key, value, timestamp: Date.now() })
  } catch (error) {
    res.status(500).json({ error: error.message })
  }
})

app.delete('/api/storage/delete/:key', async (req, res) => {
  try {
    const { key } = req.params
    await veddb.set(key, null)
    res.json({ success: true, key, timestamp: Date.now() })
  } catch (error) {
    res.status(500).json({ error: error.message })
  }
})

app.post('/api/users', async (req, res) => {
  try {
    const user = req.body
    if (!user.id) {
      return res.status(400).json({ error: 'User ID is required' })
    }
    const key = `user:${user.id}`
    await veddb.set(key, user)
    res.json({ success: true, userId: user.id, timestamp: Date.now() })
  } catch (error) {
    res.status(500).json({ error: error.message })
  }
})

app.get('/api/users/:userId', async (req, res) => {
  try {
    const { userId } = req.params
    const key = `user:${userId}`
    const user = await veddb.get(key)
    if (!user) {
      return res.status(404).json({ error: 'User not found' })
    }
    res.json({ success: true, user, timestamp: Date.now() })
  } catch (error) {
    res.status(500).json({ error: error.message })
  }
})

// ── ML Inference Proxy Routes ──────────────────────────────────────────────
// These are registered BEFORE the 404 handler and BEFORE async init completes.
// They proxy all /api/ml/* requests to the Python FastAPI service on port 5002.

const ML_URL = 'http://127.0.0.1:5002'

async function proxyToML(path, method = 'GET', body = null) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } }
  if (body) opts.body = JSON.stringify(body)
  const resp = await fetch(`${ML_URL}${path}`, opts)
  if (!resp.ok) throw new Error(`ML ${resp.status}`)
  return resp.json()
}

app.get('/api/ml/health', async (req, res) => {
  try { res.json(await proxyToML('/health')) }
  catch (e) { res.status(503).json({ status: 'unavailable', error: e.message }) }
})

app.get('/api/ml/model/info', async (req, res) => {
  try { res.json(await proxyToML('/model/info')) }
  catch (e) { res.status(503).json({ error: 'ML service unavailable', detail: e.message }) }
})

app.post('/api/ml/analyze/flow', async (req, res) => {
  try { res.json(await proxyToML('/analyze/flow', 'POST', req.body)) }
  catch (e) { res.status(503).json({ error: 'ML service unavailable', detail: e.message }) }
})

app.post('/api/ml/analyze/message', async (req, res) => {
  try { res.json(await proxyToML('/analyze/message', 'POST', req.body)) }
  catch (e) { res.status(503).json({ error: 'ML service unavailable', detail: e.message }) }
})

app.get('/api/ml/monitor/stats', async (req, res) => {
  try { res.json(await proxyToML('/monitor/stats')) }
  catch (e) { res.status(503).json({ error: 'ML service unavailable', detail: e.message }) }
})

app.get('/api/ml/realtime/feed', async (req, res) => {
  try {
    const limit = req.query.limit || 20
    res.json(await proxyToML(`/realtime/feed?limit=${limit}`))
  }
  catch (e) { res.status(503).json({ error: 'ML service unavailable', detail: e.message }) }
})

app.post('/api/ml/demo/inject', async (req, res) => {
  try { res.json(await proxyToML('/demo/inject', 'POST', req.body)) }
  catch (e) { res.status(503).json({ error: 'ML service unavailable', detail: e.message }) }
})

// ── Auto-Response Proxy Routes ─────────────────────────────────────────────
app.get('/api/ml/response/status', async (req, res) => {
  try { res.json(await proxyToML('/response/status')) }
  catch (e) { res.status(503).json({ error: 'ML service unavailable', detail: e.message }) }
})

app.post('/api/ml/response/unblock', async (req, res) => {
  try { res.json(await proxyToML('/response/unblock', 'POST', req.body)) }
  catch (e) { res.status(503).json({ error: 'ML service unavailable', detail: e.message }) }
})

app.post('/api/ml/response/toggle', async (req, res) => {
  try { res.json(await proxyToML('/response/toggle', 'POST', req.body)) }
  catch (e) { res.status(503).json({ error: 'ML service unavailable', detail: e.message }) }
})

// ── CYPHRA Rust Library Proxy Routes ──────────────────────────────────
// Proxies requests to the native Rust server running on port 5050.
// Exposes: Kyber1024 + X25519 PQC-Hybrid crypto, HKDF-BLAKE3, BLAKE3 hash,
//          X3DH session initiation/acceptance, AI threat scoring, anomaly detection.

const CYPHRA_LIBS_URL = 'http://127.0.0.1:5050'

async function proxyToCyphra(path, method = 'GET', body = null) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } }
  if (body) opts.body = JSON.stringify(body)
  const resp = await fetch(`${CYPHRA_LIBS_URL}${path}`, opts)
  if (!resp.ok) {
    const errText = await resp.text()
    throw new Error(`Cyphra ${resp.status}: ${errText}`)
  }
  return resp.json()
}

app.get('/api/Cyphra/health', async (req, res) => {
  try { res.json(await proxyToCyphra('/api/v1/health')) }
  catch (e) { res.status(503).json({ error: 'CYPHRA service unavailable', detail: e.message }) }
})

app.post('/api/Cyphra/crypto/keypair/identity', async (req, res) => {
  try { res.json(await proxyToCyphra('/api/v1/crypto/keypair/identity', 'POST', req.body || {})) }
  catch (e) { res.status(503).json({ error: 'Keypair generation failed', detail: e.message }) }
})

app.post('/api/Cyphra/crypto/keypair/signed', async (req, res) => {
  try { res.json(await proxyToCyphra('/api/v1/crypto/keypair/signed', 'POST', req.body)) }
  catch (e) { res.status(503).json({ error: 'Signed prekey failed', detail: e.message }) }
})

app.post('/api/Cyphra/crypto/keypair/onetime', async (req, res) => {
  try { res.json(await proxyToCyphra('/api/v1/crypto/keypair/onetime', 'POST', req.body)) }
  catch (e) { res.status(503).json({ error: 'One-time prekey generation failed', detail: e.message }) }
})

app.post('/api/Cyphra/crypto/x3dh/initiate', async (req, res) => {
  try { res.json(await proxyToCyphra('/api/v1/crypto/x3dh/initiate', 'POST', req.body)) }
  catch (e) { res.status(503).json({ error: 'X3DH initiation failed', detail: e.message }) }
})

app.post('/api/Cyphra/crypto/x3dh/accept', async (req, res) => {
  try { res.json(await proxyToCyphra('/api/v1/crypto/x3dh/accept', 'POST', req.body)) }
  catch (e) { res.status(503).json({ error: 'X3DH acceptance failed', detail: e.message }) }
})

app.post('/api/Cyphra/crypto/hkdf', async (req, res) => {
  try { res.json(await proxyToCyphra('/api/v1/crypto/hkdf', 'POST', req.body)) }
  catch (e) { res.status(503).json({ error: 'HKDF derivation failed', detail: e.message }) }
})

app.post('/api/Cyphra/crypto/hash', async (req, res) => {
  try { res.json(await proxyToCyphra('/api/v1/crypto/hash', 'POST', req.body)) }
  catch (e) { res.status(503).json({ error: 'Hashing failed', detail: e.message }) }
})

app.post('/api/Cyphra/ai/threat-score', async (req, res) => {
  try { res.json(await proxyToCyphra('/api/v1/ai/threat-score', 'POST', req.body)) }
  catch (e) { res.status(503).json({ error: 'Threat scoring failed', detail: e.message }) }
})

app.post('/api/Cyphra/ai/anomaly-detect', async (req, res) => {
  try { res.json(await proxyToCyphra('/api/v1/ai/anomaly-detect', 'POST', req.body)) }
  catch (e) { res.status(503).json({ error: 'Anomaly detection failed', detail: e.message }) }
})

// ── VedDB Direct Access via Rust Server (TLS-encrypted) ────────────────────
// These routes bypass the CLI subprocess and use the proper veddb-client
// Rust library with TLS 1.3 connection pooling. Much faster (<5ms vs 50-100ms).

app.post('/api/db/set', async (req, res) => {
  try { res.json(await proxyToCyphra('/api/v1/db/set', 'POST', req.body)) }
  catch (e) { res.status(503).json({ error: 'DB set failed', detail: e.message }) }
})

app.get('/api/db/get/:key', async (req, res) => {
  try { res.json(await proxyToCyphra(`/api/v1/db/get/${encodeURIComponent(req.params.key)}`)) }
  catch (e) { res.status(503).json({ error: 'DB get failed', detail: e.message }) }
})

app.delete('/api/db/delete/:key', async (req, res) => {
  try {
    const resp = await fetch(`${CYPHRA_LIBS_URL}/api/v1/db/delete/${encodeURIComponent(req.params.key)}`, { method: 'DELETE' })
    if (!resp.ok) throw new Error(`Cyphra ${resp.status}`)
    res.json(await resp.json())
  }
  catch (e) { res.status(503).json({ error: 'DB delete failed', detail: e.message }) }
})

app.get('/api/db/ping', async (req, res) => {
  try { res.json(await proxyToCyphra('/api/v1/db/ping')) }
  catch (e) { res.status(503).json({ error: 'DB ping failed', detail: e.message }) }
})

// ── Real Signal Stats Engine ───────────────────────────────────────────────
// Collects real Wi-Fi metrics from Windows every 6s via:
//   • netsh wlan show interfaces  → RSSI signal %, SSID, BSSID, channel
//   • ping <gateway>              → real RTT latency, jitter, packet loss
//   • /api/ml/monitor/stats       → real NIC packet counters
//
// Results are cached so the GET endpoint returns instantly.

let _signalCache = null   // last known good reading
let _signalTs    = 0      // when it was collected

async function _collectSignalStats() {
  const now = Date.now()

  // ── 1. Wi-Fi adapter info via netsh ──────────────────────────────────────
  let signalPct = 70, ssid = 'Wi-Fi', bssid = '?', channel = 0, radioType = ''
  try {
    const { stdout } = await execAsync('netsh wlan show interfaces', { timeout: 4000 })
    const m = (pat) => { const r = stdout.match(pat); return r ? r[1].trim() : null }
    signalPct  = parseInt(m(/Signal\s*:\s*(\d+)%/)     || '70')
    ssid       = m(/\bSSID\s*:\s*(.+)/)               || 'Wi-Fi'
    bssid      = m(/BSSID\s*:\s*([\da-fA-F:]+)/)      || '?'
    channel    = parseInt(m(/Channel\s*:\s*(\d+)/)     || '0')
    radioType  = m(/Radio type\s*:\s*(.+)/)            || ''
  } catch { /* not on Wi-Fi or netsh unavailable */ }

  // Convert Windows signal % → approximate SNR dB
  // Windows uses a rough linear mapping: 100% ≈ -50dBm, 0% ≈ -100dBm
  // Noise floor ≈ -95dBm on 2.4GHz, -90dBm on 5GHz
  const signalDbm  = -100 + (signalPct / 100) * 50
  const noisFloor  = radioType.includes('5ghz') || channel > 14 ? -90 : -95
  const snr_db     = parseFloat(Math.max(0, signalDbm - noisFloor).toFixed(1))

  // ── 2. Gateway discovery ──────────────────────────────────────────────────
  let gateway = '8.8.8.8'
  try {
    const { stdout: rt } = await execAsync('route print 0.0.0.0', { timeout: 2000 })
    const gm = rt.match(/0\.0\.0\.0\s+0\.0\.0\.0\s+([\d.]+)/)
    if (gm) gateway = gm[1]
  } catch { /* keep default */ }

  // ── 3. Real ping → latency, jitter, packet loss ───────────────────────────
  let latency_ms = 999, jitter_ms = 0, packet_loss_pct = 100
  const rtts = []
  try {
    const { stdout: po } = await execAsync(`ping -n 4 ${gateway}`, { timeout: 10000 })
    const matches = [...po.matchAll(/[Tt]ime[=<](\d+)\s*ms/g)]
    matches.forEach(m => rtts.push(parseInt(m[1])))

    const lost = 4 - rtts.length
    packet_loss_pct = parseFloat(((lost / 4) * 100).toFixed(1))

    if (rtts.length > 0) {
      latency_ms = parseFloat((rtts.reduce((a, b) => a + b, 0) / rtts.length).toFixed(1))
      if (rtts.length > 1) {
        const variance = rtts.reduce((s, v) => s + (v - latency_ms) ** 2, 0) / rtts.length
        jitter_ms = parseFloat(Math.sqrt(variance).toFixed(1))
      }
    }
  } catch { /* ping failed */ }

  // ── 4. NIC packet counters from ML service ────────────────────────────────
  let nic = {}
  try {
    const nr = await fetch('http://127.0.0.1:5002/monitor/stats', { signal: AbortSignal.timeout(2000) })
    if (nr.ok) nic = await nr.json()
  } catch { /* ML service offline */ }

  // ── 5. Real NTP timing offset via Windows Time Service ───────────────────
  // w32tm /query /status reports the phase offset between local clock and NTP
  // source. High offset (>500ms) is a real indicator of timing manipulation.
  let timing_drift_ms = 0
  try {
    const { stdout: w32 } = await execAsync('w32tm /query /status', { timeout: 4000 })
    // "Root Delay: 0.0312500s"  or  "Phase Offset: -0.003141600s"
    const phaseMatch = w32.match(/Phase Offset\s*:\s*(-?[\d.]+)s/)
    const delayMatch = w32.match(/Root Delay\s*:\s*([\d.]+)s/)
    if (phaseMatch) {
      timing_drift_ms = parseFloat((parseFloat(phaseMatch[1]) * 1000).toFixed(2))
    } else if (delayMatch) {
      timing_drift_ms = parseFloat((parseFloat(delayMatch[1]) * 1000).toFixed(2))
    }
  } catch { /* w32tm not available */ }

  // ── 6. Real flow IAT data from ML realtime feed ───────────────────────────
  // Pulls recent flow completion timestamps and packet sizes from the trained
  // ensemble's output. Used for:
  //   • iat_variance — real inter-flow timing regularity (beaconing detection)
  //   • flow_timestamps — real timestamps for pattern anomaly Z-score
  //   • bytes_per_pkt — real payload size for anomaly analysis
  //   • rst_spike — elevated RSTs (proxy for replay/brute-force indicator)
  let iat_cv          = 0.4   // 0=perfectly regular (beaconing), 1=chaotic
  let flow_timestamps = []    // real flow completion epoch ms
  let bytes_per_pkt   = 256   // real avg bytes per packet
  let rst_spike       = false // true if RST count unusually high

  try {
    const fr = await fetch('http://127.0.0.1:5002/realtime/feed?limit=30', {
      signal: AbortSignal.timeout(2000),
    })
    if (fr.ok) {
      const fd = await fr.json()
      const flows = (fd.results || []).filter(f => f.real_capture)

      if (flows.length >= 3) {
        // Flow completion timestamps (ms)
        flow_timestamps = flows.map(f => Math.round((f.ts || 0) * 1000)).filter(Boolean)

        // IAT between consecutive flow completions → regularity = beaconing
        const sorted = [...flow_timestamps].sort((a, b) => a - b)
        const iats = sorted.slice(1).map((t, i) => t - sorted[i])
        if (iats.length >= 2) {
          const mean = iats.reduce((a, b) => a + b, 0) / iats.length
          const std  = Math.sqrt(iats.reduce((s, v) => s + (v - mean) ** 2, 0) / iats.length)
          iat_cv = mean > 0 ? parseFloat((std / mean).toFixed(4)) : 0.4
        }

        // Average bytes per packet from real flows
        const bpps = flows
          .filter(f => f.total_bytes != null && f.total_packets != null && f.total_packets > 0)
          .map(f => f.total_bytes / f.total_packets)
        if (bpps.length > 0) {
          bytes_per_pkt = Math.round(bpps.reduce((a, b) => a + b, 0) / bpps.length)
        }

        // RST spike: if >30% of recent flows show Critical/Malicious AND
        // we have many flows in a short window → potential replay/brute-force
        const highThreat = flows.filter(f => (f.malicious_probability ?? 0) > 0.65).length
        rst_spike = flows.length >= 10 && (highThreat / flows.length) > 0.3
      }
    }
  } catch { /* ML service offline */ }

  _signalCache = {
    source_id:        ssid !== 'Wi-Fi' ? ssid : (gateway ? `GW-${gateway}` : 'WIFI'),
    ssid,
    bssid,
    channel,
    radio_type:       radioType,
    signal_pct:       signalPct,
    signal_dbm:       parseFloat(signalDbm.toFixed(1)),
    snr_db,
    latency_ms,
    jitter_ms,
    packet_loss_pct,
    gateway,
    ping_samples:     rtts,
    // NIC counters (real, from Npcap)
    packets_captured: nic.packets_captured  ?? null,
    bandwidth_mbps:   nic.bandwidth_mbps    ?? null,
    packet_rate_pps:  nic.packet_rate_pps   ?? null,
    active_flows:     nic.active_flows      ?? null,
    capture_iface:    nic.iface             ?? null,
    // EW threat inputs (real)
    timing_drift_ms,          // NTP phase offset in ms
    iat_cv,                   // inter-flow timing regularity (0=beaconing)
    bytes_per_pkt,            // real avg payload bytes per packet
    rst_spike,                // true if RST rate spike detected
    flow_timestamps,          // real flow completion timestamps for pattern analysis
    timestamp: now,
  }
  _signalTs = now
  return _signalCache
}

// Background refresh — run immediately, then every 6s
_collectSignalStats().catch(() => {})
setInterval(() => _collectSignalStats().catch(() => {}), 6000)

app.get('/api/signal/stats', async (req, res) => {
  try {
    // Return cache if fresh (<12s old), else collect now
    const age = Date.now() - _signalTs
    const data = (age < 12000 && _signalCache) ? _signalCache : await _collectSignalStats()
    res.json({ ok: true, ...data })
  } catch (e) {
    res.status(503).json({ ok: false, error: e.message })
  }
})

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err)
  res.status(err.status || 500).json({
    error: err.message || 'Internal server error',
    timestamp: Date.now()
  })
})

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Not found',
    path: req.url,
    timestamp: Date.now()
  })
})


// Start server
server.listen(config.port, config.host, async () => {
  console.log(`\n📡 Server started at http://${config.host}:${config.port}`)
  console.log('🔄 Initializing services...\n')
  
  try {
    await initializeServices()
    console.log('\n✅ Ghost Messenger Backend is running!')
    console.log(`📡 REST API: http://${config.host}:${config.port}`)
    console.log(`🔌 WebSocket: ws://${config.host}:${config.port}/ws`)
    console.log('\nPress Ctrl+C to stop\n')
  } catch (error) {
    console.error('❌ Failed to initialize services:', error)
    console.error('Server will shutdown...')
    process.exit(1)
  }
})

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('\n\n🛑 Shutting down gracefully...')
  await veddb.close()
  server.close(() => {
    console.log('✓ Server closed')
    process.exit(0)
  })
})

