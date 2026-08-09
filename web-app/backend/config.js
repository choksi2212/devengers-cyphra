/**
 * Backend Configuration
 */

export const config = {
  // Server Configuration
  port: process.env.PORT || 3001,
  host: process.env.HOST || '0.0.0.0',   // listen on all interfaces — required for phone access

  // VedDB Configuration
  veddb: {
    host: process.env.VEDDB_HOST || '127.0.0.1',
    port: parseInt(process.env.VEDDB_PORT || '50051'),
    poolSize: 10,
    connectTimeout: 1000,    // not used by CLI mode but kept for compat
    requestTimeout: 8000     // veddb-client.exe needs ~200ms to start + connect
  },

  // CORS Configuration
  cors: {
    origin: process.env.CORS_ORIGIN || true,
    credentials: true
  },

  // Security
  apiKey: process.env.API_KEY || 'ghost_messenger_secret_key_change_in_production'
}

