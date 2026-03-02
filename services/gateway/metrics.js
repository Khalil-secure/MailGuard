const client = require('prom-client')

// Create a registry
const register = new client.Registry()

// Add default Node.js metrics (memory, CPU, event loop)
client.collectDefaultMetrics({ register })

// ── CUSTOM METRICS ──

// Total scans with verdict label
const scansTotal = new client.Counter({
  name: 'mailguard_scans_total',
  help: 'Total number of email scans performed',
  labelNames: ['verdict', 'user_type'], // user_type: free | authenticated
  registers: [register]
})

// Threat engine hits
const engineHits = new client.Counter({
  name: 'mailguard_engine_hits_total',
  help: 'Total hits per threat intelligence engine',
  labelNames: ['engine'],
  registers: [register]
})

// Rate limit hits
const rateLimitHits = new client.Counter({
  name: 'mailguard_rate_limit_hits_total',
  help: 'Total number of rate limit rejections',
  labelNames: ['limit_type'], // free_tier | daily_limit | ip_limit
  registers: [register]
})

// Active users gauge
const activeUsers = new client.Gauge({
  name: 'mailguard_active_users_total',
  help: 'Total number of registered users',
  registers: [register]
})

// Request duration histogram
const requestDuration = new client.Histogram({
  name: 'mailguard_request_duration_ms',
  help: 'API request duration in milliseconds',
  labelNames: ['method', 'route', 'status'],
  buckets: [50, 100, 250, 500, 1000, 2500, 5000, 10000],
  registers: [register]
})

// Auth events
const authEvents = new client.Counter({
  name: 'mailguard_auth_events_total',
  help: 'Authentication events',
  labelNames: ['event'], // login | logout | token_expired
  registers: [register]
})

module.exports = {
  register,
  scansTotal,
  engineHits,
  rateLimitHits,
  activeUsers,
  requestDuration,
  authEvents
}
