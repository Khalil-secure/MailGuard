const express = require('express')
const cors = require('cors')
const axios = require('axios')
const jwt = require('jsonwebtoken')
const { Pool } = require('pg')
const { createProxyMiddleware } = require('http-proxy-middleware')

const app = express()
app.use(cors({ origin: true, credentials: true }))
app.use(express.json())

// PostgreSQL
const pool = new Pool({ connectionString: process.env.DATABASE_URL })

// Init DB tables
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      google_id VARCHAR(255) UNIQUE NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      name VARCHAR(255),
      avatar VARCHAR(500),
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS scans (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      scanned_at TIMESTAMP DEFAULT NOW()
    );
  `)
  console.log('✅ Database initialized')
}

initDB().catch(console.error)

// JWT middleware
function verifyToken(req, res, next) {
  const auth = req.headers.authorization
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' })
  }
  try {
    req.user = jwt.verify(auth.split(' ')[1], process.env.JWT_SECRET)
    next()
  } catch {
    res.status(401).json({ error: 'Invalid token' })
  }
}

// Rate limit — 10 scans/day
async function checkRateLimit(req, res, next) {
  const userId = req.user.id
  const result = await pool.query(`
    SELECT COUNT(*) FROM scans
    WHERE user_id = $1
    AND scanned_at > NOW() - INTERVAL '24 hours'
  `, [userId])
  
  const count = parseInt(result.rows[0].count)
  if (count >= 10) {
    return res.status(429).json({
      error: 'Daily limit reached',
      message: 'You have used all 10 free scans for today. Upgrade to Pro for unlimited scans.',
      scans_used: count,
      limit: 10
    })
  }
  req.scans_used = count
  next()
}

// Record scan
async function recordScan(userId) {
  await pool.query('INSERT INTO scans (user_id) VALUES ($1)', [userId])
}

// ── ROUTES ──

// Health
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'gateway' })
})

// Google OAuth — Step 1: redirect to Google
app.get('/auth/google', (req, res) => {
  const params = new URLSearchParams({
    client_id: process.env.GOOGLE_CLIENT_ID,
    redirect_uri: process.env.GOOGLE_CALLBACK_URL,
    response_type: 'code',
    scope: 'openid email profile',
    access_type: 'offline'
  })
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`)
})

// Google OAuth — Step 2: callback
app.get('/auth/google/callback', async (req, res) => {
  try {
    const { code } = req.query

    // Exchange code for tokens
    const tokenRes = await axios.post('https://oauth2.googleapis.com/token', {
      code,
      client_id: process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
      redirect_uri: process.env.GOOGLE_CALLBACK_URL,
      grant_type: 'authorization_code'
    })

    // Get user info
    const userRes = await axios.get('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: `Bearer ${tokenRes.data.access_token}` }
    })

    const { id, email, name, picture } = userRes.data

    // Upsert user in PostgreSQL
    const result = await pool.query(`
      INSERT INTO users (google_id, email, name, avatar)
      VALUES ($1, $2, $3, $4)
      ON CONFLICT (google_id) DO UPDATE
      SET name = $3, avatar = $4
      RETURNING *
    `, [id, email, name, picture])

    const user = result.rows[0]

    // Issue JWT
    const token = jwt.sign(
      { id: user.id, email: user.email, name: user.name },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    )

    // Redirect to frontend with token
    res.redirect(`https://mail-guard-beta.vercel.app?token=${token}&name=${encodeURIComponent(name)}`)

  } catch (err) {
    console.error('OAuth error:', err.response?.data || err.message)
    res.redirect('https://mail-guard-beta.vercel.app?error=auth_failed')
  }
})

// Get current user
app.get('/auth/me', verifyToken, async (req, res) => {
  const scans = await pool.query(`
    SELECT COUNT(*) FROM scans
    WHERE user_id = $1
    AND scanned_at > NOW() - INTERVAL '24 hours'
  `, [req.user.id])
  
  res.json({
    ...req.user,
    scans_used: parseInt(scans.rows[0].count),
    scans_remaining: Math.max(0, 10 - parseInt(scans.rows[0].count))
  })
})

// AI proxy
app.use('/ai', createProxyMiddleware({
  target: 'http://ai-service:8000',
  changeOrigin: true,
  pathRewrite: { '^/ai': '' }
}))

// Phishing proxy — protected + rate limited
app.use('/phishing', verifyToken, checkRateLimit, async (req, res) => {
  try {
    const targetPath = req.originalUrl.replace('/phishing', '')
    const url = `http://phishing-detector:8001${targetPath || '/'}`
    const response = await axios({
      method: req.method,
      url,
      data: req.body,
      headers: { 'Content-Type': 'application/json' },
      timeout: 120000
    })
    // Record the scan
    await recordScan(req.user.id)
    res.status(response.status).json(response.data)
  } catch (err) {
    console.error('Phishing proxy error:', err.message)
    res.status(502).json({ error: 'Phishing service unavailable' })
  }
})

app.listen(3000, () => console.log('Gateway running on port 3000'))
