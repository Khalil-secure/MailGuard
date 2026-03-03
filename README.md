# MailGuard 🛡️

> Production-grade email phishing detection SaaS — built from scratch by a junior dev who refused to give up.

**Live demo:** https://mail-guard-beta.vercel.app


---

## What is this?

MailGuard is a full-stack SaaS platform that detects phishing emails in real time. Paste any suspicious email, and the system cross-references it against 5 global threat intelligence databases, returning a clear verdict: **SAFE**, **SUSPICIOUS**, or **PHISHING**.

Built with a microservices architecture, Google OAuth authentication, PostgreSQL user accounts, HashiCorp Vault secret management, and deployed on Google Cloud — this is a real product, not a toy.

![MailGuard detecting phishing](screenvideo/Mailguard_alt_preview.gif)

---

## Architecture
<img width="2525" height="1724" alt="mermaid-diagram-2026-02-28-154242" src="https://github.com/user-attachments/assets/67a59f01-5583-4892-8f61-46f7dbe355eb" />

---

## Architecture Decisions
See [docs/decisions/](docs/decisions/) for full ADRs explaining every major technical choice.

---

### Containers

| Container | Stack | Port | Role |
|---|---|---|---|
| `gateway` | Node.js / Express | 3000 | Auth, routing, rate limiting |
| `ai-service` | Python / FastAPI | 8000 | AI microservices |
| `phishing-detector` | Python / FastAPI + aiosmtpd | 8001 / 1025 | Threat analysis engine |
| `vault` | HashiCorp Vault | 8200 | Secret management |
| `postgres` | PostgreSQL 15 | 5432 | Users + scan history |

---

## Features

### Authentication
- **Google OAuth 2.0** — one-click sign in
- **JWT tokens** — 7-day expiry, stateless
- **PostgreSQL user store** — persists across restarts

### Rate Limiting
- **10 free scans per day** per user
- Tracked in PostgreSQL per user per 24h window
- `429` response with upgrade message when limit reached

### Phishing Detection Engine
- **Typosquatting** — Levenshtein distance against 25+ known brands (`paypa1.com → paypal.com`)
- **VirusTotal** — URL and domain reputation (70+ AV engines)
- **AlienVault OTX** — Threat pulse detection
- **AbuseIPDB** — IP abuse confidence scoring
- **Google Safe Browsing** — Google's threat database
- **SPF / DMARC** — DNS-level sender validation
- All checks run in **parallel** via `asyncio.gather`

### Secret Management
- **HashiCorp Vault** in production mode with file storage
- Secrets persist across container restarts
- Services fetch secrets at runtime — zero secrets on disk
- Unseal key threshold: 3 of 5 keys required

### Dual Interface
- **REST API** — `POST /phishing/analyze`
- **SMTP Server** — receives emails on port 1025

### Frontend
- Single paste box — paste raw email, headers auto-extracted
- Instant verdict with full breakdown per engine
- Scan counter showing remaining daily scans
- Newsletter signup for lead capture

## Observability

| Tool | Role | Port |
|------|------|------|
| Prometheus | Metrics collection | 9090 |
| Grafana | Dashboard & visualization | 3001 |
| Loki | Log aggregation | 3100 |
| Promtail | Log shipping | - |

**Dashboard panels:**
- Total scans / phishing detected / rate limit hits / active users
- Scans per minute (live)
- Verdict breakdown (donut chart)
- Threat engine hits per API
- API response time p95
- 🌱 Carbon footprint (gCO2 per scan, GCP europe-west1)
![MailGuard monitoring dashboard](screenshots_dashboard/first-dashboard%20.png)

![MailGuard monitoring dashboard](screenshots_dashboard/second-dashboard-carbonne-emission.png)

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | HTML / CSS / JS — deployed on Vercel |
| Gateway | Node.js 20, Express, Passport, JWT, pg |
| Backend services | Python 3.11, FastAPI, uvicorn, httpx |
| SMTP server | aiosmtpd |
| Secret management | HashiCorp Vault (file storage) |
| Database | PostgreSQL 15 |
| Containerization | Docker, Docker Compose |
| Reverse proxy | Nginx |
| Tunnel | Cloudflare Tunnel |
| Cloud | Google Cloud Compute Engine (e2-medium, Ubuntu 22.04) |
| Threat APIs | VirusTotal, AlienVault OTX, AbuseIPDB, Google Safe Browsing |

---

## Project Structure

```
mailguard/
├── docker-compose.yml
├── .env.example
├── .gitignore
├── README.md
├── frontend/
│   ├── index.html
│   └── vercel.json
└── services/
    ├── gateway/
    │   ├── index.js         # Express gateway, OAuth, JWT, rate limiting
    │   ├── auth.js          # JWT middleware
    │   ├── package.json
    │   └── Dockerfile
    ├── ai-service/
    │   ├── main.py          # FastAPI summarizer
    │   ├── requirements.txt
    │   └── Dockerfile
    └── phishing-detector/
        ├── smtp_server.py   # SMTP receiver
        ├── api.py           # FastAPI REST endpoint
        ├── checks.py        # All threat intelligence checks
        ├── vault_client.py  # HashiCorp Vault secret loader
        ├── requirements.txt
        └── Dockerfile
```

---

## Getting Started

### Prerequisites
- Docker Desktop
- Git
- API keys (see below)
- Google OAuth credentials

### 1. Clone

```bash
git clone https://github.com/khalil-secure/mailguard.git
cd mailguard
```

### 2. Environment variables

```bash
cp .env.example .env
```

Fill in `.env`:

```env
# Threat intelligence
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
ALIENVAULT_API_KEY=
GOOGLE_SAFEBROWSING_API_KEY=
HUGGINGFACE_API_KEY=

# Auth
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GOOGLE_CALLBACK_URL=
JWT_SECRET=
SESSION_SECRET=

# Database
DATABASE_URL=postgresql:

# Vault
VAULT_TOKEN=
VAULT_ADDR=
```

### 3. Run

```bash
docker compose up -d
```

### 4. Initialize Vault

```bash
# Unseal Vault (first time only)
docker exec -e VAULT_ADDR='http://127.0.0.1:8200' mailguard-vault vault operator init

# Unseal with 3 of 5 keys
docker exec -e VAULT_ADDR='http://127.0.0.1:8200' mailguard-vault vault operator unseal KEY1
docker exec -e VAULT_ADDR='http://127.0.0.1:8200' mailguard-vault vault operator unseal KEY2
docker exec -e VAULT_ADDR='http://127.0.0.1:8200' mailguard-vault vault operator unseal KEY3

# Load secrets
docker exec -e VAULT_ADDR='http://127.0.0.1:8200' -e VAULT_TOKEN='YOUR_ROOT_TOKEN' \
  mailguard-vault vault kv put mailguard/api-keys \
  VIRUSTOTAL_API_KEY=... \
  ABUSEIPDB_API_KEY=... \
  ALIENVAULT_API_KEY=... \
  GOOGLE_SAFEBROWSING_API_KEY=... \
  HUGGINGFACE_API_KEY=...
```

---

## API Reference

### Authentication

```
GET /auth/google              # Redirect to Google OAuth
GET /auth/google/callback     # OAuth callback
GET /auth/me                  # Get current user + scan count (JWT required)
```

### Phishing Analysis

```
POST /phishing/analyze        # Requires Bearer token
```

**Request:**
```json
{
  "sender": "security@paypa1.com",
  "subject": "Urgent: Verify your account",
  "body": "Click here: http://suspicious.ru/login"
}
```

**Response:**
```json
{
  "verdict": "PHISHING",
  "checks": [
    { "verdict": "PHISHING", "reason": "'paypa1.com' looks like 'paypal.com' (distance: 1)" },
    { "source": "virustotal", "malicious": 10, "suspicious": 1, "verdict": "PHISHING" },
    { "source": "safebrowsing", "verdict": "PHISHING", "flagged_urls": ["..."] }
  ],
  "sender_domain": "paypa1.com",
  "dns_checks": { "spf": true, "dmarc": false }
}
```

**Rate limit response (429):**
```json
{
  "error": "Daily limit reached",
  "message": "You have used all 10 free scans for today. Upgrade to Pro for unlimited scans.",
  "scans_used": 10,
  "limit": 10
}
```

---

## API Keys

| Service | Free Tier | Link |
|---|---|---|
| VirusTotal | 500 req/day | https://virustotal.com |
| AbuseIPDB | 1000 req/day | https://abuseipdb.com |
| AlienVault OTX | Unlimited | https://otx.alienvault.com |
| Google Safe Browsing | Free | https://developers.google.com/safe-browsing |
| HuggingFace | Free tier | https://huggingface.co |

---

## Roadmap

- [ ] Stripe integration — Pro plan for unlimited scans
- [ ] Browser extension — real-time Gmail/Outlook flagging
- [ ] File/attachment scanning — VirusTotal hash lookup
- [ ] Custom domain + SSL (Let's Encrypt)
- [ ] Admin dashboard — usage analytics
- [ ] Webhook API — integrate with email providers
- [ ] Mobile app

---

## The Story

This entire platform was built in a single extended session — every service verified working before the next was built, every problem debugged in production.

The stack includes microservices, OAuth, JWT, secret management, threat intelligence APIs, Docker orchestration, cloud deployment, and a real SaaS business model.

If you're a recruiter or hiring manager reading this: you just read the commit history. This is the work.

---

## License

MIT




