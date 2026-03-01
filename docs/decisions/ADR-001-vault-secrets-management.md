# ADR-001: HashiCorp Vault for Secrets Management

**Date:** 2025-11  
**Status:** Accepted  
**Project:** MailGuard

---

## Context

MailGuard requires 6 API keys to operate (VirusTotal, AlienVault, AbuseIPDB, Google Safe Browsing, HuggingFace, JWT secret). These secrets need to be:
- Never stored in plaintext on disk or in version control
- Accessible to multiple Docker containers at runtime
- Rotatable without redeploying the application
- Auditable (who accessed what, when)

Early in development, secrets were stored in a `.env` file. A Google API key was accidentally committed to GitHub — Google detected it within minutes and sent an abuse notification. This incident made proper secrets management a hard requirement.

---

## Decision

Use **HashiCorp Vault** in production mode with file storage backend, running as a Docker container in the same network as the application services.

---

## Alternatives Considered

### `.env` files
- ✅ Simple, zero setup
- ❌ Easy to accidentally commit (already happened)
- ❌ No audit trail
- ❌ No rotation without redeployment
- ❌ Not acceptable for production

### AWS Secrets Manager
- ✅ Managed, no ops overhead
- ✅ Native IAM integration
- ❌ Locks infrastructure into AWS
- ❌ Costs money at scale
- ❌ Overkill for a self-hosted deployment

### Docker secrets
- ✅ Built into Docker Swarm
- ❌ Not available in plain Docker Compose
- ❌ No dynamic secret rotation
- ❌ Limited audit capabilities

### HashiCorp Vault ✅ Chosen
- ✅ Cloud-agnostic — works on any VM
- ✅ Dynamic secrets and rotation support
- ✅ Full audit log of every secret access
- ✅ Free and open source
- ✅ Industry standard — same tool used in enterprise environments
- ✅ KV engine maps naturally to our use case
- ❌ Requires manual unseal after every restart (mitigated with auto-unseal in future)

---

## Consequences

**Positive:**
- No plaintext secrets anywhere on disk
- Every secret access is logged with timestamp and accessor
- Secrets can be rotated by updating Vault without touching application code
- Demonstrates enterprise-grade secret hygiene to auditors

**Negative:**
- Vault must be unsealed after every VM restart (3 of 5 unseal keys required)
- Adds operational complexity vs simple `.env` files
- Single point of failure if Vault goes down (mitigated with health checks)

---

## Lessons Learned

Production mode (file storage) vs dev mode (memory) is a critical distinction. Dev mode resets all secrets on restart — we discovered this the hard way after a container restart wiped all keys. Production mode with a Docker volume persists secrets across restarts.
