# ADR-004: PostgreSQL for User Data and Scan Tracking

**Date:** 2025-12  
**Status:** Accepted  
**Project:** MailGuard

---

## Context

MailGuard needs to persist user accounts (from Google OAuth) and scan history (for rate limiting). The data model is relational: users have many scans, scans belong to users. Rate limiting requires querying "how many scans has this user done in the last 24 hours?"

---

## Decision

Use **PostgreSQL 15** running as a Docker container with a persistent volume.

---

## Alternatives Considered

### In-memory store (JavaScript Map/object)
- ✅ Zero setup, instant
- ❌ Data lost on every container restart
- ❌ Cannot survive VM reboots
- ❌ Not suitable for user accounts

### Redis
- ✅ Excellent for rate limiting (TTL-based counters)
- ✅ Very fast
- ❌ Not ideal for relational user data
- ❌ Would need a second database for user accounts
- ❌ Adds another service to manage

### SQLite
- ✅ Zero setup, file-based
- ✅ No separate container needed
- ❌ Single-writer limitation
- ❌ Not suitable if we scale to multiple gateway instances
- ❌ Less representative of enterprise environments

### MongoDB
- ✅ Flexible schema
- ❌ Our data is inherently relational (users → scans)
- ❌ Overkill flexibility for a simple schema
- ❌ Weaker consistency guarantees

### PostgreSQL ✅ Chosen
- ✅ ACID transactions — scan counts are always accurate
- ✅ Interval queries: `scanned_at > NOW() - INTERVAL '24 hours'` is elegant and performant
- ✅ Industry standard — same database used in most enterprise environments
- ✅ `ON CONFLICT DO UPDATE` (upsert) maps perfectly to OAuth user sync
- ✅ Scales well when combined with connection pooling
- ❌ Requires more setup than SQLite

---

## Schema Design

```sql
users (id, google_id, email, name, avatar, created_at)
scans (id, user_id → users.id, scanned_at)
```

Rate limit query:
```sql
SELECT COUNT(*) FROM scans
WHERE user_id = $1
AND scanned_at > NOW() - INTERVAL '24 hours'
```

This is a deliberate choice over storing a counter — keeping raw scan records allows future analytics (peak usage times, scan patterns, abuse detection).

---

## Consequences

**Positive:**
- Raw scan records enable future analytics and abuse detection
- Accurate rate limiting even under concurrent requests (ACID)
- Standard SQL knowledge transfers directly to enterprise environments

**Negative:**
- Slightly more complex rate limit query than a Redis TTL counter
- Requires periodic cleanup of old scan records (future: scheduled job)
