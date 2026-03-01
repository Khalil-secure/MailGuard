# ADR-002: Google OAuth 2.0 for Authentication

**Date:** 2025-12  
**Status:** Accepted  
**Project:** MailGuard

---

## Context

MailGuard needs user authentication to enforce per-user rate limiting (10 scans/day free tier) and to support a future paid plan. The authentication system needs to be secure, low-friction for users, and maintainable by a solo developer.

---

## Decision

Use **Google OAuth 2.0** with JWT tokens for session management. No passwords stored anywhere in the system.

---

## Alternatives Considered

### Username + password (bcrypt)
- ✅ No third-party dependency
- ❌ We become responsible for password storage, reset flows, breach notifications
- ❌ High friction for users (another password to remember)
- ❌ OWASP Top 10 attack surface (credential stuffing, brute force)
- ❌ Significant development overhead for a solo project

### Auth0 / Clerk
- ✅ Fully managed, feature-rich
- ✅ Handles MFA, social login, user management
- ❌ Vendor lock-in
- ❌ Free tier limits (7,000 MAU for Auth0)
- ❌ Adds cost as user base grows
- ❌ Hides the OAuth flow — less educational value

### Passport.js with multiple strategies
- ✅ Flexible, supports many providers
- ❌ More boilerplate than a manual OAuth implementation
- ❌ Adds dependency for something manageable manually
- ❌ Session-based by default — doesn't fit a stateless API

### Google OAuth 2.0 (manual) + JWT ✅ Chosen
- ✅ Google handles password security, MFA, breach detection
- ✅ Zero password storage liability
- ✅ High trust — users already have Google accounts
- ✅ JWT tokens are stateless — no server-side session storage needed
- ✅ Understanding the OAuth flow manually is more valuable than using an abstraction
- ❌ Requires Google Cloud Console setup
- ❌ Only supports Google accounts (sufficient for current target users)

---

## Implementation Details

```
User → /auth/google → Google consent screen
Google → /auth/google/callback (with code)
Backend exchanges code for access_token
Backend fetches user info from Google
Upsert user in PostgreSQL
Issue JWT (7-day expiry, signed with secret from Vault)
Redirect to frontend with token in URL
Frontend saves token to localStorage + chrome.storage
```

---

## Consequences

**Positive:**
- Zero password-related security liability
- Instant user trust (Google branding on consent screen)
- JWT tokens enable stateless API — scales horizontally
- Chrome extension can share auth state via chrome.storage

**Negative:**
- Users without Google accounts cannot sign in (acceptable trade-off for now)
- Cloudflare tunnel URL in OAuth redirect URI must be updated when tunnel changes
- JWT tokens cannot be invalidated before expiry without a blocklist (future improvement)
