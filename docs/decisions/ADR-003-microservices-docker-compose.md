# ADR-003: Microservices Architecture over Monolith

**Date:** 2025-11  
**Status:** Accepted  
**Project:** MailGuard

---

## Context

MailGuard needs to run multiple distinct workloads: a Node.js API gateway, a Python FastAPI phishing detector, a Python AI summarization service, HashiCorp Vault, and PostgreSQL. The question was whether to build a monolith or separate services.

---

## Decision

Use a **microservices architecture** with Docker Compose orchestration. Each service runs in its own container with a single responsibility.

---

## Alternatives Considered

### Monolith (single Node.js or Python app)
- ✅ Simpler deployment, single process
- ✅ No network latency between components
- ❌ Mixing Node.js (gateway) and Python (ML models) in one process is impractical
- ❌ A bug in the AI service would take down the entire API
- ❌ Cannot scale individual components independently
- ❌ Doesn't reflect enterprise architecture patterns

### Microservices with Kubernetes
- ✅ Production-grade orchestration
- ✅ Auto-scaling, self-healing
- ❌ Massive operational overhead for a 5-service application
- ❌ Overkill for current scale
- ❌ Would require managed k8s (cost) or self-managed k3s (complexity)

### Microservices with Docker Compose ✅ Chosen
- ✅ Right level of complexity for current scale
- ✅ Each service has a single responsibility
- ✅ Language-agnostic — Node.js gateway + Python ML services coexist naturally
- ✅ Easy to migrate to Kubernetes when scale requires it
- ✅ Failure isolation — AI service crash doesn't affect phishing detection
- ✅ Independent deployment of individual services
- ❌ No auto-scaling or self-healing (acceptable at current scale)

---

## Service Responsibilities

| Service | Language | Responsibility |
|---|---|---|
| gateway | Node.js | Auth, rate limiting, routing |
| phishing-detector | Python FastAPI | Threat intelligence engines |
| ai-service | Python FastAPI | HuggingFace summarization |
| vault | HashiCorp Vault | Secrets management |
| postgres | PostgreSQL | User data, scan history |

---

## Consequences

**Positive:**
- Clear separation of concerns — each service can be understood independently
- Python services can use ML libraries (transformers, requests) without polluting the Node.js gateway
- Individual services can be rebuilt/redeployed without downtime
- Demonstrates understanding of distributed systems

**Negative:**
- Network calls between services add latency vs in-process calls
- Requires Docker networking configuration
- More complex debugging (logs spread across 5 containers)
- Each service needs its own dependency management
