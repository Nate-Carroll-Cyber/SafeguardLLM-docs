# Agent Governance & Control-Plane Assessment — Safeguard LLM v2.5

**Objective:** Move the Safeguard LLM (`counter-spy`) pilot from a Beta/local-Firebase posture to secure, auditable production by enforcing human-linked authentication, fine-grained authorization, ephemeral credentialing, and lifecycle governance through a unified control plane.

**Assessment date:** 2026-07-08 · **Source of record:** `github.com/Nate-Carroll-Cyber/SafeguardLLM-docs` (`main`)

---

## Executive Summary

Safeguard LLM is architecturally strong on **plane separation** (control-plane defense vs. inference-plane response) and **fail-secure** behavior, and it already keeps provider secrets out of the browser bundle. However, from an *agent-governance* standpoint the system is still at pilot-grade identity: **execution routes are protected by a single shared static bearer token**, **JWT/OIDC per-request validation is not implemented**, secrets live in a gitignored `.env` (`dotenv`) rather than a vault, and there is **no automated credential rotation, no CIBA/RAR human-in-the-loop for high-risk actions, and no universal-logout/revocation path**. These are the load-bearing gaps to close before production.

Governance maturity snapshot:

| Control domain | Current state | Target state | Gap severity |
|---|---|---|---|
| Human identity tethering | Firebase Google OAuth for UI login; **API layer uses shared bearer token, not per-user identity** | OIDC/OAuth2 per-request identity on every execution route | **High** |
| Identity chain integrity (downstream) | Broken at the provider hop — outbound calls to judge/responder use system credentials, not user-scoped tokens | Token exchange preserving `sub` to downstream trust domains | **High** |
| Credential vaulting | `.env.demo.local` / `dotenv`; migration to Secrets Manager planned, not done | AWS Secrets Manager + no secrets in logs/LLM context | **High** |
| Ephemeral credentials / rotation | Static long-lived bearer token; no rotation documented | Auto-rotation (≤90d) via central vault; short-lived tokens | **High** |
| Fine-grained / relationship-based authz | Firestore rules enforce admin-only reads + owner-scoped Sam Spade sessions | RAG/KB scopes mapped to authenticated human's permissions | **Medium** |
| Async human-in-the-loop (CIBA/RAR) | HITL/HOTL review queue + Global Pause exist, but no out-of-band per-action approval | CIBA + Rich Authorization Requests for sensitive ops | **Medium** |
| Agent/component registry | Docs describe components; no central identity registry with owners/intent | Unified registry: every agent/service has ID, owner, purpose | **Medium** |
| Shadow AI discovery | Not addressed | Discovery workflow + onboarding into registry | **Medium** |
| Universal logout / revocation | None (static token → no immediate revocation) | Cross-system session + token revocation on threat | **High** |
| Lifecycle (onboarding/review/deprovision) | Not documented | Automated access reviews + deprovisioning | **Medium** |

---

## Phase 1 — Identity & Access Design

### 1.1 Human identity tethering (OIDC/OAuth 2.0)

**Current.** The UI authenticates users via **Firebase Authentication (Google OAuth 2.0)**, with a "Continue in Local Review Mode" bypass on `localhost` (in-memory, no Firebase writes). Critically, the **backend execution routes** (`/v1/intercept`, `/v1/translate`, `/v1/instruction-monitor/*`, `/v1/ctf/sam-spade/*`) authenticate with a **shared static bearer token** (`INTERCEPT_BEARER_TOKEN`, matched against the browser's `VITE_BACKEND_BEARER_TOKEN`). The backend does a static string comparison — **JWT/OIDC validation is explicitly not implemented**. Sam Spade routes additionally require an `x-counter-spy-user-id` caller header, but that header is **client-asserted**, not cryptographically bound to a verified identity.

**Governance finding.** Every agentic action (safeguard evaluation, downstream forwarding, translation, CTF interrogation) currently executes under a **generic shared credential**, not a verified human identity. This is the core anti-pattern the control-plane standard forbids: the shared token severs the link between human intent and agent action and makes per-user accountability impossible in the audit log except via the self-asserted `userId`/`x-counter-spy-user-id`.

**Recommendation.**
- Replace the shared bearer token on all `/v1/*` execution routes with **per-request OIDC/OAuth 2.0 validation** (validate `sub`, `aud`, `exp`, signature against the Firebase/OIDC JWKS on every request; no local caching so revocation is immediate — this matches the docs' own stated production target).
- Derive `userId` / owner scoping from the **verified `sub` claim**, never from a client-supplied header. Deprecate trust in `x-counter-spy-user-id` as an authorization input; keep it only as a correlation hint.
- Keep "Local Review Mode" strictly non-production and ensure it can never write to shared/prod data stores.

### 1.2 Identity chain integrity across downstream calls

**Current.** When a `CLEAN` prompt is forwarded to the downstream responder (OpenAI/Gemini), or when embeddings/translation are requested, the backend uses **system-owned provider credentials** (`RESPONDER_API_KEY`, `SAFEGUARDS_API_KEY`, Lara creds). The human's identity does **not** propagate to those downstream domains.

**Governance finding.** The identity chain **breaks at the backend→provider boundary**. This is partly unavoidable (frontier providers don't consume the deployer's user tokens), but it means downstream usage cannot be attributed to a specific human at the provider side — a documented forensic gap ("Firestore logs are independent of downstream-provider abuse-monitoring windows").

**Recommendation.**
- Where a downstream system supports it (internal RAG, future Bedrock, internal microservices like a split Sam Spade service), use **secure token exchange (RFC 8693)** to carry the user `sub` across trust domains rather than a shared service credential.
- For opaque frontier providers, **stamp a verified per-user correlation id** into every outbound request's metadata and audit record so provider-side abuse reports can be reconciled to a human. Preserve the SHA-256 prompt-hash linkage already in the audit schema.

### 1.3 Relationship-based / fine-grained authorization

**Current.** Firestore rules are the strongest existing authz control: users **cannot self-assign elevated roles**; `config/system` and `knowledge_base` reads are **admin-only**; `config/governance` is readable by authenticated sessions; audit-log client creates are restricted to an allowlisted field set with owner/type/size checks; backend-owned security fields (verdicts, gateway status, responder telemetry) **cannot be forged client-side**. Sam Spade sessions are **owner-scoped** (`ownerUserId`; cross-owner access returns 404 so existence isn't disclosed). Roles referenced: **Analyst / Administrator**, with an "Analyst Mode" admin toggle.

**Governance finding.** Data-layer authorization is well designed, but **API-layer authorization is coarse**: any holder of the shared bearer token can call any protected execution route. There is **no documented RBAC matrix mapping Analyst vs. Administrator to specific API operations** (e.g., who may mark an instruction reviewed-ADVERSARIAL, who may trigger governance sync, who may promote to the Golden Set / KB).

**Recommendation.**
- Define an explicit **RBAC/ReBAC matrix** at the API layer keyed to the verified identity's role claim, so agent scopes map directly to the authenticated human's permissions (e.g., `instruction-monitor:write` and `kb:promote` restricted to Administrators; `intercept:execute` to Analysts).
- For the knowledge base / Golden Set (RAG-adjacent), ensure retrieval and promotion honor the requesting human's permission set rather than a blanket service scope — preventing an agent from inheriting broad read access.

---

## Phase 2 — Operations & Control Plane

### 2.1 Credential vaulting

**Current.** Secrets (`POSTGRES_PASSWORD`, `INSTRUCTION_MONITOR_DATABASE_URL`, Lara creds, bearer tokens, provider API keys) live in a **gitignored `.env.demo.local`** loaded via **`dotenv ^17.2.3`**. The docs flag this as a known risk with a **planned** migration to AWS Secrets Manager. On the positive side, provider secrets are **never shipped in the client bundle** (browser-side inference disabled), with one intentional exception: a **browser-memory-only `safeguardApiKey`** for local LM Studio testing in Analyst Chat.

**Governance finding.** Secrets are file-based and static, not vaulted or ephemeral. The browser-memory `safeguardApiKey` exception, while scoped, is a credential in client memory and should be treated as a residual exposure.

**Recommendation.**
- Complete the **AWS Secrets Manager** migration before production; remove provider keys and bearer tokens from `.env` in all non-local environments.
- Enforce a **"no secrets in logs or LLM context"** guarantee: verify safeguard-judge and responder request/response logging redacts `Authorization` headers and API keys, and that keys can never enter a prompt sent to a model.
- Retire the browser-memory `safeguardApiKey` path for production, or gate it behind a build-time flag that is off by default.

### 2.2 Ephemeral credentialing & rotation

**Current.** The `INTERCEPT_BEARER_TOKEN` is **long-lived and static**; no rotation cadence is documented. Postgres uses SCRAM auth; the demo DB is tmpfs/ephemeral.

**Recommendation.**
- Move to **short-lived, auto-rotated credentials** issued from the vault (target ≤90-day rotation for any residual static secret; minutes-to-hours TTL for request tokens once OIDC is in place).
- Rotate the Postgres password and Lara/provider keys automatically via Secrets Manager rotation lambdas.

### 2.3 Central agent/component registry

**Current.** The documentation describes each component (frontend Shield, backend gateway, pgvector, embedding sidecar, safeguard judge host, responder, Sam Spade service) but there is **no central registry** that assigns each a **unique identity, owner, and documented intent**.

**Recommendation.**
- Stand up a **unified control-plane registry** listing every service/agent identity (backend gateway, embedding sidecar, judge host, responder connector, Sam Spade service) with: unique workload identity (e.g., IAM role / SPIFFE ID), human owner, purpose, allowed egress, and data classifications touched. This directly supports Annex IV documentation and Shadow-AI discovery.

### 2.4 Async human-in-the-loop (CIBA / RAR)

**Current.** Safeguard LLM has strong **synchronous** human governance: HITL routes borderline traffic to `PENDING_REVIEW`; **HOTL Global System Pause** (DEFCON-1 kill switch) fires on sustained critical spikes, canary-token detection, Bedrock/Gemini 503 degradation, and ReDoS >1000ms. There is, however, **no out-of-band per-action approval** (e.g., mobile push approval) for individually sensitive operations.

**Governance finding.** The kill switch is coarse (global), not per-transaction. High-consequence operations — promoting a prompt into the **Golden Set/KB** (which shapes future model fine-tuning), marking an instruction **reviewed-ADVERSARIAL** (which causes future blocking), or overriding a safeguard verdict — currently lack an explicit **backchannel approval**.

**Recommendation.**
- Implement **CIBA (Client-Initiated Backchannel Authentication)** with **Rich Authorization Requests (RAR)** for high-risk, state-changing operations: KB/Golden-Set promotion, instruction-record adversarial labeling, governance-policy changes, and any manual verdict override. RAR should encode the specific resource and action so the approver sees exactly what they authorize.
- Keep the existing Global Pause as the containment layer; add per-action approval as the authorization layer.

---

## Phase 3 — Monitoring, Lifecycle & Revocation

### 3.1 Shadow AI discovery

**Current.** Not addressed for the deployer's own environment. (Note: the product itself detects *adversarial tool-use patterns* via its MCP/A2A safety policy, but that is inbound-threat detection, not discovery of unmanaged agents in the operator's estate.)

**Recommendation.**
- Add a **Shadow-AI discovery workflow**: enumerate all outbound LLM/embedding/translation egress from the gateway and reconcile against the registry, flagging any endpoint (e.g., an unregistered LM Studio/Ollama host or a new responder base URL) that isn't an approved, owned identity. The system's own egress-allowlist posture (embeddings restricted to private network; browser cannot override provider base URLs) is a strong foundation to build this on.

### 3.2 Centralized visibility & lifecycle

**Current.** Rich telemetry exists: structured JSON events (`safeguard_decision`, `metric_increment` for `safeguard.schema`/`safeguard.divergence`, `instruction_embedding_generated`), a Metrics dashboard (Defense Funnel, Feature Pressure, threat velocity), and an audit trail with per-decision attribution. Delivery to **CloudWatch** and **formal Z-score incidenting / PagerDuty-Slack escalation are production targets, not implemented**.

**Recommendation.**
- Wire telemetry to the central collector (CloudWatch) and implement the **Z-score incidenting (`Z > 5.0`) and escalation** already specified.
- Add **automated access reviews / certifications** and **deprovisioning** workflows so credentials and roles stay aligned with current tasks (none documented today).

### 3.3 Universal logout / revocation

**Current.** With a shared static bearer token, there is **no way to revoke a single user's access immediately** — rotating the token logs everyone out. The Global Pause halts traffic but does not revoke identities/tokens.

**Recommendation.**
- Implement **cross-system universal logout**: on threat detection, revoke the affected identity's sessions and downstream tokens across the gateway, Firestore session, and any exchanged downstream tokens. This is feasible once OIDC (no local token caching) replaces the static bearer token, giving immediate revocation.

---

## Prioritized Remediation Roadmap

| Priority | Action | Domain | Closes |
|---|---|---|---|
| P0 | Replace shared bearer token with per-request OIDC/OAuth2 validation on all `/v1/*` routes; derive identity from verified `sub` | Identity | High-severity identity + revocation gaps |
| P0 | Complete AWS Secrets Manager migration; remove secrets from `.env`; enforce no-secrets-in-logs/LLM-context | Vaulting | High |
| P0 | Add universal logout / token revocation (enabled by OIDC) | Revocation | High |
| P1 | Secure token exchange (RFC 8693) for internal downstream calls; per-user correlation id stamped to frontier-provider requests | Identity chain | High |
| P1 | Auto-rotation of all residual static secrets (≤90d) + short-lived request tokens | Ephemeral creds | High |
| P1 | CIBA + RAR for KB/Golden-Set promotion, adversarial labeling, verdict override, governance changes | Async HITL | Medium |
| P2 | Central agent/component registry (identity, owner, intent, egress) | Registry | Medium |
| P2 | Explicit API-layer RBAC/ReBAC matrix (Analyst vs Admin) mapped to verified role claims | Authz | Medium |
| P2 | Shadow-AI discovery workflow over gateway egress | Discovery | Medium |
| P2 | Wire CloudWatch + Z-score incidenting + escalation; automated access reviews/deprovisioning | Lifecycle | Medium |

---

## Strengths to Preserve

The following existing controls are consistent with the control-plane standard and should be retained through the migration: strict **control-plane / inference-plane separation**; **fail-secure defaults** on every critical component; **provider secrets excluded from the client bundle**; **Firestore rules** preventing role self-elevation and forged security fields; **owner-scoped Sam Spade sessions** with existence-hiding 404s; **egress restriction** of embeddings to private network; and **redaction-before-inference** (only redacted prompts reach any model).

---

*Prepared by the Agent Governance Architect skill. Items marked "planned/not implemented" reflect the repository's own stated target state as of the analyzed `main` branch; they are remediation targets, not assertions that the pilot is unsafe for its current Beta scope.*
