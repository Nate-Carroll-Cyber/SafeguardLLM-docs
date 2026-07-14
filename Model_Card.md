# Safeguard LLM Model Governance Card

## 1. System Role

Safeguard LLM is a proxy LLM-as-a-Judge and mitigation stack. It sits between user prompts and a downstream responder model, applying local sanitization, policy enforcement, structured safeguard judging, instruction-memory comparison, and output review before or after provider inference.

The system is model-neutral. Operational deployments must attach provider-specific model cards for the configured safeguard judge, embedding model, and downstream responder.

## 2. Model and Data Boundaries

- **Local sanitizer:** TypeScript policy engine that runs before external inference and enforces PII/secret redaction, entropy thresholds, regex rules, blocked keywords, forbidden phrases, language recovery, and obfuscation detection.
- **Safeguard judge:** OpenAI-compatible API endpoint called by the backend `/v1/intercept` gateway. The allowlisted `safeguardEffectivePrompt` is used as the judge system prompt. Candidate prompt text and deterministic preprocessing evidence are sent separately as user content.
- **Instruction similarity monitor:** PostgreSQL/pgvector store containing reviewed `ADVERSARIAL` instruction records, strict and loose hashes, SimHash fingerprints, optional whole-prompt embeddings, and optional chunk embeddings. Fingerprint matches retain the stored adversarial posture; semantic-only matches route to review.
- **Downstream responder:** Separate backend-managed responder called only after local checks, instruction-memory comparison, and the safeguard judge return a clean forwarding decision. Protected routes do not accept caller-supplied responder endpoints, credentials, model IDs, or system prompts.
- **Sam Spade CTF:** Governed by the protected backend API and shared review/audit path. Sessions are bound to the authenticated caller. The allowlisted `safeguardEffectivePrompt` is also used as the safeguard judge system prompt on Sam Spade message and solve routes. Clean gameplay uses backend-managed persona/scenario prompts and the downstream responder when routing is enabled; otherwise it uses local responder passthrough after safeguard approval.

## 3. Protected Runtime Contract

Protected request bodies use Zod object schemas with `.strict()` on their security-sensitive metadata boundaries. Unknown metadata fields are rejected rather than treated as runtime configuration.

- **Backend-owned safeguard runtime:** `SAFEGUARDS_API_BASE_URL` and `SAFEGUARDS_MODEL_ID` determine the actual safeguard endpoint and model. Browser-supplied base URL or model overrides are not accepted by `/v1/intercept` or the Sam Spade request schemas.
- **Intentional safeguard exceptions:** `/v1/intercept` accepts an optional browser-memory `safeguardApiKey`; when supplied, it takes precedence over `SAFEGUARDS_API_KEY`. It also accepts `safeguardEffectivePrompt`, which is used as the safeguard judge system prompt. Sam Spade message/solve metadata accepts `safeguardEffectivePrompt` but not a browser safeguard key.
- **Local UI selections:** The Analyst Runtime Settings base URL and model fields persist in browser `localStorage` under `counter_spy_safeguard_runtime_v1`. They are display/selection state only and are not forwarded as protected backend runtime overrides. The browser-entered safeguard key is React memory only and is cleared on reload.
- **Backend-owned responder runtime:** Provider, endpoint, API key, model ID, and system prompt come from `RESPONDER_*` / `LLM_*` environment configuration. Browser responder settings may support local UI telemetry and context estimates, but protected execution rejects those values as provider overrides.

Current code and demo defaults are configuration-dependent:

- Backend safeguard model default: `gpt-5.4-mini`.
- Docker demo safeguard model: `gpt-oss-safeguard-20b`.
- Instruction-monitor embedding model default: `gpt-oss-safeguard-20b`. This is a chat-model identifier used as the backend default and should be validated against the configured embeddings endpoint; the Docker demo overrides it with `nomic-embed-text`.
- OpenAI-compatible responder model default: `amazon.nova-micro-v1:0`.
- Gemini responder default: `gemini-2.5-flash`.

## 4. Decision Contract

The safeguard path expects one JSON verdict contract: `{"verdict":"CLEAN|SUSPICIOUS|ADVERSARIAL","analystReasoning":"brief reason"}`. Legacy decision-shaped responses such as `ALLOW_AND_FORWARD`, `BLOCK`, `QUEUE_FOR_REVIEW`, or `FAIL_SECURE` are not accepted as allow-path output; malformed or schema-mismatched safeguard responses fail secure to `SUSPICIOUS` / `QUEUED`.

The instruction similarity monitor runs before responder forwarding. Exact SHA-256, loose SHA-256, and SimHash matches against stored adversarial instructions retain `ADVERSARIAL` severity and block. Semantic whole-prompt or chunk-embedding matches are `SUSPICIOUS` review evidence rather than automatic adversarial blocks.

The Safeguard Effective Prompt is the reviewable policy baseline. System Configuration previews, edits, and hashes the prompt artifact, and protected backend execution uses the submitted value as the safeguard judge system prompt. `DEFAULT_SYSTEM_CONFIG` hardcodes the recommended prompt in `safeguardEffectivePromptOverride`; empty legacy values and previous app-generated baselines normalize back to that promoted default, while custom non-empty prompts remain visible as drift.

The displayed recommended/current hash `590a286e60b99b0b353222b3ddaaa131db925a1f4d6222a0c3b1b3e49d203ad0` is computed at runtime with `crypto.subtle.digest`. The source contains the prompt text and hashing implementation, not a build-time assertion proving that literal hash; deployments should verify it in the running UI.

## 5. Safety and Fail-Closed Behavior

Eligible prompts must pass local sanitizer checks, instruction-memory comparison, and the safeguard judge before responder forwarding. Safeguard failure returns the structured `SHIELD_ERROR` review path; responder failure returns a plain upstream error response. Neither failure silently bypasses controls.

Global System Pause halts automated forwarding, routes new Analyst Chat prompts into manual review, and stops active Bulk Ingest replay.

## 6. Transparency Requirements

For compliance review, maintain:

- Provider model cards for the active safeguard judge, embedding model, and responder.
- Runtime verification of the current and recommended Safeguard Effective Prompt hashes.
- Active environment-variable and secret-source inventories.
- PostgreSQL/pgvector retention, access-control, seed-provenance, and backup policies.
- Firestore and provider-side audit retention policies.
- Validation that deployment parameters, backend defaults, and provider configuration use the intended canonical model IDs.
- Known local-review/demo limitations and the active provider model cards.
