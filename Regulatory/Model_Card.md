# Counter-Spy.ai Model Governance Card

## 1. System Role

Counter-Spy.ai is a proxy LLM-as-a-Judge and mitigation stack. It is designed to sit between user prompts and a downstream responder model, applying local sanitization, policy enforcement, structured safeguard judging, and output review before or after provider inference.

The system is model-neutral. It does not assume a fixed Gemini, OpenAI, or open-weight model. Operational deployments must attach provider-specific model cards for the configured safeguard judge and downstream responder.

## 2. Model Boundaries

- **Local sanitizer:** TypeScript policy engine that runs before external inference and enforces PII/secret redaction, entropy thresholds, regex rules, blocked keywords, forbidden phrases, language recovery, and obfuscation detection.
- **Safeguard judge:** OpenAI-compatible API endpoint called by the backend `/v1/intercept` gateway. It receives the current System Configuration Safeguard Effective Prompt verbatim as the system prompt.
- **Downstream responder:** Separate responder model called only after local checks and the safeguard judge return a clean forwarding decision. Protected routes do not accept caller-supplied responder system prompts.
- **Sam Spade CTF:** Governed by the protected backend API and shared review/audit path. Sessions are bound to the authenticated caller. Clean gameplay replies now use the live downstream responder after local sanitizer and safeguard approval when responder routing is enabled, with backend-managed Sam Spade persona and scenario prompts appended to the responder instruction. When responder routing is disabled, clean gameplay replies use local responder passthrough after safeguard approval. Sensitive redaction placeholders are blocked before gameplay/responder inference and are masked as `Bad content.` on the CTF surface.

## 3. Runtime Configuration

Analyst Chat and Responder runtime configuration are intentionally separate.

- **Analyst Chat / safeguard configuration:** OpenAI-compatible base URL, model ID, and API key are backend-managed through `SAFEGUARDS_*` environment variables or a future secret manager. Protected backend execution rejects browser-supplied safeguard endpoint, key, model, and system-prompt overrides.
- **Responder configuration:** Provider, base URL, model ID, API key, and max context window are backend-managed through `RESPONDER_*` / `LLM_*` environment variables or a future secret manager. Protected responder execution rejects browser-supplied endpoint, key, model, and backend-prompt overrides.
- **Credential handling:** Browser-side direct provider inference and provider-key injection are disabled for protected execution paths. The browser sends the backend bearer credential to the gateway, not provider credentials.

## 4. Decision Contract

The safeguard path expects one structured JSON verdict contract: `{"verdict":"CLEAN|SUSPICIOUS|ADVERSARIAL","analystReasoning":"brief reason"}`. Legacy decision-shaped responses such as `ALLOW_AND_FORWARD`, `BLOCK`, `QUEUE_FOR_REVIEW`, or `FAIL_SECURE` are not accepted as allow-path output; malformed or schema-mismatched safeguard responses fail secure to `SUSPICIOUS` / `QUEUED`.

The instruction similarity monitor runs before responder forwarding. Exact SHA-256, loose SHA-256, and SimHash matches against stored adversarial instructions retain `ADVERSARIAL` severity and block. Semantic whole-prompt or chunk-embedding matches are `SUSPICIOUS` review evidence rather than automatic adversarial blocks.

The Safeguard Effective Prompt is the reviewable policy baseline, including forbidden-category, gibberish/obfuscation guidance, and promoted few-shot examples. System Configuration previews, edits, and hashes that prompt artifact, and protected backend execution forwards the current value verbatim to the safeguard judge. The current promoted recommended baseline hash and aligned current safeguard prompt hash are `78b54175e27126f42ae7f4204619170fd98a5422c5e77929e7822563ca8f9214`.

Audit and Metrics preserve backend safeguard attribution through `backendGatewayStatus`, `backendSafeguardVerdict`, `backendSafeguardReasoning`, `backendReachedSafeguard`, `localPrecheckLatencyMs`, `backendSafeguardLatencyMs`, `backendGatewayLatencyMs`, and `responderLatencyMs`. These fields distinguish local pre-inference blocks from backend safeguard/model interventions and keep safeguard latency separate from local responder passthrough latency.

## 5. Safety and Fail-Closed Behavior

Prompts are not forwarded directly to the responder. Eligible clean prompts must pass local sanitizer checks and the safeguard judge first. If the backend, safeguard judge, or responder cannot complete, the gateway fails closed and surfaces the error instead of silently bypassing controls.

Global System Pause halts automated forwarding, routes new Analyst Chat prompts into manual review, and stops active Bulk Ingest replay.

## 6. Transparency Requirements

For compliance review, maintain the following alongside this card:

- Provider model cards for the active safeguard judge and downstream responder.
- Current System Configuration hash and recommended baseline hash: `78b54175e27126f42ae7f4204619170fd98a5422c5e77929e7822563ca8f9214`.
- Active environment variable inventory for backend-managed credentials.
- Audit retention policy for Firestore and any provider-side logs.
- Known limitations, including local-review/demo behavior and the need to validate active provider model cards for the configured safeguard judge and responder.
