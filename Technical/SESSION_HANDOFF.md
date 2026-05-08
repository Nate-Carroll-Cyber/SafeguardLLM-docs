# Session Handoff

This page captures the current implementation state so a future Codex session can continue without relying on a long chat transcript.

## Current Runtime Shape

- The Docker demo stack is the active local test path:
  - Frontend: `http://localhost:3000`
  - Backend health: `http://127.0.0.1:18080/healthz`
  - pgvector Postgres: `127.0.0.1:15432`
  - Rebuild command: `docker compose --env-file /Users/nate/Documents/Counter-Spy.ai/.env.demo.local -f /Users/nate/Documents/Counter-Spy.ai/docker-compose.demo.yml up --build -d`
- The instruction similarity monitor is enabled in the demo backend and uses `counter-spy-postgres`. The Postgres data directory is tmpfs-backed, initialized with SCRAM authentication and data checksums, so recreating the container starts with a clean instruction database. Sam Spade SQLite data still persists in its named Docker volume.
- The demo embedding sidecar is Ollama on the LM Studio Mac: `http://192.168.0.183:11434/v1`, model `nomic-embed-text`, `768` dimensions, max 4 chunks. The backend health endpoint should report `instructionMonitor.embeddings.source: "explicit"`.
- Similarity routing now separates fingerprint and semantic evidence: exact/loose SHA-256 or SimHash matches against stored `ADVERSARIAL` records remain adversarial blocks, while semantic whole-prompt or chunk-embedding matches are suspicious review events.
- Protected backend execution routes now require the shared bearer token. `/v1/intercept`, `/v1/translate`, `/v1/instruction-monitor/reviewed-adversarial`, and `/v1/ctf/sam-spade/*` reject unauthenticated requests.
- Browser callers no longer send backend runtime overrides for provider endpoints, model base URLs, backend-owned system prompts, responder, Sam Spade, or Lara translation. The Analyst Runtime Settings Safeguard API Key is the intentional exception: it is browser-memory-only and can be forwarded with Analyst Chat `/v1/intercept` requests for local LM Studio testing.
- Sam Spade sessions are owner-scoped by the authenticated caller id. Fetch/message/solve operations for another caller return not found or forbidden, and the frontend sends `x-counter-spy-user-id` through the shared backend API client.
- Firestore audit-log client creates now have a narrow rules allowlist and reject backend-owned security fields such as safeguard verdicts, gateway status, review state, and responder telemetry.
- Analyst Chat Last Execution Results now orders local verdict alert first, then backend safeguard/monitor and Similarity Monitor detail, then `Detections` badges. Shared help/info icons are hidden while modal overlays are active except inside the open dialog content.
- The Safeguard LLM may be disabled during feature testing. Feature-vector extraction must still run because it is calculated before any Safeguard LLM forwarding.
- Local review mode stores telemetry in memory. After a refresh, the Metrics card may show no feature-vector audit events until a new prompt is submitted.

## Feature Pressure Semantics

**Feature Pressure** is the operator-facing name for the analysis-only 0-100 score stored internally as `researchSignal` for backward compatibility.

- It is not an enforcement decision.
- It does not independently block, allow, or queue traffic.
- It is calculated from deterministic pre-inference evidence and persists on audit events when prompts are submitted.
- The Playground Feature Breakdown shows the current typed prompt live. If the editor is empty, it falls back to the latest submitted audit event with a feature vector.

The six normalized component pressures are:

| Component | Meaning |
| :--- | :--- |
| Instruction Pressure | Jailbreak-style control language such as ignore, override, system prompt, developer mode, or respond as. |
| Constraint Density | Concentration of control terms relative to prompt length. |
| Syntax / Wrapper Pressure | Unusual tags, brackets, wrappers, shell-like framing, special characters, and code-shaped prompt structure. |
| Obfuscation Pressure | Base64-like blobs, escape sequences, leetspeak, or other concealment bonuses. |
| Entropy Pressure | Max entropy window compared against the active entropy threshold. |
| N-Gram Signal | English trigram and Caesar-shift likelihood signal for alphabetic obfuscation. |

## Metrics Card Behavior

The Metrics view has a **Feature Pressure** card.

- `Avg Feature Pressure` is shown as `x / 100`.
- The six component rows are shown as average percentages across submitted prompts with feature vectors:
  - `Avg Instruction Pressure`
  - `Avg Constraint Density`
  - `Avg Syntax / Wrapper`
  - `Avg Obfuscation Pressure`
  - `Avg Entropy Pressure`
  - `Avg N-Gram Signal`
- `High Pressure Prompts` counts prompts with Feature Pressure >= 70.
- `Top Pressure Driver` is the most frequent top weighted driver across feature-vector audit events.
- The card no longer emphasizes Feature Sample count because every governed submission should now carry a feature vector.

## Important File Map

| Area | Files |
| :--- | :--- |
| Feature vector builder | `src/lib/promptFeatureVector.ts` |
| Feature vector types, snapshots, exports | `src/lib/playgroundMetrics.ts` |
| Playground Feature Breakdown | `src/components/SyntacticAnalyzer.tsx` |
| Metrics Feature Pressure card | `src/components/ThreatDashboard.tsx` |
| Audit-event feature vector attachment | `src/App.tsx` |
| English trigram / Caesar likelihood | `src/lib/languageLikelihood.ts` |
| Frontend deterministic sanitizer | `src/lib/sanitizer.ts` |
| Backend deterministic sanitizer | `backend/src/security/sanitizer.ts` |
| Safeguard orchestration and observability | `backend/src/server.ts` |
| Instruction similarity monitor | `backend/src/services/instruction-monitor/` |
| Protected backend API client | `src/lib/backendApi.ts` |
| Firestore audit-log create rules | `firestore.rules` |

## Safeguard Contract and Observability

The safeguard runtime contract is intentionally singular:

```json
{"verdict":"CLEAN|SUSPICIOUS|ADVERSARIAL","analystReasoning":"brief reason"}
```

Legacy decision-shaped responses such as `ALLOW_AND_FORWARD`, malformed JSON, or schema mismatches fail secure to `SUSPICIOUS` / `QUEUED`; they never default-allow.

Backend logs emit:

- `metric_increment` for `safeguard.schema` with shape `verdict`, `decision`, or `malformed`
- `metric_increment` for `safeguard.divergence` with `judgeVerdict`, `gatewayAction`, and `divergent`
- `safeguard_decision` with prompt hash, retry marker, response shape, judge verdict, gateway action, divergence boolean, optional raw reasoning trace, and latency
- `instruction_embedding_generated` with embedding model, runtime source, input count, dimensions, chunk count, and duration

## May 8 Security Remediation Validation

Focused validation added in `backend/test/securityRoutes.test.ts` covers:

- unauthenticated protected-route access fails for intercept, translate, and Sam Spade session creation
- client-supplied backend execution overrides are rejected by request schemas, except the allowlisted browser-memory Safeguard API Key for Analyst Chat local testing
- translation fails closed when backend Lara configuration is missing
- Sam Spade sessions are scoped to the authenticated caller and reject cross-user access

Latest local validation for this remediation:

- `npm run backend:test` passed: 128/128 tests
- `npm run lint` passed: frontend TypeScript plus backend typecheck

Firestore rules were tightened and statically reviewed in this session. A Firebase emulator rules test was not run in the local sandbox.

## Deterministic Detector Additions

The sanitizer now flags these structural jailbreak patterns:

| Flag | Behavior |
| :--- | :--- |
| `FORCED_PREFIX_INJECTION` | Opening instructions forcing the answer to start/begin/respond only with a required prefix. |
| `ANTI_SANITIZATION_CLAUSE` | Requests to avoid/disable sanitization, filters, moderation, warnings, disclaimers, or safety policies. |
| `PERSONA_INJECTION` | Persona assignment plus unrestricted-capability language. |
| `PAIRED_RESPONSE_INJECTION` | Dual approved/rejected, safe/unsafe, two-response, or opposite-response framing. Isolated hits are telemetry; paired with other jailbreak signals, route to review. |
| `ALLCAPS_PERSONA` | Signal-only telemetry for all-caps hyphenated persona handles. |
| `VERTICAL_TEXT` | Alphabetic vertical columns and `x - position N` rows are reflowed before detectors run; the signal itself routes to review/obfuscation handling. |
| `BINARY_ENCODING` | 8-bit binary payloads, including spaced bytes, continuous aligned blobs, and one-byte-per-line layouts. |
| `ASCII_DECIMAL` | Printable ASCII decimal byte lists, including recursive binary -> decimal wrapper payloads. |
| `A1Z26` | Alphabet-position encoding with optional `0` word-space markers and an English bigram plausibility gate. |
| `PIG_LATIN` | Signal-only detection by high non-common `ay`-suffix density; routes to review without attempting lossy decoding. |
| `SAFEGUARD_TIMEOUT` / `SAFEGUARD_ERROR` / `FAIL_SECURE` | Structured safeguard fail-secure states. Timeout/failure returns `SHIELD_ERROR`, marks records `PENDING_REVIEW`, and activates Global System Pause. |
| `instructionEmbeddingDurationMs` | Audit timing field for backend pgvector/Ollama embedding calls, surfaced in prompt details and Metrics embedding average/P95/sample count. |

Recognized decode/structural obfuscation remains strict: current policy treats known obfuscation signals as adversarial even before a concealed payload is proven to decode into a blocked phrase. Pig Latin is the current detect-and-review exception because decoding is ambiguous and lossy.

## Safeguard Timeout Boundary

- Backend safeguard calls use `SAFEGUARDS_TIMEOUT_MS`, default `30000`.
- The browser applies a 45s `/v1/intercept` abort as a second guard.
- Safeguard timeout/provider failure, including LM Studio API-token rejection, must not fall back to local inference.
- The fail-secure path emits `SHIELD_ERROR`, `SAFEGUARD_TIMEOUT` or `SAFEGUARD_ERROR`, and `FAIL_SECURE`, then queues the audit record and activates Global System Pause.

## Credit Card Redaction Boundary

- Generic 32-64 character hex strings are no longer treated as API keys.
- Credit-card redaction requires non-alphanumeric token boundaries, valid major-network lengths, issuer prefix checks, and Luhn validation.
- Long hashes, CIDs, transaction IDs, and hex payloads should remain intact for decoder inspection.

## Validation Snapshot

Last known checks for this work:

- `npm run test` passed with 112 tests after binary, ASCII decimal, A1Z26, Pig Latin, credit-card, and safeguard timeout/fail-secure changes.
- `npm run lint` passed.
- `git diff --check` passed.
- Docker demo stack includes backend, frontend, and pgvector Postgres. Recreate Postgres when a clean instruction database is needed.

## Docs Updated

The same behavior is also reflected in:

- `README.md`
- `Technical/SBOM.md`
- `Technical/ARCHITECTURE.md`
- `Technical/Technical_Specification.md`
- `Technical/LOCAL_DEVELOPMENT.md`
