# AI Bill of Materials (AI-BOM) — Safeguard LLM v2.5

**Adversary-Aware Prompt Firewall & Forwarding Gateway** (internal/legacy name: `counter-spy`)

> Compliance-ready AI-BOM mapped to the **EU AI Act (Annex IV / Art. 53)**, **California AB 2013**, and **Colorado SB 24-205**. Prepared as an AI supply-chain transparency manifest under a zero-trust provenance standard.

---

## 0. Audit Metadata & Change History (Lifecycle Traceability)

| Field | Value |
|---|---|
| AI-BOM Document Version | 1.0.0 |
| AI-BOM Creation Date | 2026-07-08 |
| Target System | Safeguard LLM v2.5 (`counter-spy`) |
| System Status | Beta / "Promotion to Beta" |
| System Classification | Proprietary / AppSec Engineering |
| Author / Responsible Team | AppSec Engineering (repo owner: Nate-Carroll-Cyber) |
| Source of Record | `github.com/Nate-Carroll-Cyber/SafeguardLLM-docs` (branch `main`) |
| Documents Analyzed | README.md, Technical/ARCHITECTURE.md, Technical/Technical_Specification.md, Technical/SESSION_HANDOFF.md, OPERATIONS_GUIDE.MD, Technical/ADVERSARIAL_PROMPT_ANALYSIS.md, Technical/MITRE_ATLAS_MAPPING.md, Technical/SAM_SPADE_CTF_INTEGRATION.md, Technical/SAM_SPADE_API_CONTRACT.md, Technical/LOCAL_DEVELOPMENT.md, Technical/SBOM.md |
| EU AI Act Retention Obligation | 10-year technical documentation retention applies (Annex IV) |

### Change History

| Date | Version | Author | Delta |
|---|---|---|---|
| 2026-07-08 | 1.0.0 | AI-BOM Architect (Claude) | Initial AI-BOM generated from SafeguardLLM-docs `main`. Documented judge/responder/embedding models, pgvector seed corpus, Firestore data stores, npm supply chain, and regulatory mapping. |

> **Lifecycle note:** This AI-BOM must be re-versioned on any change to (a) the safeguard judge model, (b) the downstream responder provider/model, (c) the `core` pgvector seed snapshot hash, (d) the Safeguard Effective Prompt drift hash, or (e) any pinned dependency addressing a CVE.

---

## 1. Regulatory Classification (Legal Filter)

| Regulation | Applicability to Safeguard LLM | Rationale |
|---|---|---|
| **EU AI Act** | **Likely High-Risk / GPAI-adjacent** if placed on the EU market. It is a safety component governing access to a general-purpose model. Annex IV technical-documentation and Art. 53 transparency duties apply to the integrated GPAI (OpenAI/Gemini) and to this system as a downstream deployer/provider. | System mediates all LLM interactions and makes automated block/allow/queue decisions on user input. |
| **California AB 2013** (GenAI training-data transparency) | **Applies to the training-data summary of any GenAI made available to Californians.** For Safeguard LLM the *directly controlled* trainable artifact is the **Golden Set / DPO dataset** and the **`core` pgvector seed corpus**. The frontier responder models (OpenAI/Gemini) are third-party GenAI whose training data is **outside this system's control** and must be sourced from the provider. | AB 2013 requires a public "high-level summary" of datasets used to train/fine-tune. |
| **Colorado SB 24-205** (algorithmic discrimination / consequential decisions) | **Conditional.** Applies if Safeguard LLM's block/queue decisions become a "consequential decision" affecting a consumer's access to a service. As deployed (a security firewall for prompts), risk of *algorithmic discrimination* centers on false-positive blocking of non-English / dialectal / obfuscation-adjacent legitimate input. | Requires risk documentation of foreseeable algorithmic-discrimination risks and reasonable-care duty. |

> ⚠️ **Determination note:** Final risk classification is a legal determination. This AI-BOM flags obligations conservatively; it does not constitute legal advice.

---

## 2. Asset Provenance & Ownership — Models (EU AI Act Annex IV / SB 24-205)

### 2.1 Safeguard Judge (control-plane decision model)

| Attribute | Value |
|---|---|
| Role | Deterministic-adjacent "judge" returning strict JSON `{verdict: CLEAN\|SUSPICIOUS\|ADVERSARIAL, analystReasoning}` |
| Interface | OpenAI-compatible `/v1/chat/completions` |
| Preset A (`LM_STUDIO`) | Model `gpt-oss-safeguard-20b`, host `http://192.168.0.183:1234/v1/chat/completions` (local, demo) |
| Preset B (`OPENAI`) | Model `gpt-5.4-mini`, host `https://api.openai.com/v1` (no hardcoded key) |
| Config keys | `SAFEGUARDS_API_BASE_URL`, `SAFEGUARDS_API_KEY`, `SAFEGUARDS_MODEL_ID`, `SAFEGUARDS_TIMEOUT_MS` |
| Model Weights | **Third-party / not held by this system.** `gpt-oss-safeguard-20b` weights run in LM Studio (local); `gpt-5.4-mini` weights are OpenAI-hosted (opaque). |
| Inference config | Governed by hardcoded **Safeguard Effective Prompt**; temperature/top_p **NOT documented** → `UNVERIFIED` |
| Provenance | Provider-controlled; no model card included in repo → `UNVERIFIED` |

### 2.2 Downstream Responder (inference-plane, pluggable, vendor-neutral)

| Attribute | Value |
|---|---|
| Role | Generates the actual answer for `CLEAN` prompts ("the Sword") |
| Providers | OpenAI-compatible (`/v1/responses`) **or** Google **Gemini** (`RESPONDER_PROVIDER=gemini`) |
| Example model | `gemini-2.5-flash` (per Sam Spade API contract example) |
| Config keys | `RESPONDER_PROVIDER`, `RESPONDER_API_BASE_URL`, `RESPONDER_API_KEY`, `RESPONDER_MODEL_ID`, generic `LLM_*` |
| Passthrough mode | `local-responder-passthrough` / status `DISABLED_LOCAL_ONLY` |
| Model Weights | **Third-party / opaque** (OpenAI or Google Gemini hosted) |
| Inference config | **NOT documented** → `UNVERIFIED` |
| Production default | Vendor-neutral by design; concrete production provider/model **not fixed** → `UNVERIFIED` |

### 2.3 Embedding Model (instruction-similarity monitor)

| Attribute | Value |
|---|---|
| Model | `nomic-embed-text` |
| Host | Ollama sidecar `http://192.168.0.183:11434/v1` (OpenAI-compatible `/v1/embeddings`) |
| Ollama version | `0.23.2` |
| Vector dimension | **768** (`vector(768)`); `INSTRUCTION_MONITOR_EMBEDDINGS_MAX_CHUNKS=4` |
| Egress policy | **Local / private-network only.** Public hosted embedding endpoints (OpenAI/Google) are **blocked** for this path so adversarial prompt material is not sent to third-party embedding APIs. |
| Model Weights | Locally hosted (Ollama); provenance of `nomic-embed-text` weights = provider-controlled → `UNVERIFIED` (no checksum in repo) |
| Production host | **NOT specified** (must remain local/private per policy) → `UNVERIFIED` |

### 2.4 Deterministic Detectors (heuristic — NOT ML models)

These are rule-based components inventoried here for completeness and for the SB 24-205 guardrail record (see §6): Sliding-Window Shannon Entropy analyzer (35-char windows / 5-char steps), Syntactic Complexity scorer, English-Likeness trigram/Caesar heuristic, obfuscation-family decoders, structural-jailbreak detectors, Feature Pressure vector builder, ReDoS circuit breaker.

> **Transparency note (verbatim from docs):** "`Blocked Topics` metrics currently count normalized phrase-family hits, not a separate semantic topic classifier." There is **no standalone semantic topic classifier**; category steering is done via the Safeguard Effective Prompt.

---

## 3. Data Lineage & Transparency (CA AB 2013 / EU AI Act Art. 53)

### 3.1 Directly-controlled trainable / reference datasets

| Dataset | Purpose | Volume | Source / Owner | Copyright | Synthetic? | PII Status | Integrity Marker |
|---|---|---|---|---|---|---|---|
| **`core` pgvector seed corpus** (`seeds/pgvector/core.json`, archived `core-2026-05-10-latest.json`) | Instruction-similarity reference for reviewed-ADVERSARIAL prompts | **319 records / 611 chunks / 768-dim**; 312 whole-prompt embeddings, 7 chunk-only, 0 hash-only | `controlled-prompt-review` (internal, first-party) | Proprietary/internal | No (curated adversarial prompts) | **Adversarial prompt text**, redacted; SHA-256 hashes stored, not raw plaintext | ✅ Snapshot hash `2a98e221…95465b`; File SHA-256 `06cb8e18…97e5cd5` — **VERIFIED** |
| **MITRE ATLAS test corpus** | Labeling, heat maps, detection-effectiveness research | **569 prompts across 97 sections** (avg 5.9/section) | Internal, mapped to MITRE ATLAS taxonomy | Taxonomy © MITRE (ATLAS); prompts internal | Mixed | Adversarial samples | **NOT stated** → `UNVERIFIED` |
| **Golden Set / DPO dataset** | Direct Preference Optimization fine-tuning corpus, built via "Promote to KB" | Not stated (grows via analyst promotion) | Internal analyst curation | Proprietary | No | Captures prompt + AI response + "Rejected Reason"; only sanitized/redacted prompts persisted | One-click JSON export; no checksum documented → `UNVERIFIED` |
| **Audit trail / prompt logs** | Forensic auditability | Continuous | First-party (Firestore) | Proprietary | No | **SHA-256 prompt hashes only**; raw un-redacted prompt storage NOT enabled | Prompt hash = SHA-256 per entry — **VERIFIED (by design)** |

### 3.2 Third-party GenAI training data (NOT controlled by this system)

| Model | Training-data disclosure | AB 2013 responsibility |
|---|---|---|
| OpenAI `gpt-5.4-mini` / `gpt-oss-safeguard-20b` | **Opaque / provider-controlled** | Must be obtained from OpenAI's AB 2013 disclosure; **not available in repo** → `UNVERIFIED` |
| Google `gemini-2.5-flash` | **Opaque / provider-controlled** | Must be obtained from Google's AB 2013 disclosure; **not available in repo** → `UNVERIFIED` |
| `nomic-embed-text` | Open-weight model; training-data summary per Nomic | Provider-controlled; **not documented in repo** → `UNVERIFIED` |

### 3.3 Processing history (cleaning / augmentation)

The `core` seed pipeline records `seed_pack`, `seed_version`, `seed_record_hash`, `seed_snapshot_hash`, `seed_immutable`, `seed_imported_at`, `seed_source`. Only **reviewed-`ADVERSARIAL`** entries are persisted; `observe()` refuses to persist clean/suspicious/unreviewed entries. Records include strict SHA-256, loose stopword-stripped SHA-256, 2/3/4-gram SimHash, optional whole-prompt embedding, and overlapping-chunk embeddings with heuristic instruction-intent scores. Seed auto-import is idempotent; changed immutable rows **fail closed** unless `--allow-seed-update`.

---

## 4. Technical Dependencies & Integrity (CRA / OWASP / EU AI Act Annex IV)

### 4.1 Runtime environment

| Item | Value |
|---|---|
| Container base | `pgvector/pgvector:pg16`; multi-stage Docker builds; non-root `node` user via `su-exec` (Alpine `0.2-r3`) |
| Backend runtime | Node.js `22.5.0+`, Express `^5.2.1`, TypeScript `~5.8.2` |
| Frontend runtime | React `~19.0.4`, Vite `^8.0.5`, Tailwind CSS `4`, Shadcn UI |
| DB extension | PostgreSQL `vector` extension `0.8.2` |
| IaC / compose | `docker-compose.demo.yml`, `docker-compose.sam-spade.yml`, `backend/Dockerfile`, `Dockerfile.frontend-demo` |
| Target infra | AWS ECS Fargate + API Gateway + Bedrock (**target-state, not implemented** → `UNVERIFIED`) |

### 4.2 Key npm dependencies (versions verbatim from SBOM) + integrity/CVE posture

| Package | Version | Security note |
|---|---|---|
| `react` / `react-dom` | `~19.0.4` | Pinned for CVE-2025-55182 & CVE-2026-23864 |
| `firebase` | `^12.12.0` (`@firebase/auth` → `1.13.0`) | Mitigates CVE-2024-11023 |
| `vite` | `^8.0.5` | Mitigates CVE-2026-39363, GHSA-v2wj-q39q-566r, GHSA-4w7w-66w2-5vf9; cites CVE-2025-31125, CVE-2025-32395 |
| `express` | `^5.2.1` | Backend gateway |
| `zod` | `^4.3.6` | Runtime config validation |
| `pg` | `^8.20.0` / `pgvector` | `^0.2.1` | pgvector client |
| `@translated/lara` | `^1.9.0` | Lara Translate SDK (backend-only egress) |
| `dotenv` | `^17.2.3` | **Known risk:** planned migration to AWS Secrets Manager |
| `react-markdown` | `^10.1.0` | **No `rehype-raw`** (residual XSS consideration — relies on library default) |
| `fast-uri` | `3.1.2` (transitive) | Patched for GHSA-q3j6-qgpj-74h6, GHSA-v39h-62p7-jpjc |
| `motion` | `^12.23.24` | Animation |
| `recharts` | `^3.8.1` | Metrics viz |
| `@modelcontextprotocol/sdk` | transitive (dev, via `shadcn`) | **Dev-only**; not a runtime MCP client |

**Forced transitive resolutions (security overrides):** `hono ^4.12.14`, `protobufjs ^7.5.5`, `esbuild ^0.28.1`.

**Deploy-only tooling (NOT in runtime bundle):** `firebase-tools 15.15.0` (via `npx`) with deprecated transitives `node-domexception 1.0.0`, `json-ptr 3.1.1`, `glob 10.5.0` → **EOL/deprecation watch**.

### 4.3 Third-party services / external egress

OpenAI API (`api.openai.com/v1`), Google Gemini API, Lara Translate (`api.laratranslate.com`), Firebase/Firestore (Google Cloud, **US-West2**), Ollama sidecar, LM Studio.

### 4.4 Third-party attribution (license compliance)

| Asset | Origin | License |
|---|---|---|
| Arcanum Prompt Obfuscator / Arcanum PI Taxonomy | Jason Haddix / Arcanum Information Security | **CC BY 4.0 — attribution required** |
| Regex prompt-injection patterns | Originally `dimitritholen` | Internalized to mitigate supply-chain risk |

### 4.5 Verified static assets

| Asset | SHA-256 |
|---|---|
| `public/brand/counter-spy-shield.png` | `7abebd60…fc4f9` — **VERIFIED** |
| `public/brand/counter-spy-shield-original.png` | `daf2935c…d5b9b` — **VERIFIED** |
| `core` pgvector seed file | `06cb8e18fcebd73ea2933d7a1c3e71979ff8a396fd8531617a2a1509297e5cd5` — **VERIFIED** |
| `core` seed snapshot | `2a98e22110240fe87582865bf5ebace17d97074414c06ef495c53239e295465b` — **VERIFIED** |
| Safeguard Effective Prompt (drift hash) | `590a286e60b99b0b353222b3ddaaa131db925a1f4d6222a0c3b1b3e49d203ad0` — **VERIFIED** |
| Canary token | `COUNTERSPY_CANARY_TOKEN_9d17d3b2-5d66-4a51-9adf-5d5bb0c4b799` |

---

## 5. Integrity Verification Summary

| Asset class | Status |
|---|---|
| `core` pgvector seed corpus | ✅ VERIFIED (file + snapshot SHA-256 present) |
| Safeguard Effective Prompt | ✅ VERIFIED (drift SHA-256 present) |
| Brand static assets | ✅ VERIFIED (SHA-256 present) |
| Safeguard judge model weights | ⚠️ UNVERIFIED (third-party/opaque; no checksum) |
| Downstream responder model weights | ⚠️ UNVERIFIED (third-party/opaque) |
| `nomic-embed-text` weights | ⚠️ UNVERIFIED (no checksum in repo) |
| MITRE ATLAS corpus | ⚠️ UNVERIFIED (no integrity marker documented) |
| Golden Set / DPO dataset | ⚠️ UNVERIFIED (export exists; no checksum documented) |
| npm dependency tree | ⚠️ PARTIAL (versions pinned; no lockfile hash / SLSA attestation in docs) |

> **Verification Failures are flagged, not silently omitted**, per AI-BOM integrity policy. Each `UNVERIFIED` item is a remediation target before production sign-off.

---

## 6. Governance, Safety & Risk Disclosures (Colorado SB 24-205)

### 6.1 Deterministic guardrails inventory

Shannon-entropy sliding-window analysis (adversarial cutoff `4.0`, suspicious floor `3.8`); syntactic-complexity scoring (suspicious `≥65`, adversarial `≥90`); English-likeness / obfuscation-family decoding (strict — any recognized obfuscation = Adversarial, Pig Latin excepted → Suspicious); structural-jailbreak detectors; instruction-similarity monitor (SimHash Hamming `≤12`; cosine `≥0.78`; chunk `>0.72`; attention pool `>0.70`; sandwich delta `>0.20`); ReDoS circuit breaker (>1000ms → block + Global Pause); canary-token exfiltration detection; output sanitization (keyword/PII re-redaction before display).

### 6.2 Foreseeable risks (incl. algorithmic discrimination)

| Risk | Description | Disclosure |
|---|---|---|
| False-positive blocking of legitimate non-English / dialectal input | `FOREIGN_LANGUAGE`, `MIXED_LANGUAGE`, low-English-likeness heuristics may over-block legitimate multilingual users → potential disparate impact | **Algorithmic-discrimination candidate** under SB 24-205; requires bias/impact testing (not documented → gap) |
| Obfuscation strict-mode over-block | Any recognized encoding flagged Adversarial even if benign | Documented design tradeoff; may block legitimate technical content |
| Over-reliance on third-party judge/responder | Judge/responder behavior opaque; provider drift not controlled | Documented; fail-secure mitigations exist |
| PII handling | Only redacted prompt sent to inference; SHA-256 hashes stored | Documented PII-minimization guarantee (backend routes own redaction) |
| Prompt-log forensic gap | Firestore logs independent of downstream-provider abuse-monitoring windows | Documented |

### 6.3 Fail-secure posture

Shield timeout → 503 block; safeguard judge failure → 202 `SHIELD_ERROR` + `FAIL_SECURE` + Global System Pause; sanitization ReDoS >1000ms → block + `GLOBAL_PAUSE`; frontend 45s intercept hang → abort + pause (no local fallback inference). Governance-sync loss is the single **Best-Effort** exception (keeps in-memory state; does not force pause).

---

## 7. Compliance Gap Register (Remediation Targets)

| # | Gap | Regulation touched | Severity |
|---|---|---|---|
| G1 | Inference parameters (temperature/top_p) for judge & responder undocumented | EU AI Act Annex IV | Medium |
| G2 | Third-party model training-data summaries (OpenAI/Gemini/Nomic) not captured | CA AB 2013 | High |
| G3 | No documented bias / disparate-impact testing for language-based over-blocking | CO SB 24-205 | High |
| G4 | Production auth (JWT/OIDC, IAM SigV4) planned but **not implemented**; shared static bearer token in Beta | EU AI Act (robustness) / OWASP | High |
| G5 | No integrity markers for MITRE ATLAS corpus & Golden Set export | CRA / integrity | Medium |
| G6 | Strict CSP is a "Known Gap"; `react-markdown` raw-HTML relies on library default | OWASP | Medium |
| G7 | No documented backend rate limiting beyond ReDoS breaker | OWASP / DoS | Medium |
| G8 | `dotenv` secret handling pending migration to AWS Secrets Manager | CRA / secrets | Medium |
| G9 | `Technical/File_Structure.md` served empty — full file tree not captured for this AI-BOM | Documentation completeness | Low |
| G10 | Data residency / DPA / subprocessor list beyond "Firestore US-West2" undocumented | EU AI Act / GDPR-adjacent | Medium |

---

## 8. Machine-Readable Manifest

A companion **CycloneDX 1.5 JSON** manifest is provided at `SafeguardLLM_AI-BOM.cyclonedx.json` (same folder), enumerating models, datasets, and key software components with the integrity markers recorded above.

---

*Prepared by the AI-BOM Architect skill. `UNVERIFIED` denotes a missing integrity marker or undocumented provenance — a remediation target, not an assertion of non-compliance. This document is a technical transparency artifact and does not constitute legal advice.*
