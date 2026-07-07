## 🗂️ Repository Structure

```
safeguard-llm/
│
├── 📚 Technical/                         # Engineering & implementation documentation
│   ├── ADVERSARIAL_PROMPT_ANALYSIS.md    # Research and evaluation plan
│   ├── ARCHITECTURE.md                   # Technical specs (Shield-and-Sword pattern & heuristics)
│   ├── LOCAL_DEVELOPMENT.md              # Local dev and Docker workflow
│   ├── MITRE_ATLAS_MAPPING.md            # Threat taxonomy mapping
│   ├── SAM_SPADE_API_CONTRACT.md         # Sam Spade backend contract
│   ├── SAM_SPADE_CTF_INTEGRATION.md      # Sam Spade integration design
│   ├── SBOM.md                           # Technical software bill of materials
│   └── Technical_Specification.md        # Deep technical reference
│
├── 🏛️ Regulatory/                       # Compliance, assurance, and trust materials
│   ├── ANALYST_GUIDE.md                  # SOPs for SOC personnel (HITL/HOTL workflows)
│   ├── EU_AI_Act_Mapping.md              # EU AI Act compliance mapping
│   ├── Model_Card.md                     # Model reference and risk notes
│   └── Threat_Model.md                   # Threat model narrative
│
├── 💻 src/                               # Application Source Code
│   │
│   ├── components/                       # Reusable React Components
│   │   │
│   │   ├── ui/                           # Hardened Shadcn UI Primitives
│   │   │   ├── alert.tsx                 # Crimson alert banners (DEFCON 1 state)
│   │   │   ├── badge.tsx                 # Severity & FN (False Negative) indicators
│   │   │   ├── button.tsx                # Interactive controls
│   │   │   ├── card.tsx                  # Layout containers for metrics & logs
│   │   │   ├── dialog.tsx                # Full Prompt Inspection modals
│   │   │   ├── dropdown-menu.tsx         # Analyst reclassification controls
│   │   │   ├── input.tsx                 # Standard text inputs
│   │   │   ├── scroll-area.tsx           # Scroll containers for high-volume log views
│   │   │   ├── separator.tsx             # Visual layout dividers
│   │   │   ├── sonner.tsx                # Toast notifications for system events
│   │   │   ├── switch.tsx                # Guardrail & Kill Switch toggles
│   │   │   ├── tabs.tsx                  # Primary navigation (Chat · Logs · Metrics · KB)
│   │   │   └── textarea.tsx              # Auto-resizing chat input
│   │   │
│   │   ├── SyntacticAnalyzer.tsx         # Real-time complexity visualization
│   │   ├── ThemeProvider.tsx             # Dark mode & Geist typography context
│   │   ├── ThemeToggle.tsx               # UI theme switcher
│   │   └── ThreatDashboard.tsx           # Anomaly detection & Z-Score charting
│   │
│   ├── 🧠 lib/                           # Core Logic & Security Engines
│   │   ├── anomalyDetector.ts            # Statistical engine (Z-Score, rolling baselines)
│   │   ├── atlasTaxonomy.ts              # Active MITRE ATLAS organizer taxonomy
│   │   ├── backendApi.ts                 # Backend gateway client for intercept, responder, CTF, translation, and governed 403 result handling
│   │   ├── firebase.ts                   # Firestore & Auth initialization
│   │   ├── gemini.ts                     # Legacy deterministic fallback helpers retained for local/demo paths
│   │   ├── languageLikelihood.ts         # English-likeness and trigram scoring helpers
│   │   ├── metrics.ts                    # Telemetry aggregation & filtering logic
│   │   ├── obfuscation.ts                # Playground obfuscation generation utilities
│   │   ├── playgroundMetrics.ts          # Browser-local Playground/Bulk metric records, including backend safeguard attribution fields
│   │   ├── policies.ts                   # Knowledge Base (MITRE ATLAS, System Config)
│   │   ├── promptFeatureVector.ts        # Feature Pressure vector calculations
│   │   ├── sanitizer.ts                  # 🛡️  Shield — PII, entropy, regex, forbidden phrase & ReDoS engine
│   │   ├── sanitizerLanguage.ts          # Local language/translation policy helpers
│   │   ├── sanitizerNormalization.ts     # Shared normalization and canonicalization helpers
│   │   ├── sanitizerObfuscation.ts       # Obfuscation-family detection helpers
│   │   ├── spellNormalize.ts             # Browser-local spelling recovery helpers
│   │   ├── syntacticAnalyzer.ts          # Heuristic complexity scoring logic
│   │   ├── translate.ts                  # Translation-mode schemas and helpers
│   │   └── utils.ts                      # Tailwind merging & shared helpers
│   │
│   ├── App.tsx                           # Application shell & state orchestration
│   ├── index.css                         # Global styles & Tailwind CSS 4 configuration
│   └── main.tsx                          # React entry point
│
├── 🖥️ backend/                           # Authenticated backend gateway and local services
│   ├── Dockerfile                         # Backend container image
│   ├── docker-entrypoint.sh               # Container entrypoint and volume ownership repair
│   ├── src/
│   │   ├── server.ts                      # `/v1/intercept`, translation, instruction-monitor, and CTF routes
│   │   ├── security/sanitizer.ts          # Backend sanitizer re-export/boundary
│   │   └── services/
│   │       ├── instruction-monitor/       # pgvector instruction similarity monitor and seed tooling
│   │       └── sam-spade/                 # Sam Spade session, SQLite store, and gameplay service
│   └── test/                              # Backend route and service tests
│
├── 🧪 seeds/pgvector/                     # Instruction similarity seed corpus snapshots
│   ├── core.json                          # Current core seed snapshot
│   └── core-2026-05-10-latest.json        # Archived latest seed snapshot
│
├── ☁️ infra/cloudformation/               # AWS deployment templates and helper scripts
│   ├── dev/                               # Dev network, auth, frontend, backend, data, and security stacks
│   └── scripts/                           # Backend/frontend deployment helpers
│
├── docker-compose.demo.yml                # Full local demo stack: frontend, backend, pgvector
├── docker-compose.sam-spade.yml           # Future Sam Spade service-boundary compose stub
├── Dockerfile.frontend-demo               # Frontend demo container
├── .env.example                          # Template for required environment variables
├── .gitignore                            # Version control exclusion rules
├── components.json                       # Shadcn UI configuration
├── firebase-applet-config.json           # Firebase project credentials
├── firebase-blueprint.json               # Firestore IR (Intermediate Representation)
├── firestore.rules                       # 🔒 Hardened RBAC & data validation rules
├── index.html                            # HTML entry point
├── metadata.json                         # App metadata & frame permissions
├── package.json                          # Dependency manifest (pinned versions)
├── README.md                             # Project overview & documentation hub
├── tsconfig.json                         # TypeScript compiler configuration
└── vite.config.ts                        # Vite build & dev server configuration
```

---

## 🏛️ Key Architectural Components

| Nickname | File | Role |
| :--- | :--- | :--- |
| 🛡️ **The Shield** | `src/lib/sanitizer.ts` | Local sanitization engine — intercepts all adversarial payloads before any external API call is initiated. |
| ⚔️ **The Sword** | `backend/src/server.ts` + `src/lib/backendApi.ts` | Backend-mediated inference path — local sanitizer, OpenAI-compatible safeguard judge, downstream responder, Sam Spade CTF persona/scenario handoff, and governed intercept result handling. |
| 🕵️ **The Case File** | `backend/src/services/sam-spade/` | Sam Spade CTF session, review, and gameplay gatekeeping — clean turns reach the responder, while sensitive/adversarial turns are masked as `Bad content.` and routed to audit review. |
| 📡 **The Radar** | `src/lib/anomalyDetector.ts` | Statistical anomaly engine — calculates real-time Z-Scores to detect coordinated automated attacks. |
| 🔒 **The Vault** | `firestore.rules` | Database-layer enforcement — ensures data integrity and PII privacy even if the client layer is compromised. |
| 📚 **The Manual** | `Technical/` + `Regulatory/` | Operational and assurance documentation — provides context for implementers, analysts, and compliance review. |
